//! Records light-client data from the Beacon API.
//!
//! ```text
//! fetch_chain <network> <out-dir> [--beacon URL] [--check-beacon URL] [--rpc URL] [--period P] [--count N] [--no-finality-update]
//!     <network>: mainnet or sepolia. Bootstrap at the finalized header of
//!     the period-P update, N period updates from P, the latest finality
//!     update, and the RLP execution header of every finalized header
//!     (`execution/`, from `--rpc`), as a chain-dir. `--check-beacon`
//!     confirms the trusted root is canonical and finalized.
//!     `--no-finality-update` leaves out the latest finality update.
//!     Default P: current period minus N.
//! fetch_chain verify-checkpoint [--network N] [--root 0x..] [--endpoint URL]... [--rpc URL]... [--min M]
//!     Runs `verify_new_checkpoint` (with `verify_instance_config`) for
//!     network N (default mainnet) against the endpoints (default: the
//!     network's default endpoints) for `root` (default: the first
//!     endpoint's finalized root) and prints the verified root. `--min`
//!     sets the number of endpoints that must answer (default 3).
//! ```

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use eth_lc_core::{initialize_store, ChainConfig, ForkName};
use eth_lc_host::chain_dir::{execution_block_hash, network_config, parse_root, Entry, Manifest};
use eth_lc_host::checkpoint::{
    verify_instance_config, verify_new_checkpoint, CheckpointPolicy, DEFAULT_ENDPOINTS, DEFAULT_RPC,
};
use eth_lc_host::execution::fetch_header_rlp;
use eth_lc_host::forks::{self, fork_str, json_to_ssz, Kind, Preset, Wire};
use eth_lc_host::http::get_json;
use eth_lc_host::ChainDir;
use serde_json::Value;

/// Default (beacon, check beacon, execution RPC) endpoints of a network.
fn defaults(network: &str) -> Result<[&'static str; 3]> {
    Ok(match network {
        "mainnet" => [
            "https://lodestar-mainnet.chainsafe.io",
            "https://ethereum-beacon-api.publicnode.com",
            "https://ethereum-rpc.publicnode.com",
        ],
        "sepolia" => [
            "https://lodestar-sepolia.chainsafe.io",
            "https://ethereum-sepolia-beacon-api.publicnode.com",
            "https://ethereum-sepolia-rpc.publicnode.com",
        ],
        other => bail!("no default endpoints for network {other}"),
    })
}

fn flag(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == name)
        .map(|w| w[1].clone())
        .collect()
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("verify-checkpoint") => verify(&args[1..]),
        Some(network @ ("mainnet" | "sepolia")) => record(network, &args[1..]),
        _ => bail!("usage: fetch_chain <mainnet|sepolia> <out-dir> [--beacon URL] [--check-beacon URL] [--rpc URL] [--period P] [--count N] [--no-finality-update] | verify-checkpoint [--network N] [--root R] [--endpoint URL]... [--rpc URL]... [--min M]"),
    }
}

fn versioned(v: &Value) -> Result<(ForkName, &Value)> {
    let version = v["version"].as_str().context("missing version")?;
    Ok((forks::parse_fork(version)?, &v["data"]))
}

fn record(network: &str, args: &[String]) -> Result<()> {
    let out = PathBuf::from(args.first().context("missing <out-dir>")?);
    let [beacon, check, rpc_url] = defaults(network)?;
    let pick = |name: &str, default: &str| flag(args, name).pop().unwrap_or(default.to_string());
    let (beacon, check, rpc_url) = (
        pick("--beacon", beacon),
        pick("--check-beacon", check),
        pick("--rpc", rpc_url),
    );
    let count: u64 = flag(args, "--count").pop().map_or(Ok(4), |s| s.parse())?;
    let cfg = network_config(network)?;
    let preset = Preset::Mainnet;
    let current_period =
        cfg.period_at_slot((now_ms()? / 1000 - cfg.genesis_time) / cfg.seconds_per_slot);
    let period: u64 = flag(args, "--period")
        .pop()
        .map_or(Ok(current_period - count), |s| s.parse())?;
    std::fs::create_dir_all(&out)?;

    let updates = get_json(
        &beacon,
        &format!("/eth/v1/beacon/light_client/updates?start_period={period}&count={count}"),
    )?;
    let updates = updates.as_array().context("updates is not an array")?;
    ensure!(
        updates.len() as u64 == count,
        "asked for {count} updates, got {}",
        updates.len()
    );
    let mut entries = Vec::new();
    for (i, u) in updates.iter().enumerate() {
        let (fork, data) = versioned(u)?;
        let file = format!("update-{}.ssz", period + i as u64);
        std::fs::write(
            out.join(&file),
            json_to_ssz(Kind::Update, fork, preset, data)?,
        )?;
        entries.push(Entry {
            fork: fork_str(fork).into(),
            file,
        });
    }

    // The trusted root: the finalized header of the first update.
    let (fork, data) = versioned(&updates[0])?;
    let first = forks::decode_update(fork, preset, Wire::Json(data))?;
    let finalized = forks::to_core_header(&cfg, &first.finalized_header)?;
    let root = finalized.beacon().hash_tree_root();
    let root_hex = format!("0x{}", hex::encode(root));
    let header = get_json(&check, &format!("/eth/v1/beacon/headers/{root_hex}"))?;
    ensure!(
        header["finalized"] == Value::Bool(true),
        "trusted root is not finalized at {check}"
    );
    ensure!(
        header["data"]["canonical"] == Value::Bool(true),
        "trusted root is not canonical at {check}"
    );

    let boot = get_json(
        &beacon,
        &format!("/eth/v1/beacon/light_client/bootstrap/{root_hex}"),
    )?;
    let (bfork, bdata) = versioned(&boot)?;
    std::fs::write(
        out.join("bootstrap.ssz"),
        json_to_ssz(Kind::Bootstrap, bfork, preset, bdata)?,
    )?;

    // The latest finality update, unless `--no-finality-update` (a past
    // range: the latest update is periods ahead of the last recorded one).
    let fin = if args.iter().any(|a| a == "--no-finality-update") {
        None
    } else {
        let fin = get_json(&beacon, "/eth/v1/beacon/light_client/finality_update")?;
        let (ffork, fdata) = versioned(&fin)?;
        std::fs::write(
            out.join("finality-update.ssz"),
            json_to_ssz(Kind::FinalityUpdate, ffork, preset, fdata)?,
        )?;
        Some((fin.clone(), ffork))
    };

    // RLP execution headers of the bootstrap and every finalized header.
    let mut headers = vec![bootstrap_header(&cfg, preset, bfork, bdata)?];
    for u in updates {
        let (fork, data) = versioned(u)?;
        let raw = forks::decode_update(fork, preset, Wire::Json(data))?;
        headers.push(forks::to_core_header(&cfg, &raw.finalized_header)?);
    }
    if let Some((f, _)) = &fin {
        let (fork, data) = versioned(f)?;
        let raw = forks::decode_finality_update(fork, preset, Wire::Json(data))?;
        headers.push(forks::to_core_header(&cfg, &raw.finalized_header)?);
    }
    std::fs::create_dir_all(out.join("execution"))?;
    for h in &headers {
        let hash = execution_block_hash(h);
        let rlp = fetch_header_rlp(&rpc_url, hash)?;
        std::fs::write(
            out.join("execution")
                .join(format!("0x{}.rlp", hex::encode(hash))),
            rlp,
        )?;
    }

    let manifest = Manifest {
        network: network.into(),
        trusted_block_root: root_hex.clone(),
        bootstrap: Entry {
            fork: fork_str(bfork).into(),
            file: "bootstrap.ssz".into(),
        },
        updates: entries,
        finality_update: fin.map(|(_, ffork)| Entry {
            fork: fork_str(ffork).into(),
            file: "finality-update.ssz".into(),
        }),
    };
    std::fs::write(
        out.join("chain.json"),
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;

    // Check: the recorded directory loads and anchors a store at the trusted root.
    let dir = ChainDir::load(&out)?;
    ensure!(dir.bootstrap.trusted_block_root == parse_root(&root_hex)?);
    let store = initialize_store(&dir.cfg, &dir.bootstrap)
        .map_err(|e| anyhow::anyhow!("initialize_store: {e}"))?;
    println!(
        "trusted_block_root={root_hex} slot={} period={} updates={count} execution_block={} execution_headers={}",
        store.finalized.slot,
        dir.cfg.period_at_slot(store.finalized.slot),
        store.execution.number,
        dir.execution_headers.len()
    );
    Ok(())
}

fn bootstrap_header(
    cfg: &ChainConfig,
    preset: Preset,
    fork: ForkName,
    data: &Value,
) -> Result<eth_lc_core::LightClientHeader> {
    let raw = forks::decode_bootstrap(fork, preset, Wire::Json(data))?;
    Ok(forks::to_core_bootstrap(cfg, &raw)?.header)
}

fn verify(args: &[String]) -> Result<()> {
    let network = flag(args, "--network").pop().unwrap_or("mainnet".into());
    let cfg = network_config(&network)?;
    let [beacon, _, default_rpc] = defaults(&network)?;
    let mut endpoints = flag(args, "--endpoint");
    if endpoints.is_empty() {
        endpoints = match network.as_str() {
            "mainnet" => DEFAULT_ENDPOINTS.iter().map(|s| s.to_string()).collect(),
            // Two operators and two clients that serve Gloas bootstraps.
            _ => vec![
                beacon.to_string(),
                "http://unstable.sepolia.beacon-api.nimbus.team".to_string(),
            ],
        };
    }
    let mut rpc_urls = flag(args, "--rpc");
    if rpc_urls.is_empty() {
        rpc_urls.push(if network == "mainnet" {
            DEFAULT_RPC.to_string()
        } else {
            default_rpc.to_string()
        });
    }
    let mut policy = CheckpointPolicy::default();
    if let Some(n) = flag(args, "--min").pop() {
        policy.min_endpoints = n.parse()?;
    }
    let root = match flag(args, "--root").pop() {
        Some(r) => parse_root(&r)?,
        None => parse_root(
            get_json(&endpoints[0], "/eth/v1/beacon/headers/finalized")?["data"]["root"]
                .as_str()
                .context("finalized root")?,
        )?,
    };
    verify_instance_config(&cfg, &endpoints, &rpc_urls, &policy)?;
    let input = verify_new_checkpoint(&cfg, &endpoints, &rpc_urls, root, now_ms()?, &policy)?;
    let slot = input.bootstrap.header.beacon().slot;
    println!(
        "network={network} verified_root=0x{} slot={slot} fork={:?} execution_header_rlp_bytes={} endpoints={}",
        hex::encode(root),
        cfg.fork_at_slot(slot),
        input.execution_header_rlp.as_ref().map_or(0, Vec::len),
        endpoints.len()
    );
    Ok(())
}
