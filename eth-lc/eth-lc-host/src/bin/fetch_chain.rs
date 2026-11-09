//! Records light-client data from the Beacon API.
//!
//! ```text
//! fetch_chain mainnet <out-dir> [--beacon URL] [--check-beacon URL] [--period P] [--count N]
//!     Bootstrap at the finalized header of the period-P update, N period
//!     updates from P, and the latest finality update, as a chain-dir.
//!     `--check-beacon` confirms the trusted root is canonical and finalized.
//!     Default P: current period minus N.
//! fetch_chain verify-checkpoint [--root 0x..] [--endpoint URL]...
//!     Runs `verify_new_checkpoint` against the endpoints (default: the
//!     three default endpoints) for `root` (default: the first endpoint's
//!     finalized root) and prints the verified root.
//! ```

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use eth_lc_core::{initialize_store, profile, ForkName};
use eth_lc_host::chain_dir::{parse_root, Entry, Manifest};
use eth_lc_host::checkpoint::{verify_new_checkpoint, CheckpointPolicy, DEFAULT_ENDPOINTS};
use eth_lc_host::forks::{self, fork_str, json_to_ssz, Kind, Preset, Wire};
use eth_lc_host::http::get_json;
use eth_lc_host::ChainDir;
use serde_json::Value;

const DEFAULT_BEACON: &str = "https://lodestar-mainnet.chainsafe.io";
const DEFAULT_CHECK_BEACON: &str = "https://ethereum-beacon-api.publicnode.com";

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
        Some("mainnet") => mainnet(&args[1..]),
        Some("verify-checkpoint") => verify(&args[1..]),
        _ => bail!("usage: fetch_chain mainnet <out-dir> [--beacon URL] [--check-beacon URL] [--period P] [--count N] | verify-checkpoint [--root R] [--endpoint URL]..."),
    }
}

fn versioned(v: &Value) -> Result<(ForkName, &Value)> {
    let version = v["version"].as_str().context("missing version")?;
    Ok((forks::parse_fork(version)?, &v["data"]))
}

fn mainnet(args: &[String]) -> Result<()> {
    let out = PathBuf::from(args.first().context("missing <out-dir>")?);
    let beacon = flag(args, "--beacon")
        .pop()
        .unwrap_or_else(|| DEFAULT_BEACON.to_string());
    let check = flag(args, "--check-beacon")
        .pop()
        .unwrap_or_else(|| DEFAULT_CHECK_BEACON.to_string());
    let count: u64 = flag(args, "--count").pop().map_or(Ok(4), |s| s.parse())?;
    let cfg = profile::mainnet();
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

    let fin = get_json(&beacon, "/eth/v1/beacon/light_client/finality_update")?;
    let (ffork, fdata) = versioned(&fin)?;
    std::fs::write(
        out.join("finality-update.ssz"),
        json_to_ssz(Kind::FinalityUpdate, ffork, preset, fdata)?,
    )?;

    let manifest = Manifest {
        network: "mainnet".into(),
        trusted_block_root: root_hex.clone(),
        bootstrap: Entry {
            fork: fork_str(bfork).into(),
            file: "bootstrap.ssz".into(),
        },
        updates: entries,
        finality_update: Some(Entry {
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
        "trusted_block_root={root_hex} slot={} period={} updates={count} execution_block={}",
        store.finalized.slot,
        dir.cfg.period_at_slot(store.finalized.slot),
        store.execution.number
    );
    Ok(())
}

fn verify(args: &[String]) -> Result<()> {
    let cfg = profile::mainnet();
    let mut endpoints = flag(args, "--endpoint");
    if endpoints.is_empty() {
        endpoints = DEFAULT_ENDPOINTS.iter().map(|s| s.to_string()).collect();
    }
    let root = match flag(args, "--root").pop() {
        Some(r) => parse_root(&r)?,
        None => parse_root(
            get_json(&endpoints[0], "/eth/v1/beacon/headers/finalized")?["data"]["root"]
                .as_str()
                .context("finalized root")?,
        )?,
    };
    let input = verify_new_checkpoint(
        &cfg,
        &endpoints,
        root,
        now_ms()?,
        &CheckpointPolicy::default(),
    )?;
    let slot = input.bootstrap.header.beacon().slot;
    println!(
        "verified_root=0x{} slot={slot} endpoints={}",
        hex::encode(root),
        endpoints.len()
    );
    Ok(())
}
