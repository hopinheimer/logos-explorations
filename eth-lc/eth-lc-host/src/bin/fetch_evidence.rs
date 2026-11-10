//! Records execution evidence for claims against a light-client record.
//!
//! ```text
//! fetch_evidence <out-dir> [--beacon URL] [--rpc URL] [--scan N]
//! ```
//!
//! Writes: the latest finality update (its finalized execution block is the
//! anchored block), that block's header JSON, `eth_getProof` results at that
//! block (WETH name slot and an absent slot; an absent account), the receipt
//! at index 0, one receipt per type (legacy, 0x02, 0x03, 0x04) from the
//! anchored block or up to `N` blocks before it, and a pre-Prague block.

use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use eth_lc_core::crypto::keccak256;
use eth_lc_core::ChainConfig;
use eth_lc_host::evidence::{quantity, receipt_proof};
use eth_lc_host::forks::{self, fork_str, json_to_ssz, Kind, Preset, Wire};
use eth_lc_host::http::{get_json, rpc};
use serde_json::{json, Value};

const DEFAULT_BEACON: &str = "https://lodestar-mainnet.chainsafe.io";
const DEFAULT_RPC: &str = "https://ethereum-rpc.publicnode.com";
/// WETH9 on mainnet.
pub const WETH: &str = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
/// A block before Prague (activated at block 22,431,084).
const PRE_PRAGUE_BLOCK: u64 = 22_000_000;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn write(dir: &Path, name: &str, v: &Value) -> Result<()> {
    std::fs::write(dir.join(name), serde_json::to_string_pretty(v)? + "\n")?;
    Ok(())
}

fn hex_u64(n: u64) -> String {
    format!("0x{n:x}")
}

/// Absent-key derivations: hashes of fixed labels.
fn absent_slot() -> String {
    format!("0x{}", hex::encode(keccak256(b"eth-lc absent slot")))
}

fn absent_account() -> String {
    format!(
        "0x{}",
        hex::encode(&keccak256(b"eth-lc absent account")[12..])
    )
}

fn receipt_record(
    rpc_url: &str,
    block: &Value,
    receipts: &[Value],
    tx_index: u64,
) -> Result<Value> {
    let (root, proof) = receipt_proof(receipts, tx_index)?;
    ensure!(
        format!("{root}") == block["receiptsRoot"].as_str().unwrap_or_default(),
        "receipts root mismatch"
    );
    let r = &receipts[tx_index as usize];
    let tx_hash = r["transactionHash"].as_str().context("transactionHash")?;
    let single = rpc(rpc_url, "eth_getTransactionReceipt", json!([tx_hash]))?;
    let log_index = single["logs"]
        .as_array()
        .map_or(0, |l| l.len().saturating_sub(1));
    Ok(json!({
        "block": block,
        "tx_index": tx_index,
        "log_index": log_index,
        "receipt_proof": proof.iter().map(|n| format!("0x{}", hex::encode(n))).collect::<Vec<_>>(),
        "receipt": single,
    }))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = PathBuf::from(
        args.first()
            .context("usage: fetch_evidence <out-dir> [--beacon URL] [--rpc URL] [--scan N]")?,
    );
    let beacon = flag(&args, "--beacon").unwrap_or_else(|| DEFAULT_BEACON.into());
    let rpc_url = flag(&args, "--rpc").unwrap_or_else(|| DEFAULT_RPC.into());
    let scan: u64 = flag(&args, "--scan").map_or(Ok(64), |s| s.parse())?;
    std::fs::create_dir_all(&out)?;
    let cfg = ChainConfig::mainnet();

    // The anchored block: the finalized execution block of the latest finality update.
    let fin = get_json(&beacon, "/eth/v1/beacon/light_client/finality_update")?;
    let fork = forks::parse_fork(fin["version"].as_str().context("version")?)?;
    let raw = forks::decode_finality_update(fork, Preset::Mainnet, Wire::Json(&fin["data"]))?;
    let update = forks::to_core_update(&cfg, &raw)?;
    let (finalized, _) = update
        .finality
        .as_ref()
        .context("finality update without finality")?;
    let anchor = eth_lc_core::execution::execution_anchor(finalized, None)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let n = anchor.number;
    std::fs::write(
        out.join("finality-update.ssz"),
        json_to_ssz(Kind::FinalityUpdate, fork, Preset::Mainnet, &fin["data"])?,
    )?;
    write(
        &out,
        "finality-update.json",
        &json!({"fork": fork_str(fork), "file": "finality-update.ssz"}),
    )?;

    // State proofs first: pruned nodes keep recent state only.
    let weth = rpc(
        &rpc_url,
        "eth_getProof",
        json!([
            WETH,
            [format!("0x{}", "00".repeat(32)), absent_slot()],
            hex_u64(n)
        ]),
    )?;
    write(&out, "weth-proof.json", &weth)?;
    let absent = rpc(
        &rpc_url,
        "eth_getProof",
        json!([absent_account(), [], hex_u64(n)]),
    )?;
    write(&out, "absent-account-proof.json", &absent)?;

    let block = rpc(&rpc_url, "eth_getBlockByNumber", json!([hex_u64(n), false]))?;
    ensure!(
        block["hash"].as_str() == Some(format!("0x{}", hex::encode(anchor.block_hash)).as_str()),
        "anchored block hash mismatch"
    );
    write(&out, "block.json", &block)?;
    let receipts = rpc(&rpc_url, "eth_getBlockReceipts", json!([hex_u64(n)]))?;
    let receipts = receipts.as_array().context("receipts")?.clone();
    write(
        &out,
        "receipt-index0.json",
        &receipt_record(&rpc_url, &block, &receipts, 0)?,
    )?;

    // One receipt per type, preferring receipts with logs.
    let mut missing: Vec<u64> = vec![0, 2, 3, 4];
    for b in (n.saturating_sub(scan)..=n).rev() {
        if missing.is_empty() {
            break;
        }
        let (blk, rs) = if b == n {
            (block.clone(), receipts.clone())
        } else {
            let blk = rpc(&rpc_url, "eth_getBlockByNumber", json!([hex_u64(b), false]))?;
            let rs = rpc(&rpc_url, "eth_getBlockReceipts", json!([hex_u64(b)]))?;
            (blk, rs.as_array().context("receipts")?.clone())
        };
        let mut found = Vec::new();
        for &t in &missing {
            let pick = rs.iter().position(|r| {
                quantity(&r["type"]).ok() == Some(t)
                    && r["logs"].as_array().is_some_and(|l| {
                        l.iter()
                            .any(|x| x["data"].as_str().is_some_and(|d| d.len() >= 66))
                    })
            });
            if let Some(i) = pick {
                write(
                    &out,
                    &format!("receipt-type-{t}.json"),
                    &receipt_record(&rpc_url, &blk, &rs, i as u64)?,
                )?;
                found.push(t);
            }
        }
        missing.retain(|t| !found.contains(t));
    }
    if !missing.is_empty() {
        bail!("no receipt with logs found for types {missing:?} in {scan} blocks");
    }

    let pre = rpc(
        &rpc_url,
        "eth_getBlockByNumber",
        json!([hex_u64(PRE_PRAGUE_BLOCK), false]),
    )?;
    write(&out, "block-pre-prague.json", &pre)?;
    println!(
        "anchored_block={n} slot={} fork={}",
        finalized.beacon().slot,
        fork_str(fork)
    );
    Ok(())
}
