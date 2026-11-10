//! E1b inputs from the recorded mainnet chain-dir (`eth-lc/vectors/mainnet`).
//!
//! For each period update N (0 to 3), writes into `<out-dir>`:
//! - `store-N.bin`: the instance state before step N, `S = borsh((ChainConfig, Store))`;
//! - `step-N.bin`: `S || borsh(UpdateInput)`, the `Update` message input;
//! - `stale-N.txt`: `stale_after_ms` of that store, the end of the `Update` window.
//!
//! The store before step 0 comes from `initialize_store`. Step 0 brings the
//! next committee; step 1 rotates it into current (the committee handoff).
//!
//! For `Attest`, after the four steps and the finality update recorded with
//! the claim evidence:
//! - `attest-state.bin`: that instance state;
//! - `attest-claim.bin`: `borsh(Claim)`, an account claim on WETH that holds there.

use std::path::PathBuf;

use anyhow::{anyhow, ensure, Context, Result};
use eth_lc_core::claim::{check_claim, Claim, Condition, Field, HeaderRecord, Op};
use eth_lc_core::{apply_update, initialize_store, stale_after_ms, ChainConfig, ForkName, Store};
use eth_lc_host::evidence::account_from_get_proof;
use eth_lc_host::forks::{self, Preset, Wire};
use eth_lc_host::ChainDir;

fn main() -> Result<()> {
    let out = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("usage: e1b-input <out-dir>")?,
    );
    let chain = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../eth-lc/vectors/mainnet"
    );
    let dir = ChainDir::load(chain)?;
    std::fs::create_dir_all(&out)?;
    let cfg = &dir.cfg;
    let mut store =
        initialize_store(cfg, &dir.bootstrap).map_err(|e| anyhow!("initialize_store: {e}"))?;
    for (n, update) in dir.updates.iter().enumerate() {
        let state = borsh::to_vec(&(cfg, &store))?;
        let input = dir.update_input(&store, update)?;
        let mut step = state.clone();
        step.extend(borsh::to_vec(&input)?);
        std::fs::write(out.join(format!("store-{n}.bin")), &state)?;
        std::fs::write(out.join(format!("step-{n}.bin")), &step)?;
        std::fs::write(
            out.join(format!("stale-{n}.txt")),
            stale_after_ms(cfg, &store).to_string(),
        )?;
        let next: Store =
            apply_update(cfg, &store, &input).map_err(|e| anyhow!("step {n}: {e}"))?;
        // Round trip: the state bytes decode to the same pair.
        let (c, s): (ChainConfig, Store) = borsh::from_slice(&state)?;
        ensure!(c == *cfg && s == store, "state bytes fail to round-trip");
        println!(
            "step {n}: period {} -> {} handoff={} finalized_slot={} execution_block={} input_bytes={}",
            cfg.period_at_slot(store.finalized.slot),
            cfg.period_at_slot(next.finalized.slot),
            next.current_committee_root != store.current_committee_root,
            next.finalized.slot,
            next.execution.number,
            step.len()
        );
        store = next;
    }

    // The evidence block: the finalized header of the evidence finality update.
    let evidence = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../eth-lc/vectors/mainnet/evidence"
    );
    let bytes = std::fs::read(format!("{evidence}/finality-update.ssz"))?;
    let raw = forks::decode_finality_update(ForkName::Fulu, Preset::Mainnet, Wire::Ssz(&bytes))?;
    let update = forks::to_core_update(cfg, &raw)?;
    let input = dir.update_input(&store, &update)?;
    let store = apply_update(cfg, &store, &input).map_err(|e| anyhow!("evidence update: {e}"))?;
    let weth: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{evidence}/weth-proof.json"))?)?;
    let claim = Claim {
        chain_id: cfg.chain_id,
        evidence: account_from_get_proof(&weth)?,
        conditions: vec![Condition {
            field: Field::Balance,
            op: Op::Gt,
            value: [0; 32],
        }],
    };
    check_claim(&HeaderRecord::from_store(cfg, &store), &claim)
        .map_err(|e| anyhow!("claim: {e}"))?;
    std::fs::write(out.join("attest-state.bin"), borsh::to_vec(&(cfg, &store))?)?;
    std::fs::write(out.join("attest-claim.bin"), borsh::to_vec(&claim)?)?;
    println!(
        "attest: finalized_slot={} execution_block={} stale_after_ms={}",
        store.finalized.slot,
        store.execution.number,
        stale_after_ms(cfg, &store)
    );
    Ok(())
}
