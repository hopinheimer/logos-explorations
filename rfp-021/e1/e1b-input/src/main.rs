//! E1b inputs from the recorded mainnet chain-dir (`eth-lc/vectors/mainnet`).
//!
//! For each period update N (0 to 3), writes into `<out-dir>`:
//! - `store-N.bin`: the instance state before step N, `S = borsh((ChainConfig, Store))`;
//! - `step-N.bin`: `S || borsh(UpdateInput)`, the `Update` message input.
//!
//! The store before step 0 comes from `initialize_store`. Step 0 brings the
//! next committee; step 1 rotates it into current (the committee handoff).

use std::path::PathBuf;

use anyhow::{anyhow, ensure, Context, Result};
use eth_lc_core::{apply_update, initialize_store, ChainConfig, Store};
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
    Ok(())
}
