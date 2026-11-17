//! Key hints for the signature check in `eth-lc-core`.

use anyhow::{anyhow, Result};
use eth_lc_core::sync::sync_signing_root;
use eth_lc_core::{ChainConfig, KeyHints, LightClientUpdate, SyncCommittee};

/// Hints for `update`'s sync aggregate over `committee`: the root of its
/// keys, its uncompressed aggregate key, each non-signer's uncompressed key
/// with its branch, in index order, the uncompressed signature, and the
/// pairing check's residue witness.
pub fn key_hints(
    cfg: &ChainConfig,
    committee: &SyncCommittee,
    update: &LightClientUpdate,
) -> Result<KeyHints> {
    KeyHints::new(
        committee,
        &update.sync_aggregate,
        &sync_signing_root(cfg, update),
    )
    .map_err(|e| anyhow!("key hints: {e:?}"))
}
