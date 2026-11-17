//! Key hints for the signature check in `eth-lc-core`.

use anyhow::{anyhow, Result};
use eth_lc_core::{KeyHints, SyncAggregate, SyncCommittee};

/// Hints for `aggregate` over `committee`: the root of its keys, its
/// uncompressed aggregate key, each non-signer's uncompressed key with its
/// branch, in index order, and the uncompressed signature.
pub fn key_hints(committee: &SyncCommittee, aggregate: &SyncAggregate) -> Result<KeyHints> {
    KeyHints::new(committee, &aggregate.bits, &aggregate.signature)
        .map_err(|e| anyhow!("key hints: {e:?}"))
}
