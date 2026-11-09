//! Key hints for the signature check in `eth-lc-core`.

use anyhow::{anyhow, Result};
use blst::min_pk::PublicKey;
use eth_lc_core::bls::bit;
use eth_lc_core::{KeyHints, SyncCommittee};

fn uncompressed(pk: &[u8; 48]) -> Result<[u8; 96]> {
    PublicKey::uncompress(pk)
        .map(|k| k.serialize())
        .map_err(|e| anyhow!("committee key fails to decompress: {e:?}"))
}

/// Hints for `bits` over `committee`: the uncompressed committee aggregate
/// and the uncompressed key of every non-signer, in index order.
pub fn key_hints(committee: &SyncCommittee, bits: &[u8]) -> Result<KeyHints> {
    let non_signers = (0..committee.pubkeys.len())
        .filter(|&i| !bit(bits, i))
        .map(|i| Ok((u32::try_from(i)?, uncompressed(&committee.pubkeys[i])?)))
        .collect::<Result<_>>()?;
    Ok(KeyHints {
        aggregate: uncompressed(&committee.aggregate_pubkey)?,
        non_signers,
    })
}
