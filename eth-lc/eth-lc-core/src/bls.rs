//! Sync-committee participation and the aggregate signature check.
//!
//! Implements the participation and `bls.FastAggregateVerify` parts of
//! `validate_light_client_update` (`specs/altair/light-client/sync-protocol.md`,
//! `specs/altair/bls.md`). The participant key is the committee aggregate
//! minus the non-signers, from hinted uncompressed keys bound to the committed
//! compressed bytes.

use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use blst::BLST_ERROR;

use crate::config::ChainConfig;
use crate::types::{KeyHints, Root, SyncAggregate, SyncCommittee};
use crate::Error;

/// Ciphersuite of Ethereum BLS signatures (`specs/phase0/beacon-chain.md`, BLS signatures).
pub const DST_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Compressed encoding of the G1 identity (point at infinity).
const G1_IDENTITY_COMPRESSED: [u8; 48] = {
    let mut id = [0u8; 48];
    id[0] = 0xc0;
    id
};

/// `get_set_bit_count(sync_committee_bits)` after the length check
/// `len(bits) == SYNC_COMMITTEE_SIZE / 8`.
pub fn participation(cfg: &ChainConfig, bits: &[u8]) -> Result<u32, Error> {
    if bits.len() != (cfg.sync_committee_size / 8) as usize {
        return Err(Error::BitsLength);
    }
    Ok(bits.iter().map(|b| b.count_ones()).sum())
}

/// Bit `i` of an SSZ bitvector (LSB-first per byte).
pub fn bit(bits: &[u8], i: usize) -> bool {
    bits.get(i / 8).is_some_and(|b| (b >> (i % 8)) & 1 == 1)
}

/// Decodes a 96-byte hint and binds it to the committed compressed key.
fn bound_key(hint: &[u8; 96], committed: &[u8; 48]) -> Result<PublicKey, Error> {
    // `deserialize` accepts only the uncompressed form here and checks the point is on the curve.
    let pk = PublicKey::deserialize(hint).map_err(|_| Error::InvalidKey)?;
    if pk.compress() != *committed {
        return Err(Error::InvalidKey);
    }
    Ok(pk)
}

/// The signature part of `validate_light_client_update`:
/// `bls.FastAggregateVerify(participant_pubkeys, signing_root, signature)`.
///
/// `committee` must already be bound to the store (size and root). Steps:
/// hint indices equal the zero bits; every hinted key is on the curve and
/// compresses to its committed bytes; participant key = aggregate minus the
/// non-signers; the participant key differs from the identity; the
/// signature passes its subgroup check and verifies.
pub fn verify_sync_aggregate(
    committee: &SyncCommittee,
    hints: &KeyHints,
    aggregate: &SyncAggregate,
    signing_root: &Root,
) -> Result<(), Error> {
    let n = committee.pubkeys.len();
    let mut hinted = hints.non_signers.iter();
    for i in (0..n).filter(|&i| !bit(&aggregate.bits, i)) {
        match hinted.next() {
            Some((idx, _)) if *idx as usize == i => {}
            _ => return Err(Error::HintMismatch),
        }
    }
    if hinted.next().is_some() {
        return Err(Error::HintMismatch);
    }

    let all = bound_key(&hints.aggregate, &committee.aggregate_pubkey)?;
    let mut participants = AggregatePublicKey::from_public_key(&all);
    if let Some(((first_idx, first), rest)) = hints.non_signers.split_first() {
        let committed = |i: u32| committee.pubkeys.get(i as usize).ok_or(Error::HintMismatch);
        let mut absent =
            AggregatePublicKey::from_public_key(&bound_key(first, committed(*first_idx)?)?);
        for (idx, hint) in rest {
            let pk = bound_key(hint, committed(*idx)?)?;
            absent
                .add_public_key(&pk, false)
                .map_err(|_| Error::InvalidKey)?;
        }
        participants.sub_aggregate(&absent);
    }
    let pk = participants.to_public_key();
    // Identity check on the compressed encoding. `PublicKey::validate` adds a
    // subgroup check that measured 2.5% of an E1b update; the participant key
    // is a sum of committed keys, so the identity is the case to exclude.
    if pk.compress() == G1_IDENTITY_COMPRESSED {
        return Err(Error::IdentityKey);
    }

    let sig = Signature::from_bytes(&aggregate.signature).map_err(|_| Error::InvalidSignature)?;
    match sig.verify(true, signing_root, DST_POP, &[], &pk, false) {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(Error::InvalidSignature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use blst::min_pk::SecretKey;

    use crate::config::ChainConfig;
    fn mainnet() -> ChainConfig {
        ChainConfig::mainnet()
    }

    fn keys(n: usize) -> Vec<SecretKey> {
        (0..n)
            .map(|i| SecretKey::key_gen(&[i as u8 + 1; 32], &[]).unwrap())
            .collect()
    }

    fn committee(sks: &[SecretKey]) -> SyncCommittee {
        let pks: Vec<PublicKey> = sks.iter().map(|s| s.sk_to_pk()).collect();
        let refs: Vec<&PublicKey> = pks.iter().collect();
        let agg = AggregatePublicKey::aggregate(&refs, false)
            .unwrap()
            .to_public_key();
        SyncCommittee {
            pubkeys: pks.iter().map(|p| p.compress()).collect(),
            aggregate_pubkey: agg.compress(),
        }
    }

    fn hints(c: &SyncCommittee, bits: &[u8]) -> KeyHints {
        let ser = |k: &[u8; 48]| PublicKey::uncompress(k).unwrap().serialize();
        KeyHints {
            aggregate: ser(&c.aggregate_pubkey),
            non_signers: (0..c.pubkeys.len())
                .filter(|&i| !bit(bits, i))
                .map(|i| (i as u32, ser(&c.pubkeys[i])))
                .collect(),
        }
    }

    fn sign(sks: &[SecretKey], bits: &[u8], msg: &Root) -> [u8; 96] {
        let sigs: Vec<Signature> = sks
            .iter()
            .enumerate()
            .filter(|(i, _)| bit(bits, *i))
            .map(|(_, s)| s.sign(msg, DST_POP, &[]))
            .collect();
        let refs: Vec<&Signature> = sigs.iter().collect();
        blst::min_pk::AggregateSignature::aggregate(&refs, false)
            .unwrap()
            .to_signature()
            .compress()
    }

    fn setup(bits: [u8; 2]) -> (Vec<SecretKey>, SyncCommittee, SyncAggregate, Root) {
        let sks = keys(16);
        let c = committee(&sks);
        let msg = [5u8; 32];
        let agg = SyncAggregate {
            bits: bits.to_vec(),
            signature: sign(&sks, &bits, &msg),
        };
        (sks, c, agg, msg)
    }

    #[test]
    fn popcount_and_length() {
        let mut cfg = mainnet();
        cfg.sync_committee_size = 16;
        assert_eq!(participation(&cfg, &[0b1010_1010, 0xff]), Ok(12));
        assert_eq!(participation(&cfg, &[0xff]), Err(Error::BitsLength));
        assert_eq!(
            participation(&cfg, &[0xff, 0xff, 0]),
            Err(Error::BitsLength)
        );
    }

    #[test]
    fn valid_aggregate_verifies() {
        let (_, c, agg, msg) = setup([0b1110_1111, 0b0111_1111]);
        assert_eq!(
            verify_sync_aggregate(&c, &hints(&c, &agg.bits), &agg, &msg),
            Ok(())
        );
        let (_, c, agg, msg) = setup([0xff, 0xff]);
        assert_eq!(
            verify_sync_aggregate(&c, &hints(&c, &agg.bits), &agg, &msg),
            Ok(())
        );
    }

    #[test]
    fn hint_set_must_equal_zero_bits() {
        let (_, c, agg, msg) = setup([0b1110_1111, 0b0111_1110]);
        let good = hints(&c, &agg.bits);
        // Omitted hint.
        let mut h = good.clone();
        h.non_signers.pop();
        assert_eq!(
            verify_sync_aggregate(&c, &h, &agg, &msg),
            Err(Error::HintMismatch)
        );
        // Duplicate hint.
        let mut h = good.clone();
        h.non_signers.push(h.non_signers[2]);
        assert_eq!(
            verify_sync_aggregate(&c, &h, &agg, &msg),
            Err(Error::HintMismatch)
        );
        // Unsorted hints.
        let mut h = good.clone();
        h.non_signers.swap(0, 1);
        assert_eq!(
            verify_sync_aggregate(&c, &h, &agg, &msg),
            Err(Error::HintMismatch)
        );
        // Hint for another key.
        let mut h = good.clone();
        h.non_signers[0].1 = PublicKey::uncompress(&c.pubkeys[0]).unwrap().serialize();
        assert_eq!(
            verify_sync_aggregate(&c, &h, &agg, &msg),
            Err(Error::InvalidKey)
        );
        // Off-curve hint.
        let mut h = good.clone();
        h.non_signers[0].1[95] ^= 1;
        assert_eq!(
            verify_sync_aggregate(&c, &h, &agg, &msg),
            Err(Error::InvalidKey)
        );
        // Aggregate hint mismatch.
        let mut h = good.clone();
        h.aggregate = PublicKey::uncompress(&c.pubkeys[0]).unwrap().serialize();
        assert_eq!(
            verify_sync_aggregate(&c, &h, &agg, &msg),
            Err(Error::InvalidKey)
        );
        // Zero bit flipped to one, hint kept.
        let mut a = agg.clone();
        a.bits[0] |= 0b0001_0000;
        assert_eq!(
            verify_sync_aggregate(&c, &good, &a, &msg),
            Err(Error::HintMismatch)
        );
        // One bit flipped to zero, hint set unchanged.
        let mut a = agg.clone();
        a.bits[0] &= !1;
        assert_eq!(
            verify_sync_aggregate(&c, &good, &a, &msg),
            Err(Error::HintMismatch)
        );
        // Signature byte.
        let mut a = agg.clone();
        a.signature[10] ^= 1;
        assert!(verify_sync_aggregate(&c, &good, &a, &msg).is_err());
    }

    #[test]
    fn identity_participant_key_is_refused() {
        // Committee with key k at index 0 and -k at index 1: their sum is the identity.
        let sks = keys(16);
        let mut c = committee(&sks);
        let k = sks[0].sk_to_pk();
        let mut neg = AggregatePublicKey::from_public_key(&sks[2].sk_to_pk());
        neg.sub_aggregate(&AggregatePublicKey::from_public_key(&sks[2].sk_to_pk()));
        neg.sub_aggregate(&AggregatePublicKey::from_public_key(&k));
        c.pubkeys[1] = neg.to_public_key().compress();
        // Aggregate of the altered committee.
        let pks: Vec<PublicKey> = c
            .pubkeys
            .iter()
            .map(|p| PublicKey::uncompress(p).unwrap())
            .collect();
        let refs: Vec<&PublicKey> = pks.iter().collect();
        c.aggregate_pubkey = AggregatePublicKey::aggregate(&refs, false)
            .unwrap()
            .to_public_key()
            .compress();
        let bits = [0b0000_0011, 0];
        let agg = SyncAggregate {
            bits: bits.to_vec(),
            signature: sign(&sks[..1], &[1], &[5; 32]),
        };
        assert_eq!(
            verify_sync_aggregate(&c, &hints(&c, &bits), &agg, &[5; 32]),
            Err(Error::IdentityKey)
        );
    }
}
