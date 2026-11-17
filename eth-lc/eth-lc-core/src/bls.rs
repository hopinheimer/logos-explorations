//! Sync-committee participation and the aggregate signature check.
//!
//! Implements the participation and `bls.FastAggregateVerify` parts of
//! `validate_light_client_update` (`specs/altair/light-client/sync-protocol.md`,
//! `specs/altair/bls.md`). The participant key is the committee aggregate
//! minus the non-signers. The committee comes as a witness ([`KeyHints`]):
//! the root of its keys, the aggregate key, and each non-signer's key with
//! its branch, all uncompressed and bound to the committee root.

use alloc::vec::Vec;

use blst::min_pk::{AggregatePublicKey, PublicKey};
use blst::{
    blst_final_exp, blst_fp12, blst_fp12_is_one, blst_hash_to_g2, blst_miller_loop_n, blst_p1,
    blst_p1_affine, blst_p1_affine_generator, blst_p1_cneg, blst_p1_from_affine, blst_p1_to_affine,
    blst_p2, blst_p2_affine, blst_p2_affine_compress, blst_p2_affine_in_g2,
    blst_p2_affine_serialize, blst_p2_deserialize, blst_p2_to_affine, blst_p2_uncompress,
    BLST_ERROR,
};

use crate::config::ChainConfig;
use crate::crypto::hash_pair;
use crate::ssz::{is_valid_merkle_branch, pubkey_root};
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

/// Decodes a 96-byte key hint: the point, on the curve, and its compressed
/// bytes, which are what the committee's SSZ hashes. Only the plain
/// uncompressed encoding is taken (no flag bits), so a key has one encoding.
fn hinted_key(hint: &[u8; 96]) -> Result<(PublicKey, [u8; 48]), Error> {
    if hint[0] & 0xe0 != 0 {
        return Err(Error::InvalidKey);
    }
    let pk = PublicKey::deserialize(hint).map_err(|_| Error::InvalidKey)?;
    let compressed = pk.compress();
    Ok((pk, compressed))
}

/// Uncompressed G1 key of committed bytes, for a hint.
fn uncompressed_key(pk: &[u8; 48]) -> Result<[u8; 96], Error> {
    PublicKey::uncompress(pk)
        .map(|k| k.serialize())
        .map_err(|_| Error::InvalidKey)
}

impl KeyHints {
    /// The witness for `bits` over `committee`, and `signature` uncompressed:
    /// what a submitter sends with an update the committee signed.
    pub fn new(
        committee: &SyncCommittee,
        bits: &[u8],
        signature: &[u8; 96],
    ) -> Result<Self, Error> {
        let leaves: Vec<Root> = committee.pubkeys.iter().map(pubkey_root).collect();
        let size = leaves.len();
        if !size.is_power_of_two() {
            return Err(Error::CommitteeSize);
        }
        let mut layers = alloc::vec![leaves];
        while layers[layers.len() - 1].len() > 1 {
            let up = layers[layers.len() - 1]
                .chunks(2)
                .map(|p| hash_pair(&p[0], &p[1]))
                .collect();
            layers.push(up);
        }
        let depth = layers.len() - 1;
        let non_signers = (0..size)
            .filter(|&i| !bit(bits, i))
            .map(|i| {
                let branch = (0..depth).map(|d| layers[d][(i >> d) ^ 1]).collect();
                Ok((i as u32, uncompressed_key(&committee.pubkeys[i])?, branch))
            })
            .collect::<Result<_, Error>>()?;
        let mut sig = blst_p2_affine::default();
        let mut uncompressed = [0u8; 192];
        // SAFETY: `signature` is 96 bytes and `uncompressed` 192, the sizes blst reads and writes.
        unsafe {
            if blst_p2_uncompress(&mut sig, signature.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                return Err(Error::InvalidSignature);
            }
            blst_p2_affine_serialize(uncompressed.as_mut_ptr(), &sig);
        }
        Ok(Self {
            pubkeys_root: layers[depth][0],
            aggregate: uncompressed_key(&committee.aggregate_pubkey)?,
            non_signers,
            signature: uncompressed,
        })
    }
}

/// The participant key: the committee aggregate minus the non-signers, after
/// checking that `hints` is a witness for `bits` under `committee_root`: the
/// aggregate key and `pubkeys_root` hash to `committee_root`; the hint
/// indices equal the zero bits, in order; every non-signer's key is on the
/// curve and on its branch to `pubkeys_root`.
fn participant_key(
    cfg: &ChainConfig,
    committee_root: &Root,
    hints: &KeyHints,
    bits: &[u8],
) -> Result<PublicKey, Error> {
    let (all, compressed) = hinted_key(&hints.aggregate)?;
    if hash_pair(&hints.pubkeys_root, &pubkey_root(&compressed)) != *committee_root {
        return Err(Error::CommitteeMismatch);
    }
    let size = cfg.sync_committee_size as usize;
    let depth = size.trailing_zeros();
    let mut hinted = hints.non_signers.iter();
    for i in (0..size).filter(|&i| !bit(bits, i)) {
        match hinted.next() {
            Some((idx, _, _)) if *idx as usize == i => {}
            _ => return Err(Error::HintMismatch),
        }
    }
    if hinted.next().is_some() {
        return Err(Error::HintMismatch);
    }

    let mut participants = AggregatePublicKey::from_public_key(&all);
    let mut absent: Option<AggregatePublicKey> = None;
    for (idx, hint, branch) in &hints.non_signers {
        let (pk, compressed) = hinted_key(hint)?;
        if branch.len() != depth as usize
            || !is_valid_merkle_branch(
                &pubkey_root(&compressed),
                branch,
                depth,
                u64::from(*idx),
                &hints.pubkeys_root,
            )
        {
            return Err(Error::InvalidKey);
        }
        match &mut absent {
            None => absent = Some(AggregatePublicKey::from_public_key(&pk)),
            Some(a) => a
                .add_public_key(&pk, false)
                .map_err(|_| Error::InvalidKey)?,
        }
    }
    if let Some(a) = &absent {
        participants.sub_aggregate(a);
    }
    Ok(participants.to_public_key())
}

/// The signature part of `validate_light_client_update`:
/// `bls.FastAggregateVerify(participant_pubkeys, signing_root, signature)`.
///
/// `committee_root` is the store root the signature period selects. Steps:
/// the participant key from the witness ([`participant_key`]); it differs from
/// the identity; the hinted signature is on the curve, compresses to the
/// committed signature bytes and passes its subgroup check; then
/// e(-pk, H(m)) * e(g1, sig) = 1, with the two Miller loops run as one and a
/// single final exponentiation.
pub fn verify_sync_aggregate(
    cfg: &ChainConfig,
    committee_root: &Root,
    hints: &KeyHints,
    aggregate: &SyncAggregate,
    signing_root: &Root,
) -> Result<(), Error> {
    let pk = participant_key(cfg, committee_root, hints, &aggregate.bits)?;
    // Identity check on the compressed encoding. `PublicKey::validate` adds a
    // subgroup check that measured 2.5% of an E1b update; the participant key
    // is a sum of committed keys, so the identity is the case to exclude.
    if pk.compress() == G1_IDENTITY_COMPRESSED {
        return Err(Error::IdentityKey);
    }
    if hints.signature[0] & 0xe0 != 0 {
        return Err(Error::InvalidSignature);
    }
    let pk: blst_p1_affine = pk.into();
    let mut sig = blst_p2_affine::default();
    let mut committed = [0u8; 96];
    let (mut neg, mut neg_pk) = (blst_p1::default(), blst_p1_affine::default());
    let (mut h, mut hashed) = (blst_p2::default(), blst_p2_affine::default());
    let (mut f, mut gt) = (blst_fp12::default(), blst_fp12::default());
    // SAFETY: every pointer is to a live value of the type blst expects; the
    // byte buffers are 192 (uncompressed G2) and 96 (compressed G2) bytes.
    unsafe {
        if blst_p2_deserialize(&mut sig, hints.signature.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return Err(Error::InvalidSignature);
        }
        blst_p2_affine_compress(committed.as_mut_ptr(), &sig);
        if committed != aggregate.signature || !blst_p2_affine_in_g2(&sig) {
            return Err(Error::InvalidSignature);
        }
        blst_p1_from_affine(&mut neg, &pk);
        blst_p1_cneg(&mut neg, true);
        blst_p1_to_affine(&mut neg_pk, &neg);
        blst_hash_to_g2(
            &mut h,
            signing_root.as_ptr(),
            signing_root.len(),
            DST_POP.as_ptr(),
            DST_POP.len(),
            core::ptr::null(),
            0,
        );
        blst_p2_to_affine(&mut hashed, &h);
        let qs = [&hashed as *const blst_p2_affine, &sig];
        let ps = [&neg_pk as *const blst_p1_affine, blst_p1_affine_generator()];
        blst_miller_loop_n(&mut f, qs.as_ptr(), ps.as_ptr(), 2);
        blst_final_exp(&mut gt, &f);
        if blst_fp12_is_one(&gt) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use blst::min_pk::{SecretKey, Signature};

    use crate::config::ChainConfig;
    fn mainnet() -> ChainConfig {
        ChainConfig::mainnet()
    }

    /// Mainnet parameters with the 16-member committees these tests use.
    fn cfg16() -> ChainConfig {
        let mut cfg = mainnet();
        cfg.sync_committee_size = 16;
        cfg
    }

    fn verify(
        c: &SyncCommittee,
        h: &KeyHints,
        agg: &SyncAggregate,
        msg: &Root,
    ) -> Result<(), Error> {
        verify_sync_aggregate(&cfg16(), &c.hash_tree_root(), h, agg, msg)
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

    fn hints(c: &SyncCommittee, agg: &SyncAggregate) -> KeyHints {
        KeyHints::new(c, &agg.bits, &agg.signature).unwrap()
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
        assert_eq!(verify(&c, &hints(&c, &agg), &agg, &msg), Ok(()));
        let (_, c, agg, msg) = setup([0xff, 0xff]);
        assert_eq!(verify(&c, &hints(&c, &agg), &agg, &msg), Ok(()));
    }

    #[test]
    fn hint_set_must_equal_zero_bits() {
        let (_, c, agg, msg) = setup([0b1110_1111, 0b0111_1110]);
        let good = hints(&c, &agg);
        // Omitted hint.
        let mut h = good.clone();
        h.non_signers.pop();
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::HintMismatch));
        // Duplicate hint.
        let mut h = good.clone();
        h.non_signers.push(h.non_signers[2].clone());
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::HintMismatch));
        // Unsorted hints.
        let mut h = good.clone();
        h.non_signers.swap(0, 1);
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::HintMismatch));
        // Hint for another key.
        let mut h = good.clone();
        h.non_signers[0].1 = PublicKey::uncompress(&c.pubkeys[0]).unwrap().serialize();
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::InvalidKey));
        // Off-curve hint.
        let mut h = good.clone();
        h.non_signers[0].1[95] ^= 1;
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::InvalidKey));
        // Aggregate hint mismatch: the witness no longer hashes to the committee root.
        let mut h = good.clone();
        h.aggregate = PublicKey::uncompress(&c.pubkeys[0]).unwrap().serialize();
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::CommitteeMismatch));
        // Keys root of another committee.
        let mut h = good.clone();
        h.pubkeys_root[0] ^= 1;
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::CommitteeMismatch));
        // A non-signer's branch tampered, or one node short.
        let mut h = good.clone();
        h.non_signers[1].2[2][0] ^= 1;
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::InvalidKey));
        let mut h = good.clone();
        h.non_signers[1].2.pop();
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::InvalidKey));
        // The same key with the compressed flag set: one key, one encoding.
        let mut h = good.clone();
        h.non_signers[0].1[0] |= 0x80;
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::InvalidKey));
        // A witness of another committee is refused under this one's root.
        let other = committee(&keys(17)[1..]);
        let h = KeyHints::new(&other, &agg.bits, &agg.signature).unwrap();
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::CommitteeMismatch));
        // Zero bit flipped to one, hint kept.
        let mut a = agg.clone();
        a.bits[0] |= 0b0001_0000;
        assert_eq!(verify(&c, &good, &a, &msg), Err(Error::HintMismatch));
        // One bit flipped to zero, hint set unchanged.
        let mut a = agg.clone();
        a.bits[0] &= !1;
        assert_eq!(verify(&c, &good, &a, &msg), Err(Error::HintMismatch));
        // Signature byte: the hint no longer compresses to it.
        let mut a = agg.clone();
        a.signature[10] ^= 1;
        assert_eq!(verify(&c, &good, &a, &msg), Err(Error::InvalidSignature));
        // Signature hint off the curve, or flagged.
        let mut h = good.clone();
        h.signature[191] ^= 1;
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::InvalidSignature));
        let mut h = good.clone();
        h.signature[0] |= 0x80;
        assert_eq!(verify(&c, &h, &agg, &msg), Err(Error::InvalidSignature));
        // Another message.
        assert_eq!(
            verify(&c, &good, &agg, &[6; 32]),
            Err(Error::InvalidSignature)
        );
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
            verify(&c, &hints(&c, &agg), &agg, &[5; 32]),
            Err(Error::IdentityKey)
        );
    }
}
