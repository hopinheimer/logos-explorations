//! Cross-check of the core MPT walker against proofs built by `alloy-trie`.

use alloy_rlp::Encodable;
use alloy_trie::proof::ProofRetainer;
use alloy_trie::{HashBuilder, Nibbles};
use eth_lc_core::crypto::keccak256;
use eth_lc_core::mpt::get;

/// Builds a trie of `(key, value)` pairs; returns the root and a proof per target key.
fn build(pairs: &[(Vec<u8>, Vec<u8>)], targets: &[Vec<u8>]) -> ([u8; 32], Vec<Vec<Vec<u8>>>) {
    let mut sorted: Vec<(Nibbles, &Vec<u8>)> =
        pairs.iter().map(|(k, v)| (Nibbles::unpack(k), v)).collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let nib: Vec<Nibbles> = targets.iter().map(Nibbles::unpack).collect();
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(nib.clone()));
    for (k, v) in &sorted {
        hb.add_leaf(k.clone(), v);
    }
    let root = hb.root().0;
    let nodes = hb.take_proof_nodes();
    let proofs = nib
        .iter()
        .map(|t| {
            nodes
                .matching_nodes_sorted(t)
                .into_iter()
                .map(|(_, n)| n.to_vec())
                .collect()
        })
        .collect();
    (root, proofs)
}

fn rlp_index(i: u64) -> Vec<u8> {
    let mut out = Vec::new();
    i.encode(&mut out);
    out
}

#[test]
fn hashed_keys_inclusion_and_absence() {
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..500u64)
        .map(|i| {
            (
                keccak256(&i.to_be_bytes()).to_vec(),
                keccak256(&[i as u8; 3])[..(i as usize % 31) + 1].to_vec(),
            )
        })
        .collect();
    let absent: Vec<Vec<u8>> = (1000..1050u64)
        .map(|i| keccak256(&i.to_be_bytes()).to_vec())
        .collect();
    let targets: Vec<Vec<u8>> = pairs
        .iter()
        .step_by(7)
        .map(|(k, _)| k.clone())
        .chain(absent.iter().cloned())
        .collect();
    let (root, proofs) = build(&pairs, &targets);
    for (t, p) in targets.iter().zip(&proofs) {
        let want = pairs.iter().find(|(k, _)| k == t).map(|(_, v)| v.clone());
        assert_eq!(get(&root, t, p), Ok(want));
    }
}

#[test]
fn short_keys_with_inline_nodes() {
    // Receipt-style keys and one-byte values: lower trie levels embed nodes inline.
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..300u64)
        .map(|i| (rlp_index(i), vec![(i % 200) as u8 + 1]))
        .collect();
    let targets: Vec<Vec<u8>> = (0..300u64)
        .step_by(13)
        .map(rlp_index)
        .chain([rlp_index(300), rlp_index(5000)])
        .collect();
    let (root, proofs) = build(&pairs, &targets);
    for (t, p) in targets.iter().zip(&proofs) {
        let want = pairs.iter().find(|(k, _)| k == t).map(|(_, v)| v.clone());
        assert_eq!(get(&root, t, p), Ok(want.clone()), "key {}", hex::encode(t));
        // EIP-1186 provers list hashed nodes only: drop the embedded entries.
        let hashed: Vec<Vec<u8>> = p
            .iter()
            .enumerate()
            .filter(|(i, n)| *i == 0 || n.len() >= 32)
            .map(|(_, n)| n.clone())
            .collect();
        assert_eq!(
            get(&root, t, &hashed),
            Ok(want),
            "key {} (hashed nodes only)",
            hex::encode(t)
        );
    }
}

#[test]
fn tampered_and_truncated_proofs_fail() {
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..200u64)
        .map(|i| (keccak256(&i.to_be_bytes()).to_vec(), vec![7; 40]))
        .collect();
    let t = pairs[17].0.clone();
    let (root, proofs) = build(&pairs, std::slice::from_ref(&t));
    let p = &proofs[0];
    assert!(get(&root, &t, p).unwrap().is_some());
    let mut bad = p.clone();
    let last = bad.len() - 1;
    bad[last][5] ^= 1;
    assert!(get(&root, &t, &bad).is_err());
    assert!(get(&root, &t, &p[..p.len() - 1]).is_err());
    assert!(get(&root, &t, &[]).is_err());
}
