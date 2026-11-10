//! SSZ merkleization of the fixed light-client containers and Merkle branch
//! checks (`ssz/simple-serialize.md`, `ssz/merkle-proofs.md`,
//! `specs/phase0/beacon-chain.md`).

use alloc::vec::Vec;

use crate::crypto::{hash_pair, sha256};
use crate::types::{
    BeaconBlockHeader, ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb, Root,
    SyncCommittee,
};

/// `MAX_EXTRA_DATA_BYTES` (`specs/bellatrix/beacon-chain.md`).
pub const MAX_EXTRA_DATA_BYTES: usize = 32;

/// `merkleize(chunks, limit = 2**depth)` (`ssz/simple-serialize.md`): pads
/// with zero chunks up to `2**depth` leaves. Callers pass at most
/// `2**depth` chunks.
pub fn merkleize(chunks: &[Root], depth: u32) -> Root {
    let mut layer: Vec<Root> = chunks.to_vec();
    let mut zero = [0u8; 32];
    for _ in 0..depth {
        if layer.len() % 2 == 1 {
            layer.push(zero);
        }
        layer = layer
            .chunks_exact(2)
            .map(|p| hash_pair(&p[0], &p[1]))
            .collect();
        zero = hash_pair(&zero, &zero);
    }
    layer.first().copied().unwrap_or(zero)
}

/// `mix_in_length` (`ssz/simple-serialize.md`).
pub fn mix_in_length(root: &Root, length: usize) -> Root {
    let mut len = [0u8; 32];
    len[..8].copy_from_slice(&(length as u64).to_le_bytes());
    hash_pair(root, &len)
}

/// Chunk of a `uint64`.
pub fn u64_chunk(v: u64) -> Root {
    let mut c = [0u8; 32];
    c[..8].copy_from_slice(&v.to_le_bytes());
    c
}

fn bytes_chunk(b: &[u8]) -> Root {
    let mut c = [0u8; 32];
    c[..b.len()].copy_from_slice(b);
    c
}

/// `hash_tree_root` of a 48-byte `BLSPubkey`.
pub fn pubkey_root(pk: &[u8; 48]) -> Root {
    let mut buf = [0u8; 64];
    buf[..48].copy_from_slice(pk);
    sha256(&buf)
}

fn logs_bloom_root(bloom: &[u8; 256]) -> Root {
    let chunks: Vec<Root> = bloom.chunks_exact(32).map(bytes_chunk).collect();
    merkleize(&chunks, 3)
}

/// `hash_tree_root(ByteList[MAX_EXTRA_DATA_BYTES])`. Longer data is invalid;
/// the caller checks the length first.
fn extra_data_root(extra: &[u8]) -> Root {
    let chunks: Vec<Root> = extra.chunks(32).map(bytes_chunk).collect();
    mix_in_length(&merkleize(&chunks, 0), extra.len())
}

impl BeaconBlockHeader {
    /// `hash_tree_root(BeaconBlockHeader)`.
    pub fn hash_tree_root(&self) -> Root {
        merkleize(
            &[
                u64_chunk(self.slot),
                u64_chunk(self.proposer_index),
                self.parent_root,
                self.state_root,
                self.body_root,
            ],
            3,
        )
    }
}

impl SyncCommittee {
    /// `hash_tree_root(SyncCommittee)` for a committee of any power-of-two
    /// size. Size checks against the config happen in the sync functions.
    pub fn hash_tree_root(&self) -> Root {
        let leaves: Vec<Root> = self.pubkeys.iter().map(pubkey_root).collect();
        let depth = leaves.len().next_power_of_two().trailing_zeros();
        hash_pair(
            &merkleize(&leaves, depth),
            &pubkey_root(&self.aggregate_pubkey),
        )
    }
}

macro_rules! payload_fields {
    ($h:expr) => {
        [
            $h.parent_hash,
            bytes_chunk(&$h.fee_recipient),
            $h.state_root,
            $h.receipts_root,
            logs_bloom_root(&$h.logs_bloom),
            $h.prev_randao,
            u64_chunk($h.block_number),
            u64_chunk($h.gas_limit),
            u64_chunk($h.gas_used),
            u64_chunk($h.timestamp),
            extra_data_root(&$h.extra_data),
            $h.base_fee_per_gas,
            $h.block_hash,
            $h.transactions_root,
            $h.withdrawals_root,
        ]
    };
}

impl ExecutionPayloadHeaderCapella {
    /// `hash_tree_root(capella.ExecutionPayloadHeader)`. `None` when
    /// `extra_data` exceeds `MAX_EXTRA_DATA_BYTES`.
    pub fn hash_tree_root(&self) -> Option<Root> {
        if self.extra_data.len() > MAX_EXTRA_DATA_BYTES {
            return None;
        }
        Some(merkleize(&payload_fields!(self), 4))
    }
}

impl ExecutionPayloadHeaderDeneb {
    /// `hash_tree_root(deneb.ExecutionPayloadHeader)`. `None` when
    /// `extra_data` exceeds `MAX_EXTRA_DATA_BYTES`.
    pub fn hash_tree_root(&self) -> Option<Root> {
        if self.extra_data.len() > MAX_EXTRA_DATA_BYTES {
            return None;
        }
        let mut leaves: Vec<Root> = payload_fields!(self).to_vec();
        leaves.push(u64_chunk(self.blob_gas_used));
        leaves.push(u64_chunk(self.excess_blob_gas));
        Some(merkleize(&leaves, 5))
    }
}

/// `floorlog2` (`specs/phase0/beacon-chain.md`); 0 for 0.
pub fn floorlog2(x: u64) -> u32 {
    63u32.saturating_sub(x.leading_zeros())
}

/// `get_subtree_index` (`specs/altair/light-client/sync-protocol.md`).
pub fn get_subtree_index(gindex: u64) -> u64 {
    gindex % (1u64 << floorlog2(gindex))
}

/// `compute_merkle_branch_root` (`specs/gloas/light-client/sync-protocol.md`
/// uses it in `get_lc_execution_root`): the root from `leaf` and the first
/// `depth` nodes of `branch`. `None` when `branch` is shorter than `depth`.
pub fn compute_merkle_branch_root(
    leaf: &Root,
    branch: &[Root],
    depth: u32,
    index: u64,
) -> Option<Root> {
    if branch.len() < depth as usize {
        return None;
    }
    let mut value = *leaf;
    for (i, node) in branch.iter().take(depth as usize).enumerate() {
        value = if (index >> i) & 1 == 1 {
            hash_pair(node, &value)
        } else {
            hash_pair(&value, node)
        };
    }
    Some(value)
}

/// `is_valid_merkle_branch` (`specs/phase0/beacon-chain.md`). Reads the
/// first `depth` nodes of `branch`; fails when `branch` is shorter.
pub fn is_valid_merkle_branch(
    leaf: &Root,
    branch: &[Root],
    depth: u32,
    index: u64,
    root: &Root,
) -> bool {
    compute_merkle_branch_root(leaf, branch, depth, index) == Some(*root)
}

/// `is_valid_normalized_merkle_branch` (`specs/altair/light-client/sync-protocol.md`).
pub fn is_valid_normalized_merkle_branch(
    leaf: &Root,
    branch: &[Root],
    gindex: u64,
    root: &Root,
) -> bool {
    let depth = floorlog2(gindex);
    let index = get_subtree_index(gindex);
    let Some(num_extra) = branch.len().checked_sub(depth as usize) else {
        return false;
    };
    if branch[..num_extra].iter().any(|n| *n != [0u8; 32]) {
        return false;
    }
    is_valid_merkle_branch(leaf, &branch[num_extra..], depth, index, root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkleize_pads_with_zero_subtrees() {
        let z1 = hash_pair(&[0; 32], &[0; 32]);
        let a = [1u8; 32];
        assert_eq!(merkleize(&[], 0), [0; 32]);
        assert_eq!(merkleize(&[a], 0), a);
        assert_eq!(merkleize(&[a], 1), hash_pair(&a, &[0; 32]));
        assert_eq!(merkleize(&[a], 2), hash_pair(&hash_pair(&a, &[0; 32]), &z1));
        assert_eq!(merkleize(&[], 1), z1);
    }

    #[test]
    fn floorlog2_and_subtree_index() {
        assert_eq!(floorlog2(1), 0);
        assert_eq!(floorlog2(25), 4);
        assert_eq!(floorlog2(105), 6);
        assert_eq!(floorlog2(169), 7);
        assert_eq!(floorlog2(735), 9);
        assert_eq!(floorlog2(2856), 11);
        assert_eq!(floorlog2(2945), 11);
        assert_eq!(get_subtree_index(25), 9);
        assert_eq!(get_subtree_index(55), 23);
        assert_eq!(get_subtree_index(2946), 898);
    }

    fn root_of(leaf: Root, branch: &[Root], index: u64) -> Root {
        let mut v = leaf;
        for (i, n) in branch.iter().enumerate() {
            v = if (index >> i) & 1 == 1 {
                hash_pair(n, &v)
            } else {
                hash_pair(&v, n)
            };
        }
        v
    }

    #[test]
    fn normalized_branch_rules() {
        let leaf = [9u8; 32];
        let branch: Vec<Root> = (0..6).map(|i| [i as u8 + 1; 32]).collect();
        let root = root_of(leaf, &branch, get_subtree_index(105));
        assert!(is_valid_normalized_merkle_branch(
            &leaf, &branch, 105, &root
        ));
        // One zero prefix node: still valid (normalized to a deeper tree).
        let mut padded = alloc::vec![[0u8; 32]];
        padded.extend_from_slice(&branch);
        assert!(is_valid_normalized_merkle_branch(
            &leaf, &padded, 105, &root
        ));
        // Nonzero prefix node: invalid.
        padded[0][0] = 1;
        assert!(!is_valid_normalized_merkle_branch(
            &leaf, &padded, 105, &root
        ));
        // Short branch: invalid.
        assert!(!is_valid_normalized_merkle_branch(
            &leaf,
            &branch[1..],
            105,
            &root
        ));
        // Altered node: invalid.
        let mut bad = branch.clone();
        bad[3][0] ^= 1;
        assert!(!is_valid_normalized_merkle_branch(&leaf, &bad, 105, &root));
    }

    #[test]
    fn extra_data_limit() {
        let mut h = ExecutionPayloadHeaderCapella::default();
        h.extra_data = alloc::vec![1; 32];
        assert!(h.hash_tree_root().is_some());
        h.extra_data.push(1);
        assert!(h.hash_tree_root().is_none());
    }
}
