//! Spec containers, the light-client store and the guest inputs.
//!
//! Container fields follow consensus-specs `v1.7.0-beta.4`. Fixed-length SSZ
//! vectors (branches, committee keys) are `Vec`s here; the sync functions
//! check their lengths.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};

/// A 32-byte SSZ root or hash.
pub type Root = [u8; 32];

/// `BeaconBlockHeader` (`specs/phase0/beacon-chain.md`).
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
}

/// `ExecutionPayloadHeader` (`specs/capella/beacon-chain.md`).
/// `base_fee_per_gas` is the SSZ `uint256`, little-endian.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct ExecutionPayloadHeaderCapella {
    pub parent_hash: Root,
    pub fee_recipient: [u8; 20],
    pub state_root: Root,
    pub receipts_root: Root,
    pub logs_bloom: [u8; 256],
    pub prev_randao: Root,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
}

/// `ExecutionPayloadHeader` (`specs/deneb/beacon-chain.md`). The header
/// layout of Deneb, Electra and Fulu.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct ExecutionPayloadHeaderDeneb {
    pub parent_hash: Root,
    pub fee_recipient: [u8; 20],
    pub state_root: Root,
    pub receipts_root: Root,
    pub logs_bloom: [u8; 256],
    pub prev_randao: Root,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

impl Default for ExecutionPayloadHeaderCapella {
    fn default() -> Self {
        Self {
            parent_hash: [0; 32],
            fee_recipient: [0; 20],
            state_root: [0; 32],
            receipts_root: [0; 32],
            logs_bloom: [0; 256],
            prev_randao: [0; 32],
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Vec::new(),
            base_fee_per_gas: [0; 32],
            block_hash: [0; 32],
            transactions_root: [0; 32],
            withdrawals_root: [0; 32],
        }
    }
}

impl Default for ExecutionPayloadHeaderDeneb {
    fn default() -> Self {
        Self {
            parent_hash: [0; 32],
            fee_recipient: [0; 20],
            state_root: [0; 32],
            receipts_root: [0; 32],
            logs_bloom: [0; 256],
            prev_randao: [0; 32],
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Vec::new(),
            base_fee_per_gas: [0; 32],
            block_hash: [0; 32],
            transactions_root: [0; 32],
            withdrawals_root: [0; 32],
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }
}

/// `LightClientHeader` per fork layout (`specs/{capella,deneb,gloas}/light-client/sync-protocol.md`).
/// `Capella` holds at a Capella slot, `Deneb` at a Deneb, Electra or Fulu
/// slot. `Gloas` holds at any slot from Capella on: at an older slot it is
/// the Gloas upgrade of that slot's header (`specs/gloas/light-client/fork.md`).
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum LightClientHeader {
    Capella {
        beacon: BeaconBlockHeader,
        execution: ExecutionPayloadHeaderCapella,
        execution_branch: Vec<Root>,
    },
    Deneb {
        beacon: BeaconBlockHeader,
        execution: ExecutionPayloadHeaderDeneb,
        execution_branch: Vec<Root>,
    },
    Gloas {
        beacon: BeaconBlockHeader,
        execution_block_hash: Root,
        execution_branch: Vec<Root>,
    },
}

impl LightClientHeader {
    /// The beacon block header.
    pub fn beacon(&self) -> &BeaconBlockHeader {
        match self {
            Self::Capella { beacon, .. }
            | Self::Deneb { beacon, .. }
            | Self::Gloas { beacon, .. } => beacon,
        }
    }

    /// The execution branch.
    pub fn execution_branch(&self) -> &[Root] {
        match self {
            Self::Capella {
                execution_branch, ..
            }
            | Self::Deneb {
                execution_branch, ..
            }
            | Self::Gloas {
                execution_branch, ..
            } => execution_branch,
        }
    }

    /// `LightClientHeader.empty()`: every field holds its zero value.
    pub fn is_empty(&self) -> bool {
        let zero_branch = self.execution_branch().iter().all(|n| *n == [0; 32]);
        let zero_body = match self {
            Self::Capella { execution, .. } => {
                *execution == ExecutionPayloadHeaderCapella::default()
            }
            Self::Deneb { execution, .. } => *execution == ExecutionPayloadHeaderDeneb::default(),
            Self::Gloas {
                execution_block_hash,
                ..
            } => *execution_block_hash == [0; 32],
        };
        *self.beacon() == BeaconBlockHeader::default() && zero_branch && zero_body
    }
}

/// `SyncCommittee` (`specs/altair/beacon-chain.md`).
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct SyncCommittee {
    pub pubkeys: Vec<[u8; 48]>,
    pub aggregate_pubkey: [u8; 48],
}

/// `SyncAggregate` (`specs/altair/beacon-chain.md`). `bits` is the SSZ
/// `Bitvector[SYNC_COMMITTEE_SIZE]`: LSB-first per byte, `len == size / 8`.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct SyncAggregate {
    pub bits: Vec<u8>,
    pub signature: [u8; 96],
}

/// `LightClientBootstrap` (`specs/altair/light-client/sync-protocol.md`).
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct LightClientBootstrap {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub current_sync_committee_branch: Vec<Root>,
}

/// `LightClientUpdate` (`specs/altair/light-client/sync-protocol.md`).
/// `None` stands for the spec's empty next committee or empty finality data
/// (an all-zero branch). The next committee is its `hash_tree_root`: the store
/// keeps only that root, so its keys are not needed until it signs.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct LightClientUpdate {
    pub attested_header: LightClientHeader,
    pub next_sync_committee: Option<(Root, Vec<Root>)>,
    pub finality: Option<(LightClientHeader, Vec<Root>)>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}

impl LightClientUpdate {
    /// Slot of the finalized header; 0 (the empty header) when `finality` is `None`.
    pub fn finalized_slot(&self) -> u64 {
        self.finality.as_ref().map_or(0, |(h, _)| h.beacon().slot)
    }
}

/// The execution block a finalized header anchors.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct ExecutionAnchor {
    pub block_hash: Root,
    pub number: u64,
    pub state_root: Root,
    pub receipts_root: Root,
}

/// The light-client store. Committees are kept as roots; inputs carry a
/// witness of the signing committee ([`KeyHints`]) that must hash to the
/// selected root.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct Store {
    pub finalized: BeaconBlockHeader,
    pub execution: ExecutionAnchor,
    pub current_committee_root: Root,
    pub next_committee_root: Option<Root>,
}

/// What the signature check needs of the signing committee, in place of its
/// keys: the root of its `pubkeys` vector, its aggregate key, and each
/// non-signer's key with its branch to that root. Hashing all the keys cost
/// about a tenth of an update; this proves the committee root with one hash
/// and each non-signer with one hash per tree level. Points are uncompressed,
/// so the guest takes no square roots.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct KeyHints {
    /// `hash_tree_root` of the committee's `pubkeys` vector.
    pub pubkeys_root: Root,
    /// The committee aggregate key, uncompressed (96 bytes).
    pub aggregate: [u8; 96],
    /// Each non-signer, in committee order: index, uncompressed key, and the
    /// branch from its key's root to `pubkeys_root`.
    pub non_signers: Vec<(u32, [u8; 96], Vec<Root>)>,
    /// The sync aggregate signature, uncompressed (192 bytes).
    pub signature: [u8; 192],
}

/// Input of [`crate::apply_update`].
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct UpdateInput {
    pub update: LightClientUpdate,
    pub hints: KeyHints,
    /// RLP of the execution header a Gloas finalized header names.
    pub execution_header_rlp: Option<Vec<u8>>,
}

/// Input of [`crate::initialize_store`].
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct BootstrapInput {
    pub trusted_block_root: Root,
    pub bootstrap: LightClientBootstrap,
    /// RLP of the execution header a Gloas bootstrap header names.
    pub execution_header_rlp: Option<Vec<u8>>,
}
