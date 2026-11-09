//! Synthetic light-client data for tests: committees of test keys, headers
//! with consistent execution branches, beacon states with consistent
//! finality and committee branches, and signed updates for any supported fork.

use std::collections::BTreeMap;

use alloy_rlp::{Encodable, Header};
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use eth_lc_core::bls::{bit, DST_POP};
use eth_lc_core::config::{compute_domain, compute_signing_root, DOMAIN_SYNC_COMMITTEE};
use eth_lc_core::crypto::{hash_pair, keccak256};
use eth_lc_core::fork::{
    current_sync_committee_gindex, execution_gindex, finalized_root_gindex,
    next_sync_committee_gindex,
};
use eth_lc_core::{
    BeaconBlockHeader, BootstrapInput, ChainConfig, ExecutionPayloadHeaderCapella,
    ExecutionPayloadHeaderDeneb, ForkName, LightClientBootstrap, LightClientHeader,
    LightClientUpdate, Root, SyncAggregate, SyncCommittee, UpdateInput,
};

use crate::hints::key_hints;

/// A committee of test keys.
#[derive(Clone)]
pub struct TestCommittee {
    pub secret_keys: Vec<SecretKey>,
    pub committee: SyncCommittee,
}

impl TestCommittee {
    /// `size` deterministic keys from `seed`.
    pub fn new(seed: u8, size: usize) -> Self {
        let secret_keys: Vec<SecretKey> = (0..size)
            .map(|i| {
                let mut ikm = [seed; 32];
                ikm[..8].copy_from_slice(&(i as u64).to_le_bytes());
                SecretKey::key_gen(&ikm, &[]).expect("32-byte key material is valid")
            })
            .collect();
        Self::from_keys(secret_keys)
    }

    fn from_keys(secret_keys: Vec<SecretKey>) -> Self {
        let pks: Vec<PublicKey> = secret_keys.iter().map(SecretKey::sk_to_pk).collect();
        let refs: Vec<&PublicKey> = pks.iter().collect();
        let aggregate = AggregatePublicKey::aggregate(&refs, false)
            .expect("non-empty key set")
            .to_public_key();
        let committee = SyncCommittee {
            pubkeys: pks.iter().map(PublicKey::compress).collect(),
            aggregate_pubkey: aggregate.compress(),
        };
        Self {
            secret_keys,
            committee,
        }
    }

    /// Aggregate signature over `msg` by the members whose bit is set.
    pub fn sign(&self, bits: &[u8], msg: &Root) -> [u8; 96] {
        let sigs: Vec<Signature> = self
            .secret_keys
            .iter()
            .enumerate()
            .filter(|(i, _)| bit(bits, *i))
            .map(|(_, sk)| sk.sign(msg, DST_POP, &[]))
            .collect();
        if sigs.is_empty() {
            let mut inf = [0u8; 96];
            inf[0] = 0xc0;
            return inf;
        }
        let refs: Vec<&Signature> = sigs.iter().collect();
        AggregateSignature::aggregate(&refs, false)
            .expect("non-empty")
            .to_signature()
            .compress()
    }
}

/// Root of a sparse tree with `leaves` at their gindices and zero elsewhere,
/// plus the branch of each leaf (bottom-up siblings).
pub fn sparse_tree(leaves: &[(u64, Root)]) -> (Root, BTreeMap<u64, Vec<Root>>) {
    let map: BTreeMap<u64, Root> = leaves.iter().copied().collect();
    fn node(g: u64, map: &BTreeMap<u64, Root>) -> Root {
        if let Some(v) = map.get(&g) {
            return *v;
        }
        // Inner node when some leaf lies below g.
        let below = map.keys().any(|&l| {
            let mut x = l;
            while x > g {
                x /= 2;
            }
            x == g && l != g
        });
        if below {
            hash_pair(&node(2 * g, map), &node(2 * g + 1, map))
        } else {
            [0u8; 32]
        }
    }
    let branches = map
        .keys()
        .map(|&leaf| {
            let mut branch = Vec::new();
            let mut g = leaf;
            while g > 1 {
                branch.push(node(g ^ 1, &map));
                g /= 2;
            }
            (leaf, branch)
        })
        .collect();
    (node(1, &map), branches)
}

/// A minimal RLP execution header (21 fields) for Gloas anchors.
pub fn execution_header_rlp(number: u64, state_root: Root, receipts_root: Root) -> Vec<u8> {
    let mut items: Vec<Vec<u8>> = Vec::new();
    for i in 0..21u64 {
        let mut out = Vec::new();
        match i {
            3 => state_root.encode(&mut out),
            5 => receipts_root.encode(&mut out),
            6 => [0u8; 256].encode(&mut out),
            8 => number.encode(&mut out),
            _ => i.encode(&mut out),
        }
        items.push(out);
    }
    let mut out = Vec::new();
    Header {
        list: true,
        payload_length: items.iter().map(Vec::len).sum(),
    }
    .encode(&mut out);
    items.into_iter().for_each(|i| out.extend(i));
    out
}

/// A header at `slot` in the variant of its fork, with a valid execution
/// branch under `state_root`. Returns the RLP preimage for Gloas headers.
pub fn make_header(
    cfg: &ChainConfig,
    slot: u64,
    state_root: Root,
) -> (LightClientHeader, Option<Vec<u8>>) {
    let fork = cfg.fork_at_slot(slot);
    let exec_state = keccak256(&slot.to_le_bytes());
    let exec_receipts = keccak256(&(slot + 1).to_le_bytes());
    let mut capella = ExecutionPayloadHeaderCapella {
        block_number: slot,
        state_root: exec_state,
        receipts_root: exec_receipts,
        timestamp: slot * cfg.seconds_per_slot,
        extra_data: b"eth-lc synthetic".to_vec(),
        ..Default::default()
    };
    capella.block_hash = keccak256(&[&slot.to_le_bytes()[..], b"block"].concat());
    let (leaf, header_of, rlp): (
        Root,
        Box<dyn Fn(BeaconBlockHeader, Vec<Root>) -> LightClientHeader>,
        Option<Vec<u8>>,
    ) = match fork {
        ForkName::Capella => {
            let e = capella.clone();
            let root = e.hash_tree_root().expect("short extra data");
            (
                root,
                Box::new(move |beacon, branch| LightClientHeader::Capella {
                    beacon,
                    execution: e.clone(),
                    execution_branch: branch,
                }),
                None,
            )
        }
        ForkName::Deneb | ForkName::Electra | ForkName::Fulu => {
            let c = capella.clone();
            let e = ExecutionPayloadHeaderDeneb {
                parent_hash: c.parent_hash,
                fee_recipient: c.fee_recipient,
                state_root: c.state_root,
                receipts_root: c.receipts_root,
                logs_bloom: c.logs_bloom,
                prev_randao: c.prev_randao,
                block_number: c.block_number,
                gas_limit: c.gas_limit,
                gas_used: c.gas_used,
                timestamp: c.timestamp,
                extra_data: c.extra_data,
                base_fee_per_gas: c.base_fee_per_gas,
                block_hash: c.block_hash,
                transactions_root: c.transactions_root,
                withdrawals_root: c.withdrawals_root,
                blob_gas_used: 131_072,
                excess_blob_gas: 0,
            };
            let root = e.hash_tree_root().expect("short extra data");
            (
                root,
                Box::new(move |beacon, branch| LightClientHeader::Deneb {
                    beacon,
                    execution: e.clone(),
                    execution_branch: branch,
                }),
                None,
            )
        }
        ForkName::Gloas => {
            let rlp = execution_header_rlp(slot.saturating_sub(1), exec_state, exec_receipts);
            let hash = keccak256(&rlp);
            (
                hash,
                Box::new(move |beacon, branch| LightClientHeader::Gloas {
                    beacon,
                    execution_block_hash: hash,
                    execution_branch: branch,
                }),
                Some(rlp),
            )
        }
        f => panic!("synthetic headers start at Capella, not {f:?}"),
    };
    let gindex = execution_gindex(fork).expect("Capella or later");
    let (body_root, branches) = sparse_tree(&[(gindex, leaf)]);
    let beacon = BeaconBlockHeader {
        slot,
        proposer_index: slot % 7,
        parent_root: keccak256(&slot.to_be_bytes()),
        state_root,
        body_root,
    };
    (header_of(beacon, branches[&gindex].clone()), rlp)
}

/// A bootstrap at `slot` whose state carries `committee` as current committee.
pub fn make_bootstrap(cfg: &ChainConfig, slot: u64, committee: &SyncCommittee) -> BootstrapInput {
    let gindex = current_sync_committee_gindex(cfg.fork_at_slot(slot));
    let (state_root, branches) = sparse_tree(&[(gindex, committee.hash_tree_root())]);
    let (header, rlp) = make_header(cfg, slot, state_root);
    BootstrapInput {
        trusted_block_root: header.beacon().hash_tree_root(),
        bootstrap: LightClientBootstrap {
            header,
            current_sync_committee: committee.clone(),
            current_sync_committee_branch: branches[&gindex].clone(),
        },
        execution_header_rlp: rlp,
    }
}

/// Parameters of a synthetic update.
#[derive(Clone, Debug)]
pub struct UpdateSpec {
    pub attested_slot: u64,
    /// Finalized slot; `None` for an update with empty finality data.
    pub finalized_slot: Option<u64>,
    /// Next committee the attested state carries, if the update includes it.
    pub next: Option<SyncCommittee>,
    pub signature_slot: u64,
    /// Number of leading committee members that sign.
    pub signers: usize,
}

/// A signed update and its guest input for `signer`, plus the RLP preimage
/// of the finalized header's execution block (Gloas).
pub fn make_update(cfg: &ChainConfig, spec: &UpdateSpec, signer: &TestCommittee) -> UpdateInput {
    let attested_fork = cfg.fork_at_slot(spec.attested_slot);
    let finalized = spec.finalized_slot.map(|slot| {
        make_header(
            cfg,
            slot,
            keccak256(&[&slot.to_le_bytes()[..], b"state"].concat()),
        )
    });
    let mut leaves = Vec::new();
    let fin_gindex = finalized_root_gindex(attested_fork);
    let next_gindex = next_sync_committee_gindex(attested_fork);
    if let Some((h, _)) = &finalized {
        leaves.push((fin_gindex, h.beacon().hash_tree_root()));
    }
    if let Some(next) = &spec.next {
        leaves.push((next_gindex, next.hash_tree_root()));
    }
    if leaves.is_empty() {
        leaves.push((fin_gindex, keccak256(b"filler")));
    }
    let (state_root, branches) = sparse_tree(&leaves);
    let (attested, _) = make_header(cfg, spec.attested_slot, state_root);

    let size = cfg.sync_committee_size as usize;
    let mut bits = vec![0u8; size / 8];
    (0..spec.signers.min(size)).for_each(|i| bits[i / 8] |= 1 << (i % 8));
    let fork_version =
        cfg.fork_version_at_epoch(cfg.compute_epoch_at_slot(spec.signature_slot.saturating_sub(1)));
    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE,
        fork_version,
        &cfg.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&attested.beacon().hash_tree_root(), &domain);
    let signature = signer.sign(&bits, &signing_root);

    let rlp = finalized.as_ref().and_then(|(_, r)| r.clone());
    let update = LightClientUpdate {
        attested_header: attested,
        next_sync_committee: spec
            .next
            .clone()
            .map(|c| (c, branches[&next_gindex].clone())),
        finality: finalized.map(|(h, _)| (h, branches[&fin_gindex].clone())),
        sync_aggregate: SyncAggregate {
            bits: bits.clone(),
            signature,
        },
        signature_slot: spec.signature_slot,
    };
    UpdateInput {
        hints: key_hints(&signer.committee, &bits).expect("test keys decompress"),
        committee: signer.committee.clone(),
        update,
        execution_header_rlp: rlp,
    }
}
