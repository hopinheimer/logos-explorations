//! consensus-specs `v1.7.0-beta.4` light-client `sync` vectors (minimal
//! preset; the pin has no mainnet-preset sync vectors).
//!
//! Spec store: a test-only `LightClientStore` (best valid update, safety
//! threshold, optimistic header, force update, store upgrade) on top of
//! `validate_light_client_update` (with the vector `current_slot`) and the
//! `spec-oracle` transition. Every step must succeed and match the checks.
//!
//! Strict store: `apply_update` on the same steps, from the same bootstrap.
//! On every step its result must equal the strict model (the spec validation,
//! the strict policy, then the spec transition). While it tracks the spec
//! store, these relations hold:
//! - both committee roots equal the spec store's on every step;
//! - `Err(AcceptRule)` comes only with two-thirds participation, finality,
//!   and an accept rule that fails by an independent computation (a
//!   next-committee signature with the finalized header in the store period);
//! - across a run of such refusals the strict finalized header may stay
//!   behind the spec store's, in the same period; every other result leaves
//!   it equal;
//! - `Ok` comes only on a two-thirds step the spec store applied, and then
//!   the finalized header, both committee roots and the execution anchor
//!   equal the spec store's;
//! - any other error comes only on a step where the spec store skipped its
//!   two-thirds arm.
//!
//! A spec force update leaves the strict store unchanged. The cases where
//! one happens are pinned; after it, the strict store is checked against the
//! strict model only.
//!
//! Gloas-variant headers need the RLP preimage of their execution block. The
//! test derives each preimage and checks it by Keccak-256: from a payload
//! header in the same case (`compute_el_header_block_hash` in the pyspec
//! helper `execution_payload.py`, empty transactions and withdrawals, empty
//! requests), or from the Gloas genesis payload of the pyspec helper
//! `genesis.py`. A Gloas-variant header needs a derivation; a missing one
//! fails the case.
//!
//! Data: `SPEC_DATA` (default `../spec-data`), filled by `just spec-tests`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use alloy_consensus::Header;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use alloy_rlp::Encodable;
use eth_lc_core::crypto::{keccak256, sha256};
use eth_lc_core::execution::execution_anchor;
use eth_lc_core::oracle;
use eth_lc_core::profile::FORK_COUNT;
use eth_lc_core::{
    apply_update, get_lc_execution_root, initialize_store, validate_light_client_update,
    BootstrapInput, ChainConfig, Error, ForkName, LightClientHeader, LightClientUpdate, Root,
    Store, SyncCommittee, UpdateInput,
};
use eth_lc_host::chain_dir::parse_root;
use eth_lc_host::forks::{self, Preset, Wire};
use eth_lc_host::key_hints;
use serde_yaml::Value;

fn data_dir() -> PathBuf {
    std::env::var("SPEC_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec-data"))
}

fn snappy(path: &Path) -> Vec<u8> {
    let raw = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    snap::raw::Decoder::new().decompress_vec(&raw).unwrap()
}

fn yaml(path: &Path) -> Value {
    serde_yaml::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

const EPOCH_KEYS: [&str; 7] = [
    "ALTAIR_FORK_EPOCH",
    "BELLATRIX_FORK_EPOCH",
    "CAPELLA_FORK_EPOCH",
    "DENEB_FORK_EPOCH",
    "ELECTRA_FORK_EPOCH",
    "FULU_FORK_EPOCH",
    "GLOAS_FORK_EPOCH",
];

/// Config of a case: the minimal preset with the case's genesis root and fork epochs.
fn case_config(case: &Path, gvr: Root) -> ChainConfig {
    let cfg_yaml = yaml(&case.join("config.yaml"));
    let mut epochs = [0u64; FORK_COUNT];
    for (i, k) in EPOCH_KEYS.iter().enumerate() {
        epochs[i + 1] = cfg_yaml.get(*k).and_then(Value::as_u64).unwrap_or(u64::MAX);
    }
    ChainConfig::minimal(gvr, epochs)
}

const LAYOUTS: [ForkName; 4] = [
    ForkName::Capella,
    ForkName::Deneb,
    ForkName::Electra,
    ForkName::Gloas,
];

/// Layout fork of a slot's fork (Fulu uses the Electra layout).
fn layout_of(f: ForkName) -> ForkName {
    if f == ForkName::Fulu {
        ForkName::Electra
    } else {
        f
    }
}

/// Decodes an update in the layout of its attested slot's fork, and the keys
/// of the next committee it carries (the core update holds only its root).
fn decode_update(cfg: &ChainConfig, bytes: &[u8]) -> (LightClientUpdate, Option<SyncCommittee>) {
    for layout in LAYOUTS {
        if let Ok(raw) = forks::decode_update(layout, Preset::Minimal, Wire::Ssz(bytes)) {
            if layout_of(cfg.fork_at_slot(raw.attested_header.beacon().slot)) == layout {
                let update = forks::to_core_update(cfg, &raw).unwrap();
                let next = update
                    .next_sync_committee
                    .as_ref()
                    .and(raw.next)
                    .map(|(c, _)| c);
                return (update, next);
            }
        }
    }
    panic!("no layout decodes this update")
}

fn decode_bootstrap(cfg: &ChainConfig, bytes: &[u8]) -> eth_lc_core::LightClientBootstrap {
    for layout in LAYOUTS {
        if let Ok(raw) = forks::decode_bootstrap(layout, Preset::Minimal, Wire::Ssz(bytes)) {
            if layout_of(cfg.fork_at_slot(raw.header.beacon().slot)) == layout {
                return forks::to_core_bootstrap(cfg, &raw).unwrap();
            }
        }
    }
    panic!("no layout decodes this bootstrap")
}

/// `keccak256(rlp(b""))`: the root of the empty trie and the hash of an empty
/// block access list.
const EMPTY_TRIE_ROOT: &str = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
/// `keccak256(rlp([]))`: the ommers hash after the merge.
const EMPTY_OMMERS_HASH: &str = "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347";

fn b256(hex_str: &str) -> B256 {
    B256::from_slice(&hex::decode(hex_str).unwrap())
}

fn rlp(h: &Header) -> Vec<u8> {
    let mut out = Vec::new();
    h.encode(&mut out);
    out
}

/// The RLP header of the Gloas genesis payload of the pyspec helper
/// `get_sample_genesis_execution_payload` with `GENESIS_ETH1_BLOCK_HASH`.
fn gloas_genesis_rlp() -> Vec<u8> {
    rlp(&Header {
        parent_hash: B256::repeat_byte(0x30),
        ommers_hash: b256(EMPTY_OMMERS_HASH),
        beneficiary: Address::repeat_byte(0x42),
        state_root: B256::repeat_byte(0x20),
        transactions_root: b256(EMPTY_TRIE_ROOT),
        receipts_root: B256::repeat_byte(0x20),
        logs_bloom: Bloom::repeat_byte(0x35),
        difficulty: U256::ZERO,
        number: 0,
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: 0,
        extra_data: Bytes::new(),
        mix_hash: B256::repeat_byte(0xda),
        nonce: B64::ZERO,
        base_fee_per_gas: Some(1_000_000_000),
        withdrawals_root: Some(b256(EMPTY_TRIE_ROOT)),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::ZERO),
        requests_hash: Some(B256::from(sha256(&[]))),
        block_access_list_hash: Some(b256(EMPTY_TRIE_ROOT)),
        slot_number: Some(0),
    })
}

/// The RLP header behind a Capella or Deneb variant's payload, by
/// `compute_el_header_block_hash` with empty transactions, withdrawals and
/// requests. `None` for a Gloas variant or a base fee above `u64`.
fn payload_rlp(cfg: &ChainConfig, h: &LightClientHeader) -> Option<(Root, Vec<u8>)> {
    let fork = cfg.fork_at_slot(h.beacon().slot);
    let (e, blob) = match h {
        LightClientHeader::Capella { execution: e, .. } => (
            (
                e.parent_hash,
                e.fee_recipient,
                e.state_root,
                e.receipts_root,
                e.logs_bloom,
                e.prev_randao,
                e.block_number,
                e.gas_limit,
                e.gas_used,
                e.timestamp,
                e.extra_data.clone(),
                e.base_fee_per_gas,
                e.block_hash,
            ),
            None,
        ),
        LightClientHeader::Deneb { execution: e, .. } => (
            (
                e.parent_hash,
                e.fee_recipient,
                e.state_root,
                e.receipts_root,
                e.logs_bloom,
                e.prev_randao,
                e.block_number,
                e.gas_limit,
                e.gas_used,
                e.timestamp,
                e.extra_data.clone(),
                e.base_fee_per_gas,
                e.block_hash,
            ),
            Some((e.blob_gas_used, e.excess_blob_gas)),
        ),
        LightClientHeader::Gloas { .. } => return None,
    };
    let base_fee = U256::from_le_bytes(e.11);
    let deneb = fork >= ForkName::Deneb;
    let header = Header {
        parent_hash: B256::from(e.0),
        ommers_hash: b256(EMPTY_OMMERS_HASH),
        beneficiary: Address::from(e.1),
        state_root: B256::from(e.2),
        transactions_root: b256(EMPTY_TRIE_ROOT),
        receipts_root: B256::from(e.3),
        logs_bloom: Bloom::from(e.4),
        difficulty: U256::ZERO,
        number: e.6,
        gas_limit: e.7,
        gas_used: e.8,
        timestamp: e.9,
        extra_data: Bytes::from(e.10),
        mix_hash: B256::from(e.5),
        nonce: B64::ZERO,
        base_fee_per_gas: Some(u64::try_from(base_fee).ok()?),
        withdrawals_root: Some(b256(EMPTY_TRIE_ROOT)),
        blob_gas_used: deneb.then(|| blob.map_or(0, |b| b.0)),
        excess_blob_gas: deneb.then(|| blob.map_or(0, |b| b.1)),
        parent_beacon_block_root: deneb.then(|| B256::from(h.beacon().parent_root)),
        requests_hash: (fork >= ForkName::Electra).then(|| B256::from(sha256(&[]))),
        block_access_list_hash: None,
        slot_number: None,
    };
    Some((e.12, rlp(&header)))
}

/// Execution preimages of a case, by block hash, each checked by Keccak-256.
struct Preimages(HashMap<Root, Vec<u8>>);

impl Preimages {
    fn derive(cfg: &ChainConfig, headers: &[LightClientHeader]) -> Self {
        let mut map = HashMap::new();
        let genesis = gloas_genesis_rlp();
        map.insert(keccak256(&genesis), genesis);
        for h in headers {
            if let Some((hash, rlp)) = payload_rlp(cfg, h) {
                if keccak256(&rlp) == hash {
                    map.insert(hash, rlp);
                }
            }
        }
        Self(map)
    }

    /// The preimage a header's anchor needs: `None` for Capella and Deneb
    /// variants. Panics for a Gloas variant whose block hash has no derivation.
    fn of(&self, h: &LightClientHeader, ctx: &str) -> Option<Vec<u8>> {
        match h {
            LightClientHeader::Gloas {
                execution_block_hash,
                ..
            } => Some(
                self.0
                    .get(execution_block_hash)
                    .cloned()
                    .unwrap_or_else(|| {
                        panic!(
                            "{ctx}: no preimage derivation for execution block 0x{}",
                            hex::encode(execution_block_hash)
                        )
                    }),
            ),
            _ => None,
        }
    }
}

/// The test-only spec `LightClientStore`.
struct SpecStore {
    cfg: ChainConfig,
    core: Store,
    finalized: LightClientHeader,
    optimistic: LightClientHeader,
    best_valid_update: Option<LightClientUpdate>,
    previous_max_active_participants: u64,
    current_max_active_participants: u64,
    committees: HashMap<Root, SyncCommittee>,
}

fn popcount(u: &LightClientUpdate) -> u64 {
    u.sync_aggregate
        .bits
        .iter()
        .map(|b| b.count_ones() as u64)
        .sum()
}

impl SpecStore {
    fn period(&self, slot: u64) -> u64 {
        self.cfg.period_at_slot(slot)
    }

    /// `is_better_update` (`specs/altair/light-client/sync-protocol.md`).
    fn is_better_update(&self, new: &LightClientUpdate, old: &LightClientUpdate) -> bool {
        let max = self.cfg.sync_committee_size as u64;
        let (n_new, n_old) = (popcount(new), popcount(old));
        let (sm_new, sm_old) = (n_new * 3 >= max * 2, n_old * 3 >= max * 2);
        if sm_new != sm_old {
            return sm_new;
        }
        if !sm_new && n_new != n_old {
            return n_new > n_old;
        }
        let relevant = |u: &LightClientUpdate| {
            u.next_sync_committee.is_some()
                && self.period(u.attested_header.beacon().slot) == self.period(u.signature_slot)
        };
        if relevant(new) != relevant(old) {
            return relevant(new);
        }
        let (f_new, f_old) = (new.finality.is_some(), old.finality.is_some());
        if f_new != f_old {
            return f_new;
        }
        if f_new {
            let scf = |u: &LightClientUpdate| {
                self.period(u.finalized_slot()) == self.period(u.attested_header.beacon().slot)
            };
            if scf(new) != scf(old) {
                return scf(new);
            }
        }
        if n_new != n_old {
            return n_new > n_old;
        }
        let (a_new, a_old) = (
            new.attested_header.beacon().slot,
            old.attested_header.beacon().slot,
        );
        if a_new != a_old {
            return a_new < a_old;
        }
        new.signature_slot < old.signature_slot
    }

    fn safety_threshold(&self) -> u64 {
        self.previous_max_active_participants
            .max(self.current_max_active_participants)
            / 2
    }

    /// `apply_light_client_update` on the full store: participant counters,
    /// the oracle transition on committee roots, and the full headers.
    fn apply(&mut self, update: &LightClientUpdate) {
        let store_period = self.period(self.core.finalized.slot);
        let fin_period = self.period(update.finalized_slot());
        if self.core.next_committee_root.is_some() && fin_period == store_period + 1 {
            self.previous_max_active_participants = self.current_max_active_participants;
            self.current_max_active_participants = 0;
        }
        oracle::apply_light_client_update(&self.cfg, &mut self.core, update).unwrap();
        if let Some((h, _)) = &update.finality {
            if h.beacon().slot > self.finalized.beacon().slot {
                self.finalized = h.clone();
                if h.beacon().slot > self.optimistic.beacon().slot {
                    self.optimistic = h.clone();
                }
            }
        }
    }

    /// The committee behind the root that `update`'s signature period selects in `st`.
    fn signer_for(&self, st: &Store, update: &LightClientUpdate) -> SyncCommittee {
        let root = if self.period(update.signature_slot) == self.period(st.finalized.slot) {
            Some(st.current_committee_root)
        } else {
            st.next_committee_root
        };
        root.and_then(|r| self.committees.get(&r).cloned())
            .unwrap_or_else(|| SyncCommittee {
                pubkeys: vec![[0; 48]; self.cfg.sync_committee_size as usize],
                aggregate_pubkey: [0; 48],
            })
    }

    /// `process_light_client_update`. Returns whether the 2/3 arm applied.
    fn process(&mut self, update: &LightClientUpdate, current_slot: u64) -> Result<bool, Error> {
        let committee = self.signer_for(&self.core, update);
        let hints = key_hints(&self.cfg, &committee, update).map_err(|_| Error::InvalidKey)?;
        validate_light_client_update(&self.cfg, &self.core, update, &hints, current_slot)?;
        if self
            .best_valid_update
            .as_ref()
            .is_none_or(|b| self.is_better_update(update, b))
        {
            self.best_valid_update = Some(update.clone());
        }
        let n = popcount(update);
        self.current_max_active_participants = self.current_max_active_participants.max(n);
        if n > self.safety_threshold()
            && update.attested_header.beacon().slot > self.optimistic.beacon().slot
        {
            self.optimistic = update.attested_header.clone();
        }
        let has_finalized_next = self.core.next_committee_root.is_none()
            && update.next_sync_committee.is_some()
            && update.finality.is_some()
            && self.period(update.finalized_slot())
                == self.period(update.attested_header.beacon().slot);
        let max = self.cfg.sync_committee_size as u64;
        if n * 3 >= max * 2
            && (update.finalized_slot() > self.core.finalized.slot || has_finalized_next)
        {
            self.apply(update);
            self.best_valid_update = None;
            return Ok(true);
        }
        Ok(false)
    }

    /// `process_light_client_store_force_update`. Returns whether it applied.
    fn force_update(&mut self, current_slot: u64) -> bool {
        let timeout = self.cfg.slots_per_epoch * self.cfg.epochs_per_sync_committee_period;
        if current_slot > self.core.finalized.slot + timeout {
            if let Some(mut best) = self.best_valid_update.take() {
                if best.finalized_slot() <= self.core.finalized.slot {
                    let branch = best
                        .finality
                        .as_ref()
                        .map(|(_, b)| b.clone())
                        .unwrap_or_default();
                    best.finality = Some((best.attested_header.clone(), branch));
                }
                self.apply(&best);
                return true;
            }
        }
        false
    }

    fn check(&self, checks: &Value, ctx: &str) {
        for (name, h) in [
            ("finalized_header", &self.finalized),
            ("optimistic_header", &self.optimistic),
        ] {
            let c = &checks[name];
            assert_eq!(
                c["slot"].as_u64(),
                Some(h.beacon().slot),
                "{ctx}: {name}.slot"
            );
            assert_eq!(
                parse_root(c["beacon_root"].as_str().unwrap()).unwrap(),
                h.beacon().hash_tree_root(),
                "{ctx}: {name}.beacon_root"
            );
            if let Some(e) = c.get("execution_root") {
                assert_eq!(
                    parse_root(e.as_str().unwrap()).unwrap(),
                    get_lc_execution_root(&self.cfg, h),
                    "{ctx}: {name}.execution_root"
                );
            }
        }
    }
}

/// The strict model: the spec validation minus the `current_slot` bound,
/// the strict policy (two thirds, finality, accept rule, progress), the spec
/// transition, and the anchor of a new finalized header.
fn strict_model(cfg: &ChainConfig, st: &Store, input: &UpdateInput) -> Result<Store, Error> {
    let u = &input.update;
    validate_light_client_update(cfg, st, u, &input.hints, u64::MAX)?;
    if popcount(u) * 3 < cfg.sync_committee_size as u64 * 2 {
        return Err(Error::NoSupermajority);
    }
    let Some((finalized, _)) = &u.finality else {
        return Err(Error::MissingFinality);
    };
    let store_period = cfg.period_at_slot(st.finalized.slot);
    let fin_period = cfg.period_at_slot(finalized.beacon().slot);
    if cfg.period_at_slot(u.signature_slot) != store_period && fin_period != store_period + 1 {
        return Err(Error::AcceptRule);
    }
    let has_finalized_next = st.next_committee_root.is_none()
        && u.next_sync_committee.is_some()
        && fin_period == cfg.period_at_slot(u.attested_header.beacon().slot);
    let advances = finalized.beacon().slot > st.finalized.slot;
    if !(advances || has_finalized_next) {
        return Err(Error::NoProgress);
    }
    let mut next = st.clone();
    oracle::apply_light_client_update(cfg, &mut next, u)?;
    if advances {
        next.execution = execution_anchor(finalized, input.execution_header_rlp.as_deref())?;
    } else if input.execution_header_rlp.is_some() {
        return Err(Error::UnexpectedExecutionPreimage);
    }
    Ok(next)
}

/// The store fork of a case, from the pyspec helper that emits it
/// (`light_client_sync.py`, `test_sync.py`): `fork` for
/// `<fork>_store_with_legacy_data`, `fork_2` for the two-fork transitions
/// `<fork_1>_<fork_2>_fork`, and the fork directory otherwise (single-fork
/// tests, one-fork transitions `<fork>_fork`).
fn store_fork(dir_fork: ForkName, case_name: &str) -> ForkName {
    if let Some(f) = case_name.strip_suffix("_store_with_legacy_data") {
        return forks::parse_fork(f).unwrap();
    }
    match case_name
        .strip_suffix("_fork")
        .map(|fs| fs.split('_').collect::<Vec<_>>())
    {
        Some(names) if names.len() == 2 => forks::parse_fork(names[1]).unwrap(),
        _ => dir_fork,
    }
}

/// `_get_store_fork_version` (pyspec helper `light_client_sync.py`): Electra's
/// version for an Electra or Fulu store.
fn store_fork_version(cfg: &ChainConfig, fork: ForkName) -> [u8; 4] {
    let f = if fork == ForkName::Fulu {
        ForkName::Electra
    } else {
        fork
    };
    cfg.forks[f as usize].version
}

/// Outcome of one case.
#[derive(Default)]
struct Outcome {
    steps: usize,
    strict_accepted: usize,
    accept_rule_refusals: usize,
    force_update_steps: Vec<usize>,
    model_only_steps: usize,
    notes: Vec<String>,
}

fn run_case(dir_fork: ForkName, case: &Path) -> Outcome {
    let case_name = case.file_name().unwrap().to_string_lossy().to_string();
    let ctx = format!("{dir_fork:?}/{case_name}");
    let meta = yaml(&case.join("meta.yaml"));
    let gvr = parse_root(meta["genesis_validators_root"].as_str().unwrap()).unwrap();
    let cfg = case_config(case, gvr);
    let trusted = parse_root(meta["trusted_block_root"].as_str().unwrap()).unwrap();
    let bootstrap = decode_bootstrap(&cfg, &snappy(&case.join("bootstrap.ssz_snappy")));

    let store_version = hex::decode(
        meta["store_fork_version"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let sf = store_fork(dir_fork, &case_name);
    assert_eq!(
        store_version[..],
        store_fork_version(&cfg, sf)[..],
        "{ctx}: store_fork_version"
    );
    assert!(
        sf >= cfg.fork_at_slot(bootstrap.header.beacon().slot),
        "{ctx}: store fork {sf:?} before the bootstrap fork"
    );

    // Every header of the case, for the preimage derivations.
    let steps = yaml(&case.join("steps.yaml"));
    let mut updates = HashMap::new();
    // Committee keys by root: the store holds roots, and the signer's keys are
    // looked up by the root the store selects.
    let mut committees: HashMap<Root, SyncCommittee> = [(
        bootstrap.current_sync_committee.hash_tree_root(),
        bootstrap.current_sync_committee.clone(),
    )]
    .into();
    let mut headers = vec![bootstrap.header.clone()];
    for step in steps.as_sequence().unwrap() {
        if let Some(s) = step.get("process_update") {
            let name = s["update"].as_str().unwrap().trim().to_string();
            let (u, next) = decode_update(&cfg, &snappy(&case.join(format!("{name}.ssz_snappy"))));
            if let Some(c) = next {
                committees.insert(c.hash_tree_root(), c);
            }
            headers.push(u.attested_header.clone());
            headers.extend(u.finality.iter().map(|(h, _)| h.clone()));
            updates.insert(name, u);
        }
    }
    let preimages = Preimages::derive(&cfg, &headers);

    let input = BootstrapInput {
        trusted_block_root: trusted,
        bootstrap: bootstrap.clone(),
        execution_header_rlp: preimages.of(&bootstrap.header, &ctx),
    };
    let st0 = initialize_store(&cfg, &input).unwrap_or_else(|e| panic!("{ctx}: bootstrap: {e}"));
    assert!(
        eth_lc_core::is_valid_light_client_header(&cfg, &bootstrap.header),
        "{ctx}"
    );
    let mut spec = SpecStore {
        cfg: cfg.clone(),
        core: st0.clone(),
        finalized: bootstrap.header.clone(),
        optimistic: bootstrap.header.clone(),
        best_valid_update: None,
        previous_max_active_participants: 0,
        current_max_active_participants: 0,
        committees,
    };
    let mut st = st0;
    // Set by an accept-rule refusal, cleared by an accepted step.
    let mut lag_allowed = false;
    // The step of the first spec force update, after which only the model applies.
    let mut diverged = false;
    let mut out = Outcome::default();

    for (i, step) in steps.as_sequence().unwrap().iter().enumerate() {
        let sctx = format!("{ctx} step {i}");
        out.steps += 1;
        if let Some(s) = step.get("process_update") {
            let update = &updates[s["update"].as_str().unwrap().trim()];
            let current_slot = s["current_slot"].as_u64().unwrap();
            let applied = spec
                .process(update, current_slot)
                .unwrap_or_else(|e| panic!("{sctx}: spec store refused: {e}"));
            spec.check(&s["checks"], &sctx);

            let committee = spec.signer_for(&st, update);
            let advances = update.finalized_slot() > st.finalized.slot;
            let input = UpdateInput {
                hints: key_hints(&cfg, &committee, update).unwrap(),
                update: update.clone(),
                execution_header_rlp: match &update.finality {
                    Some((h, _)) if advances => preimages.of(h, &sctx),
                    _ => None,
                },
            };
            let result = apply_update(&cfg, &st, &input);
            assert_eq!(
                result,
                strict_model(&cfg, &st, &input),
                "{sctx}: strict store differs from the strict model"
            );
            if diverged {
                out.model_only_steps += 1;
            } else {
                track(
                    &cfg, &st, &spec, update, applied, &result, &preimages, &sctx,
                );
                match &result {
                    Ok(_) => lag_allowed = false,
                    Err(Error::AcceptRule) => {
                        lag_allowed = true;
                        out.accept_rule_refusals += 1;
                        out.notes
                            .push(format!("step {i}: accept rule refused (justified)"));
                    }
                    Err(_) => {}
                }
            }
            if let Ok(next) = result {
                out.strict_accepted += 1;
                st = next;
            }
            if !diverged {
                let c = &spec.core;
                assert_eq!(
                    (st.current_committee_root, st.next_committee_root),
                    (c.current_committee_root, c.next_committee_root),
                    "{sctx}: committee roots"
                );
                if st.finalized != c.finalized {
                    assert!(
                        lag_allowed
                            && st.finalized.slot < c.finalized.slot
                            && cfg.period_at_slot(st.finalized.slot)
                                == cfg.period_at_slot(c.finalized.slot),
                        "{sctx}: strict finalized header differs outside an accept-rule run"
                    );
                }
            }
        } else if let Some(s) = step.get("force_update") {
            let before = st.clone();
            if spec.force_update(s["current_slot"].as_u64().unwrap()) {
                out.force_update_steps.push(i);
                out.notes.push(format!(
                    "step {i}: spec force update; strict store unchanged, model checks from here"
                ));
                diverged = true;
            }
            spec.check(&s["checks"], &sctx);
            assert_eq!(st, before, "{sctx}");
        } else if let Some(s) = step.get("upgrade_store") {
            // Headers keep their own-slot variants; the upgrade leaves the core state as it is.
            spec.check(&s["checks"], &sctx);
        } else {
            panic!("{sctx}: unknown step {step:?}");
        }
    }
    out
}

/// The relations between the strict and the spec store on one tracked step.
#[allow(clippy::too_many_arguments)]
fn track(
    cfg: &ChainConfig,
    st: &Store,
    spec: &SpecStore,
    update: &LightClientUpdate,
    spec_applied: bool,
    result: &Result<Store, Error>,
    preimages: &Preimages,
    ctx: &str,
) {
    let store_period = cfg.period_at_slot(st.finalized.slot);
    let sig_next = cfg.period_at_slot(update.signature_slot) != store_period;
    let accept_rule_holds =
        !sig_next || cfg.period_at_slot(update.finalized_slot()) == store_period + 1;
    let two_thirds = popcount(update) * 3 >= cfg.sync_committee_size as u64 * 2;
    match result {
        Ok(next) => {
            assert!(
                spec_applied && update.finality.is_some() && accept_rule_holds,
                "{ctx}: strict store accepted a step the spec store skipped"
            );
            assert_eq!(next.finalized, spec.core.finalized, "{ctx}: finalized");
            assert_eq!(
                next.current_committee_root, spec.core.current_committee_root,
                "{ctx}: current committee"
            );
            assert_eq!(
                next.next_committee_root, spec.core.next_committee_root,
                "{ctx}: next committee"
            );
            let rlp = preimages.of(&spec.finalized, ctx);
            let anchor = execution_anchor(&spec.finalized, rlp.as_deref()).unwrap();
            assert_eq!(next.execution, anchor, "{ctx}: execution anchor");
        }
        Err(Error::AcceptRule) => {
            assert!(
                two_thirds && update.finality.is_some() && !accept_rule_holds,
                "{ctx}: accept-rule refusal while the accept rule holds"
            );
        }
        Err(e) => {
            assert!(
                !spec_applied,
                "{ctx}: strict store refused a step the spec store applied: {e}"
            );
        }
    }
}

/// Fork directories with sync vectors the strict store covers.
const COVERED: [(&str, ForkName); 5] = [
    ("capella", ForkName::Capella),
    ("deneb", ForkName::Deneb),
    ("electra", ForkName::Electra),
    ("fulu", ForkName::Fulu),
    ("gloas", ForkName::Gloas),
];
/// Sync cases at the pin in the covered directories: 4 single-fork tests in
/// each of the 5, plus 13 transition and legacy-data tests.
const EXPECTED_CASES: usize = 33;
/// Cases where the spec store force-updates (precomputed).
const EXPECTED_FORCE_UPDATED: [&str; 5] = [
    "Capella/light_client_sync",
    "Deneb/light_client_sync",
    "Electra/light_client_sync",
    "Fulu/light_client_sync",
    "Gloas/light_client_sync",
];

#[test]
fn sync_vectors() {
    let root = data_dir().join("tests");
    assert!(
        root.exists(),
        "spec data missing at {}: run `just spec-tests`",
        root.display()
    );
    for fork in ["altair", "bellatrix", "heze"] {
        if root
            .join("minimal")
            .join(fork)
            .join("light_client/sync")
            .exists()
        {
            println!("minimal/{fork}: skipped (fork outside Capella..Gloas)");
        }
    }
    for fork in [
        "altair",
        "bellatrix",
        "capella",
        "deneb",
        "electra",
        "fulu",
        "gloas",
        "heze",
    ] {
        assert!(
            !root
                .join("mainnet")
                .join(fork)
                .join("light_client/sync")
                .exists(),
            "mainnet/{fork}: mainnet-preset sync vectors appeared; cover them"
        );
    }
    let mut counted = 0;
    let mut zero_accepted = Vec::new();
    let mut force_updated = Vec::new();
    let (mut accepted, mut refusals, mut model_only) = (0, 0, 0);
    for (name, fork) in COVERED {
        let dir = root
            .join("minimal")
            .join(name)
            .join("light_client/sync/pyspec_tests");
        assert!(dir.exists(), "missing {}", dir.display());
        let mut cases: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        cases.sort();
        let mut steps = 0;
        for case in &cases {
            let o = run_case(fork, case);
            let id = format!("{fork:?}/{}", case.file_name().unwrap().to_string_lossy());
            for n in &o.notes {
                println!("  {id}: {n}");
            }
            counted += 1;
            steps += o.steps;
            accepted += o.strict_accepted;
            refusals += o.accept_rule_refusals;
            model_only += o.model_only_steps;
            if o.strict_accepted == 0 {
                zero_accepted.push(id.clone());
            }
            if !o.force_update_steps.is_empty() {
                force_updated.push(id);
            }
        }
        println!("minimal/{name}: {} cases, {steps} steps: ok", cases.len());
    }
    println!(
        "strict store: {counted} cases, {accepted} accepted steps, {refusals} justified accept-rule refusals, {model_only} steps checked by the model only (after a spec force update)"
    );
    assert_eq!(counted, EXPECTED_CASES, "case count at the pin");
    assert!(
        zero_accepted.is_empty(),
        "cases with zero accepted strict steps: {zero_accepted:?}"
    );
    assert_eq!(force_updated, EXPECTED_FORCE_UPDATED, "force-updated cases");
}
