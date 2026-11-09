//! consensus-specs `v1.7.0-beta.4` light-client `sync` vectors.
//!
//! Spec store: a test-only `LightClientStore` (best valid update, safety
//! threshold, optimistic header, force update, store upgrade) on top of
//! `validate_light_client_update` (with the vector `current_slot`) and the
//! `spec-oracle` transition. Every step must succeed and match the checks.
//!
//! Strict store (minimal preset): `apply_update` on the same steps. It must
//! accept every 2/3-arm step the accept rule allows and then equal the spec
//! store; it must stay unchanged on force updates and on accept-rule refusals.
//!
//! Data: `SPEC_DATA` (default `../spec-data`), filled by `just spec-tests`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use eth_lc_core::execution::execution_anchor;
use eth_lc_core::oracle;
use eth_lc_core::profile::{self, minimal, FORK_COUNT};
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

/// Config of a case: the pinned profile of its preset with the case's genesis root and fork epochs.
fn case_config(preset: Preset, case: &Path, gvr: Root) -> ChainConfig {
    let cfg_yaml = yaml(&case.join("config.yaml"));
    let mut epochs = [0u64; FORK_COUNT];
    for (i, k) in EPOCH_KEYS.iter().enumerate() {
        epochs[i + 1] = cfg_yaml.get(*k).and_then(Value::as_u64).unwrap_or(u64::MAX);
    }
    match preset {
        Preset::Minimal => minimal(gvr, epochs),
        Preset::Mainnet => {
            let mut c = profile::mainnet();
            c.genesis_validators_root = gvr;
            c.forks
                .iter_mut()
                .zip(epochs)
                .for_each(|(f, e)| f.epoch = e);
            c
        }
    }
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

/// Decodes an update in the layout of its attested slot's fork.
fn decode_update(cfg: &ChainConfig, preset: Preset, bytes: &[u8]) -> LightClientUpdate {
    for layout in LAYOUTS {
        if let Ok(raw) = forks::decode_update(layout, preset, Wire::Ssz(bytes)) {
            if layout_of(cfg.fork_at_slot(raw.attested_header.beacon().slot)) == layout {
                return forks::to_core_update(cfg, &raw).unwrap();
            }
        }
    }
    panic!("no layout decodes this update")
}

fn decode_bootstrap(
    cfg: &ChainConfig,
    preset: Preset,
    bytes: &[u8],
) -> eth_lc_core::LightClientBootstrap {
    for layout in LAYOUTS {
        if let Ok(raw) = forks::decode_bootstrap(layout, preset, Wire::Ssz(bytes)) {
            if layout_of(cfg.fork_at_slot(raw.header.beacon().slot)) == layout {
                return forks::to_core_bootstrap(cfg, &raw).unwrap();
            }
        }
    }
    panic!("no layout decodes this bootstrap")
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

    fn signer(&self, update: &LightClientUpdate) -> SyncCommittee {
        let root = if self.period(update.signature_slot) == self.period(self.core.finalized.slot) {
            Some(self.core.current_committee_root)
        } else {
            self.core.next_committee_root
        };
        root.and_then(|r| self.committees.get(&r).cloned())
            .unwrap_or_else(|| SyncCommittee {
                pubkeys: vec![[0; 48]; self.cfg.sync_committee_size as usize],
                aggregate_pubkey: [0; 48],
            })
    }

    /// `process_light_client_update`. Returns whether the 2/3 arm applied.
    fn process(&mut self, update: &LightClientUpdate, current_slot: u64) -> Result<bool, Error> {
        if let Some((c, _)) = &update.next_sync_committee {
            self.committees.insert(c.hash_tree_root(), c.clone());
        }
        let committee = self.signer(update);
        let hints =
            key_hints(&committee, &update.sync_aggregate.bits).map_err(|_| Error::InvalidKey)?;
        validate_light_client_update(
            &self.cfg,
            &self.core,
            update,
            &committee,
            &hints,
            current_slot,
        )?;
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
                    get_lc_execution_root(h),
                    "{ctx}: {name}.execution_root"
                );
            }
        }
    }
}

/// Outcome of one case.
#[derive(Default)]
struct Outcome {
    steps: usize,
    strict_ran: bool,
    strict_accepted: usize,
    notes: Vec<String>,
}

fn run_case(preset: Preset, case: &Path) -> Outcome {
    let ctx = case
        .components()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    let meta = yaml(&case.join("meta.yaml"));
    let gvr = parse_root(meta["genesis_validators_root"].as_str().unwrap()).unwrap();
    let cfg = case_config(preset, case, gvr);
    let trusted = parse_root(meta["trusted_block_root"].as_str().unwrap()).unwrap();
    let bootstrap = decode_bootstrap(&cfg, preset, &snappy(&case.join("bootstrap.ssz_snappy")));

    // The store fork: an LC layout fork at or after the bootstrap layout.
    let store_version = hex::decode(
        meta["store_fork_version"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let boot_layout = layout_of(cfg.fork_at_slot(bootstrap.header.beacon().slot));
    let ok = LAYOUTS
        .iter()
        .filter(|l| **l >= boot_layout)
        .any(|l| cfg.forks[*l as usize].version[..] == store_version[..]);
    assert!(ok, "{ctx}: store_fork_version {store_version:?} is not an LC layout at or after {boot_layout:?}");

    let input = BootstrapInput {
        trusted_block_root: trusted,
        bootstrap: bootstrap.clone(),
        execution_header_rlp: None,
    };
    // Spec store: `initialize_light_client_store`. The spec store tracks headers only; Gloas bootstraps skip the anchor.
    let core = match initialize_store(&cfg, &input) {
        Ok(s) => s,
        Err(Error::MissingExecutionPreimage) | Err(Error::ProfileMismatch) => Store {
            finalized: bootstrap.header.beacon().clone(),
            execution: Default::default(),
            current_committee_root: bootstrap.current_sync_committee.hash_tree_root(),
            next_committee_root: None,
        },
        Err(e) => panic!("{ctx}: bootstrap: {e}"),
    };
    assert!(
        eth_lc_core::is_valid_light_client_header(&cfg, &bootstrap.header),
        "{ctx}"
    );
    let mut spec = SpecStore {
        cfg: cfg.clone(),
        core,
        finalized: bootstrap.header.clone(),
        optimistic: bootstrap.header.clone(),
        best_valid_update: None,
        previous_max_active_participants: 0,
        current_max_active_participants: 0,
        committees: [(
            bootstrap.current_sync_committee.hash_tree_root(),
            bootstrap.current_sync_committee.clone(),
        )]
        .into(),
    };

    // Strict store: minimal preset only (mainnet-preset cases are off-profile).
    let mut strict = match (preset, initialize_store(&cfg, &input)) {
        (Preset::Minimal, Ok(s)) => Some(s),
        (Preset::Minimal, Err(Error::MissingExecutionPreimage)) => None,
        (Preset::Minimal, Err(e)) => panic!("{ctx}: strict bootstrap: {e}"),
        (Preset::Mainnet, _) => None,
    };
    let mut out = Outcome {
        strict_ran: strict.is_some(),
        ..Default::default()
    };
    if strict.is_none() {
        out.notes.push(match preset {
            Preset::Mainnet => "strict store skipped: mainnet-preset config is off-profile".into(),
            Preset::Minimal => {
                "strict store skipped: Gloas bootstrap without an execution preimage".into()
            }
        });
    }

    let steps = yaml(&case.join("steps.yaml"));
    for (i, step) in steps.as_sequence().unwrap().iter().enumerate() {
        let sctx = format!("{ctx} step {i}");
        out.steps += 1;
        if let Some(s) = step.get("process_update") {
            let name = s["update"].as_str().unwrap().trim();
            let update = decode_update(
                &cfg,
                preset,
                &snappy(&case.join(format!("{name}.ssz_snappy"))),
            );
            let current_slot = s["current_slot"].as_u64().unwrap();
            let applied = spec
                .process(&update, current_slot)
                .unwrap_or_else(|e| panic!("{sctx}: spec store refused: {e}"));
            spec.check(&s["checks"], &sctx);
            if let Some(st) = strict.as_mut() {
                strict_step(&cfg, st, &spec, &update, applied, (&sctx, i), &mut out);
                let same = st.finalized == spec.core.finalized
                    && st.current_committee_root == spec.core.current_committee_root
                    && st.next_committee_root == spec.core.next_committee_root;
                if !same {
                    out.notes.push(format!(
                        "step {i}: strict store diverged from the spec store; strict checks stop"
                    ));
                    strict = None;
                }
            }
        } else if let Some(s) = step.get("force_update") {
            let forced = spec.force_update(s["current_slot"].as_u64().unwrap());
            spec.check(&s["checks"], &sctx);
            if forced {
                out.notes.push(format!(
                    "step {i}: spec force update applied; strict store unchanged"
                ));
                if strict.is_some() {
                    out.notes.push(format!(
                        "step {i}: strict store diverged from the spec store; strict checks stop"
                    ));
                }
                strict = None;
            }
        } else if let Some(s) = step.get("upgrade_store") {
            // Headers keep their own-slot variants; the upgrade leaves the core state as it is.
            spec.check(&s["checks"], &sctx);
        } else {
            panic!("{sctx}: unknown step {step:?}");
        }
    }
    out
}

fn strict_step(
    cfg: &ChainConfig,
    st: &mut Store,
    spec: &SpecStore,
    update: &LightClientUpdate,
    spec_applied: bool,
    (ctx, step): (&str, usize),
    out: &mut Outcome,
) {
    let committee = spec.signer_for(st, update);
    let input = UpdateInput {
        hints: key_hints(&committee, &update.sync_aggregate.bits).unwrap(),
        committee,
        update: update.clone(),
        execution_header_rlp: None,
    };
    let result = apply_update(cfg, st, &input);
    let sig_next =
        cfg.period_at_slot(update.signature_slot) != cfg.period_at_slot(st.finalized.slot);
    let accept_rule_holds = !sig_next
        || cfg.period_at_slot(update.finalized_slot()) == cfg.period_at_slot(st.finalized.slot) + 1;
    let two_thirds_finality = spec_applied && update.finality.is_some();
    match result {
        Ok(next) => {
            assert!(
                two_thirds_finality && accept_rule_holds,
                "{ctx}: strict store accepted a step the spec store did not apply"
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
            if next.finalized != st.finalized {
                let anchor = execution_anchor(&spec.finalized, None).unwrap();
                assert_eq!(next.execution, anchor, "{ctx}: execution anchor");
            }
            out.strict_accepted += 1;
            *st = next;
        }
        Err(Error::AcceptRule) => {
            assert!(two_thirds_finality, "{ctx}");
            out.notes.push(format!(
                "step {step}: accept rule refused; strict store unchanged"
            ));
        }
        Err(Error::MissingExecutionPreimage) => {
            assert!(two_thirds_finality, "{ctx}");
            out.notes.push(format!("step {step}: Gloas finalized header without an execution preimage; strict store unchanged"));
        }
        Err(e) => {
            assert!(
                !two_thirds_finality,
                "{ctx}: strict store refused a 2/3 finality step: {e}"
            );
        }
    }
}

impl SpecStore {
    /// The signing committee for `update` relative to the strict store `st`.
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
}

#[test]
fn sync_vectors() {
    let root = data_dir().join("tests");
    if !root.exists() {
        panic!(
            "spec data missing at {}: run `just spec-tests`",
            root.display()
        );
    }
    let mut zero_accepted = Vec::new();
    let mut skipped = Vec::new();
    let mut counted = 0;
    for (preset, pname) in [(Preset::Minimal, "minimal"), (Preset::Mainnet, "mainnet")] {
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
            let dir = root
                .join(pname)
                .join(fork)
                .join("light_client/sync/pyspec_tests");
            if !dir.exists() {
                continue;
            }
            if matches!(fork, "altair" | "bellatrix" | "heze") {
                println!("{pname}/{fork}: skipped (fork outside Capella..Gloas)");
                continue;
            }
            let mut cases: Vec<PathBuf> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            cases.sort();
            let mut steps = 0;
            for case in &cases {
                let o = run_case(preset, case);
                steps += o.steps;
                let name = format!(
                    "{pname}/{fork}/{}",
                    case.file_name().unwrap().to_string_lossy()
                );
                for n in &o.notes {
                    println!("  {name}: {n}");
                }
                if preset == Preset::Minimal {
                    if !o.strict_ran {
                        skipped.push(name);
                    } else {
                        counted += 1;
                        if o.strict_accepted == 0 {
                            zero_accepted.push(name);
                        }
                    }
                }
            }
            println!("{pname}/{fork}: {} cases, {steps} steps: ok", cases.len());
        }
    }
    println!(
        "strict store: {counted} minimal cases counted, {} with zero accepted steps:",
        zero_accepted.len()
    );
    for z in &zero_accepted {
        println!("  {z}");
    }
    println!(
        "strict store skipped (a Gloas bootstrap needs an execution preimage, absent from the vectors): {}",
        skipped.len()
    );
    for z in &skipped {
        println!("  {z}");
    }
    assert_eq!(
        zero_accepted.len(),
        EXPECTED_ZERO_ACCEPTED,
        "counted cases with zero accepted strict steps"
    );
    assert_eq!(
        skipped.len(),
        EXPECTED_STRICT_SKIPPED,
        "minimal cases without a strict store"
    );
}

/// Counted minimal cases whose strict store accepts zero steps (precomputed).
const EXPECTED_ZERO_ACCEPTED: usize = 0;
/// Minimal cases that skip the strict store: the four `minimal/gloas` cases.
const EXPECTED_STRICT_SKIPPED: usize = 4;
