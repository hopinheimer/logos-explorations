//! Recorded Sepolia chain across the Gloas fork (epoch 353,024, the first
//! slot of period 1379): a Fulu bootstrap in period 1376, period updates
//! 1376 to 1380 (Fulu layout through 1378, Gloas layout from 1379), and the
//! RLP execution header of every finalized header.
//!
//! The same program and the same code path as mainnet: only the `Init`
//! config differs. Every update runs through `apply_update` with real BLS.
//!
//! Gloas-layout headers at pre-Gloas slots: each recorded Fulu object is
//! upgraded with `upgrade_lc_*_to_gloas` (`specs/gloas/light-client/fork.md`)
//! and replayed. That replay must give the same stores, anchors included,
//! as the replay of the objects as served.

use eth_lc_core::{
    apply_update, get_lc_execution_root, initialize_store, BootstrapInput, ChainConfig, Error,
    ForkName, LightClientHeader, LightClientUpdate, Store,
};
use eth_lc_host::chain_dir::{execution_block_hash, Manifest};
use eth_lc_host::forks::{self, Preset, RawUpdate, Wire};
use eth_lc_host::ChainDir;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/sepolia");

fn chain() -> ChainDir {
    ChainDir::load(DIR).unwrap()
}

fn manifest() -> Manifest {
    serde_json::from_slice(&std::fs::read(format!("{DIR}/chain.json")).unwrap()).unwrap()
}

/// The recorded period updates as decoded raw objects, in replay order.
fn raw_updates() -> Vec<RawUpdate> {
    manifest()
        .updates
        .iter()
        .map(|e| {
            let bytes = std::fs::read(format!("{DIR}/{}", e.file)).unwrap();
            let fork = forks::parse_fork(&e.fork).unwrap();
            forks::decode_update(fork, Preset::Mainnet, Wire::Ssz(&bytes)).unwrap()
        })
        .collect()
}

/// Replays `updates` from `bootstrap`; returns the store after each step.
fn replay(dir: &ChainDir, bootstrap: &BootstrapInput, updates: &[LightClientUpdate]) -> Vec<Store> {
    let mut store = initialize_store(&dir.cfg, bootstrap).unwrap();
    let mut out = vec![store.clone()];
    for (i, u) in updates.iter().enumerate() {
        let input = dir.update_input(&store, u).unwrap();
        store = apply_update(&dir.cfg, &store, &input).unwrap_or_else(|e| panic!("step {i}: {e}"));
        out.push(store.clone());
    }
    out
}

#[test]
fn sepolia_config_passes_the_same_code_path() {
    let dir = chain();
    assert_eq!(dir.cfg, ChainConfig::sepolia());
    assert_eq!(eth_lc_core::check_profile(&dir.cfg), Ok(()));
    assert_eq!(dir.cfg.fork_at_epoch(353_023), ForkName::Fulu);
    assert_eq!(dir.cfg.fork_at_epoch(353_024), ForkName::Gloas);
    assert_eq!(dir.cfg.period_at_slot(353_024 * 32), 1379);
}

#[test]
fn replay_crosses_the_gloas_fork() {
    let dir = chain();
    let cfg = &dir.cfg;
    let updates: Vec<LightClientUpdate> = dir.all_updates().cloned().collect();
    let stores = replay(&dir, &dir.bootstrap, &updates);
    for (i, s) in stores.iter().enumerate() {
        println!(
            "store {i}: slot {} period {} fork {:?} next_known={} execution_block={}",
            s.finalized.slot,
            cfg.period_at_slot(s.finalized.slot),
            cfg.fork_at_slot(s.finalized.slot),
            s.next_committee_root.is_some(),
            s.execution.number
        );
    }
    // Fulu through period 1378, Gloas from 1379.
    let forks_seen: Vec<ForkName> = stores
        .iter()
        .map(|s| cfg.fork_at_slot(s.finalized.slot))
        .collect();
    assert_eq!(forks_seen[..4], [ForkName::Fulu; 4]);
    assert!(forks_seen[4..].iter().all(|f| *f == ForkName::Gloas));
    // The period-1379 update is signed under the Gloas fork version.
    let u1379 = &updates[3];
    assert_eq!(
        cfg.fork_at_slot(u1379.signature_slot - 1),
        ForkName::Gloas,
        "signature domain"
    );
    // Each Gloas anchor is the RLP header of `execution_block_hash`.
    for (s, u) in stores[1..].iter().zip(&updates) {
        let (h, _) = u.finality.as_ref().unwrap();
        if s.finalized == *h.beacon() {
            assert_eq!(s.execution.block_hash, execution_block_hash(h));
        }
    }
    // Execution numbers grow with each new finalized header across the fork.
    assert!(stores.windows(2).all(
        |w| (w[0].finalized == w[1].finalized) || w[0].execution.number < w[1].execution.number
    ));
}

#[test]
fn gloas_layout_at_fulu_slots_replays_to_the_same_stores() {
    let dir = chain();
    let cfg = &dir.cfg;
    let raw = raw_updates();
    let served: Vec<LightClientUpdate> = dir.all_updates().cloned().collect();
    let upgraded: Vec<LightClientUpdate> = raw
        .iter()
        .map(|u| {
            forks::to_core_update(cfg, &forks::upgrade_update_to_gloas(cfg, u).unwrap()).unwrap()
        })
        .collect();

    // Every upgraded header is a Gloas variant; the Fulu-slot ones are the mixed case.
    let mut mixed = 0;
    for (s, u) in served.iter().zip(&upgraded) {
        for (a, b) in [
            (&s.attested_header, &u.attested_header),
            (
                &s.finality.as_ref().unwrap().0,
                &u.finality.as_ref().unwrap().0,
            ),
        ] {
            assert!(matches!(b, LightClientHeader::Gloas { .. }));
            assert!(eth_lc_core::is_valid_light_client_header(cfg, b));
            assert_eq!(a.beacon(), b.beacon());
            assert_eq!(execution_block_hash(a), execution_block_hash(b));
            assert_eq!(get_lc_execution_root(cfg, a), get_lc_execution_root(cfg, b));
            if cfg.fork_at_slot(b.beacon().slot) != ForkName::Gloas {
                mixed += 1;
            }
        }
    }
    println!("{mixed} Gloas-layout headers at Fulu slots");
    assert_eq!(mixed, 6);

    // The upgraded bootstrap anchors through the RLP header of the payload block.
    let bytes = std::fs::read(format!("{DIR}/bootstrap.ssz")).unwrap();
    let raw_boot =
        forks::decode_bootstrap(ForkName::Fulu, Preset::Mainnet, Wire::Ssz(&bytes)).unwrap();
    let boot = forks::to_core_bootstrap(
        cfg,
        &forks::upgrade_bootstrap_to_gloas(cfg, &raw_boot).unwrap(),
    )
    .unwrap();
    let hash = execution_block_hash(&boot.header);
    let gloas_boot = BootstrapInput {
        trusted_block_root: dir.bootstrap.trusted_block_root,
        bootstrap: boot,
        execution_header_rlp: Some(dir.execution_headers[&hash].clone()),
    };
    let a = replay(&dir, &dir.bootstrap, &served);
    let b = replay(&dir, &gloas_boot, &upgraded);
    assert_eq!(a, b, "the upgraded replay must give the same stores");

    // The upgraded Fulu-slot header anchors only through its preimage.
    let mut missing = gloas_boot.clone();
    missing.execution_header_rlp = None;
    assert_eq!(
        initialize_store(cfg, &missing),
        Err(Error::MissingExecutionPreimage)
    );
}

#[test]
fn gloas_layout_at_a_fulu_slot_needs_its_own_gindex() {
    let dir = chain();
    let cfg = &dir.cfg;
    let raw = raw_updates();
    let up =
        forks::to_core_update(cfg, &forks::upgrade_update_to_gloas(cfg, &raw[0]).unwrap()).unwrap();
    let h = up.attested_header;
    assert!(eth_lc_core::is_valid_light_client_header(cfg, &h));
    let LightClientHeader::Gloas {
        beacon,
        execution_block_hash,
        execution_branch,
    } = h
    else {
        unreachable!()
    };
    // An altered branch node fails.
    let mut bad = execution_branch.clone();
    bad[8][0] ^= 1;
    let altered = LightClientHeader::Gloas {
        beacon: beacon.clone(),
        execution_block_hash,
        execution_branch: bad,
    };
    assert!(!eth_lc_core::is_valid_light_client_header(cfg, &altered));
    // The same header placed at a Gloas slot uses gindex 2856 and fails.
    let mut moved = beacon.clone();
    moved.slot = 353_024 * 32;
    let at_gloas = LightClientHeader::Gloas {
        beacon: moved,
        execution_block_hash,
        execution_branch,
    };
    assert!(!eth_lc_core::is_valid_light_client_header(cfg, &at_gloas));
}
