//! Synthetic 32-key committees on the minimal profile: the strict store per
//! supported fork, the accept rule, refused force-update shapes, the domain
//! at a fork boundary, and input mutations.

use blst::min_pk::{AggregatePublicKey, PublicKey};
use eth_lc_core::config::{compute_domain, compute_signing_root, DOMAIN_SYNC_COMMITTEE};
use eth_lc_core::profile::FORK_COUNT;
use eth_lc_core::{
    apply_update, initialize_store, validate_light_client_update, ChainConfig, Error, ForkName,
    LightClientHeader, Store, UpdateInput,
};
use eth_lc_host::synthetic::{make_bootstrap, make_header, make_update, TestCommittee, UpdateSpec};

const GVR: [u8; 32] = [0x42; 32];

/// Minimal profile with every fork up to `fork` at genesis.
fn cfg_for(fork: ForkName) -> ChainConfig {
    let epochs: [u64; FORK_COUNT] =
        std::array::from_fn(|i| if i <= fork as usize { 0 } else { u64::MAX });
    ChainConfig::minimal(GVR, epochs)
}

const SUPPORTED: [ForkName; 5] = [
    ForkName::Capella,
    ForkName::Deneb,
    ForkName::Electra,
    ForkName::Fulu,
    ForkName::Gloas,
];

struct Setup {
    cfg: ChainConfig,
    c: [TestCommittee; 3],
    /// Store after bootstrap at slot 8 (period 0), next unknown.
    s0: Store,
}

impl Setup {
    fn new(fork: ForkName) -> Self {
        let cfg = cfg_for(fork);
        let c = [
            TestCommittee::new(1, 32),
            TestCommittee::new(2, 32),
            TestCommittee::new(3, 32),
        ];
        let s0 = initialize_store(&cfg, &make_bootstrap(&cfg, 8, &c[0].committee)).unwrap();
        Self { cfg, c, s0 }
    }

    fn update(
        &self,
        attested: u64,
        finalized: Option<u64>,
        next: Option<usize>,
        sig: u64,
        signer: usize,
        signers: usize,
    ) -> UpdateInput {
        let spec = UpdateSpec {
            attested_slot: attested,
            finalized_slot: finalized,
            next: next.map(|i| self.c[i].committee.clone()),
            signature_slot: sig,
            signers,
        };
        make_update(&self.cfg, &spec, &self.c[signer])
    }

    /// u0: same-period update that brings committee 1 and finalizes slot 16.
    fn u0(&self) -> UpdateInput {
        self.update(20, Some(16), Some(1), 21, 0, 30)
    }

    /// Store after u0: period 0, next = committee 1.
    fn s1(&self) -> Store {
        apply_update(&self.cfg, &self.s0, &self.u0()).unwrap()
    }

    /// u1: next-committee signature with a next-period finalized header (rotation).
    fn u1(&self) -> UpdateInput {
        self.update(80, Some(72), Some(2), 81, 1, 32)
    }
}

fn apply(s: &Setup, store: &Store, input: &UpdateInput) -> Result<Store, Error> {
    apply_update(&s.cfg, store, input)
}

#[test]
fn strict_store_syncs_on_every_supported_fork() {
    for fork in SUPPORTED {
        let s = Setup::new(fork);
        let s1 = s.s1();
        assert_eq!(s1.finalized.slot, 16, "{fork:?}");
        assert_eq!(
            s1.next_committee_root,
            Some(s.c[1].committee.hash_tree_root())
        );
        let s2 = apply(&s, &s1, &s.u1()).unwrap();
        assert_eq!(s2.finalized.slot, 72);
        assert_eq!(s2.current_committee_root, s.c[1].committee.hash_tree_root());
        assert_eq!(
            s2.next_committee_root,
            Some(s.c[2].committee.hash_tree_root())
        );
        assert_eq!(
            s2.execution.number,
            if fork == ForkName::Gloas { 71 } else { 72 },
            "{fork:?}"
        );
        // The spec read-only check agrees.
        let u = s.u1();
        assert_eq!(
            validate_light_client_update(&s.cfg, &s1, &u.update, &u.hints, 81),
            Ok(())
        );
        assert_eq!(
            validate_light_client_update(&s.cfg, &s1, &u.update, &u.hints, 80),
            Err(Error::SlotOrder)
        );
        println!("{fork:?}: bootstrap, fill next, rotate: ok");
    }
}

#[test]
fn accept_rule() {
    for fork in SUPPORTED {
        let s = Setup::new(fork);
        let s1 = s.s1();
        // Next-committee signature (period 1) with a current-period finalized header: refused.
        let early = s.update(66, Some(40), None, 70, 1, 32);
        assert_eq!(apply(&s, &s1, &early), Err(Error::AcceptRule), "{fork:?}");
        // The spec check alone accepts it.
        assert_eq!(
            validate_light_client_update(&s.cfg, &s1, &early.update, &early.hints, 70),
            Ok(())
        );
        // With a next-period finalized header: accepted.
        assert!(apply(&s, &s1, &s.u1()).is_ok());
        // Same-period signature with a same-period finalized header: accepted.
        let same = s.update(40, Some(32), None, 41, 0, 32);
        assert_eq!(apply(&s, &s1, &same).map(|t| t.finalized.slot), Ok(32));
    }
}

#[test]
fn force_update_shapes_are_refused() {
    for fork in SUPPORTED {
        let s = Setup::new(fork);
        let s1 = s.s1();
        // Below two thirds (21 of 32).
        let weak = s.update(40, Some(32), None, 41, 0, 21);
        assert_eq!(
            apply(&s, &s1, &weak),
            Err(Error::NoSupermajority),
            "{fork:?}"
        );
        // No finality: the spec would only move the optimistic header or, by force, finalize the attested one.
        let mut optimistic = s.update(40, None, None, 41, 0, 32);
        optimistic.execution_header_rlp = None;
        assert_eq!(apply(&s, &s1, &optimistic), Err(Error::MissingFinality));
        // No progress: finalized slot equal to the store's and next already known.
        let stale = s.update(40, Some(16), None, 41, 0, 32);
        assert_eq!(apply(&s, &s1, &stale), Err(Error::NoProgress));
    }
}

#[test]
fn domain_uses_the_slot_before_the_signature() {
    // Electra at genesis, Fulu at epoch 2 (slot 16).
    let epochs = [0, 0, 0, 0, 0, 0, 2, u64::MAX];
    let cfg = ChainConfig::minimal(GVR, epochs);
    let c = TestCommittee::new(1, 32);
    let s0 = initialize_store(&cfg, &make_bootstrap(&cfg, 8, &c.committee)).unwrap();
    // Signature slot 16 is the first Fulu slot; the domain comes from slot 15 (Electra).
    let spec = UpdateSpec {
        attested_slot: 12,
        finalized_slot: Some(9),
        next: None,
        signature_slot: 16,
        signers: 32,
    };
    let good = make_update(&cfg, &spec, &c);
    assert!(apply_update(&cfg, &s0, &good).is_ok());
    // The same update signed under the Fulu domain fails.
    let mut bad = good.clone();
    let fulu = compute_domain(DOMAIN_SYNC_COMMITTEE, cfg.forks[6].version, &GVR);
    let root = compute_signing_root(&bad.update.attested_header.beacon().hash_tree_root(), &fulu);
    bad.update.sync_aggregate.signature = c.sign(&bad.update.sync_aggregate.bits, &root);
    assert_eq!(apply_update(&cfg, &s0, &bad), Err(Error::InvalidSignature));
}

/// Committee where member 1 is the negation of member 0.
fn cancelling_committee() -> TestCommittee {
    let mut t = TestCommittee::new(9, 32);
    let k = PublicKey::uncompress(&t.committee.pubkeys[0]).unwrap();
    let mut neg = AggregatePublicKey::from_public_key(&k);
    neg.sub_aggregate(&AggregatePublicKey::from_public_key(&k));
    neg.sub_aggregate(&AggregatePublicKey::from_public_key(&k));
    t.committee.pubkeys[1] = neg.to_public_key().compress();
    let pks: Vec<PublicKey> = t
        .committee
        .pubkeys
        .iter()
        .map(|p| PublicKey::uncompress(p).unwrap())
        .collect();
    let refs: Vec<&PublicKey> = pks.iter().collect();
    t.committee.aggregate_pubkey = AggregatePublicKey::aggregate(&refs, false)
        .unwrap()
        .to_public_key()
        .compress();
    t
}

#[test]
fn identity_participant_key_is_refused() {
    let cfg = cfg_for(ForkName::Fulu);
    let t = cancelling_committee();
    let s0 = initialize_store(&cfg, &make_bootstrap(&cfg, 8, &t.committee)).unwrap();
    // Members 0 and 1 sign; their keys sum to the identity.
    let spec = UpdateSpec {
        attested_slot: 20,
        finalized_slot: Some(16),
        next: None,
        signature_slot: 21,
        signers: 2,
    };
    let input = make_update(&cfg, &spec, &t);
    assert_eq!(apply_update(&cfg, &s0, &input), Err(Error::IdentityKey));
}

#[test]
fn mutations_fail() {
    for fork in SUPPORTED {
        let s = Setup::new(fork);
        let base = s.u0();
        assert!(apply(&s, &s.s0, &base).is_ok());
        let s1 = s.s1();
        let mut cases: Vec<(&str, UpdateInput, Store, Error)> = Vec::new();
        let mut m =
            |name: &'static str, f: &dyn Fn(&mut UpdateInput), store: &Store, want: Error| {
                let mut i = base.clone();
                f(&mut i);
                cases.push((name, i, store.clone(), want));
            };
        let s0 = s.s0.clone();
        m(
            "signature byte",
            &|i| i.update.sync_aggregate.signature[5] ^= 1,
            &s0,
            Error::InvalidSignature,
        );
        m(
            "zero bit set, hint kept",
            &|i| i.update.sync_aggregate.bits[3] |= 0x80,
            &s0,
            Error::HintMismatch,
        );
        m(
            "one bit cleared, no hint",
            &|i| i.update.sync_aggregate.bits[0] &= !1,
            &s0,
            Error::HintMismatch,
        );
        m(
            "duplicate hint",
            &|i| i.hints.non_signers.push(i.hints.non_signers[1].clone()),
            &s0,
            Error::HintMismatch,
        );
        m(
            "omitted hint",
            &|i| {
                i.hints.non_signers.pop();
            },
            &s0,
            Error::HintMismatch,
        );
        m(
            "unsorted hints",
            &|i| i.hints.non_signers.swap(0, 1),
            &s0,
            Error::HintMismatch,
        );
        m(
            "hint for another key",
            &|i| i.hints.non_signers[0].1 = i.hints.non_signers[1].1,
            &s0,
            Error::InvalidKey,
        );
        m(
            "off-curve hint",
            &|i| i.hints.non_signers[0].1[90] ^= 1,
            &s0,
            Error::InvalidKey,
        );
        m(
            "aggregate hint",
            &|i| i.hints.aggregate = i.hints.non_signers[0].1,
            &s0,
            Error::CommitteeMismatch,
        );
        m(
            "bits length",
            &|i| i.update.sync_aggregate.bits.push(0),
            &s0,
            Error::BitsLength,
        );
        m(
            "wrong committee",
            &|i| i.hints.pubkeys_root[0] ^= 1,
            &s0,
            Error::CommitteeMismatch,
        );
        m(
            "finality branch node",
            &|i| i.update.finality.as_mut().unwrap().1[2][0] ^= 1,
            &s0,
            Error::InvalidFinalityBranch,
        );
        m(
            "next-committee branch node",
            &|i| i.update.next_sync_committee.as_mut().unwrap().1[1][0] ^= 1,
            &s0,
            Error::InvalidNextCommitteeBranch,
        );
        m(
            "nonzero normalization prefix",
            &|i| i.update.finality.as_mut().unwrap().1.insert(0, [1; 32]),
            &s0,
            Error::InvalidFinalityBranch,
        );
        m(
            "signature slot at attested slot",
            &|i| i.update.signature_slot = 20,
            &s0,
            Error::SlotOrder,
        );
        m(
            "finalized after attested",
            &|i| {
                let (h, _) = i.update.finality.as_mut().unwrap();
                let (LightClientHeader::Capella { beacon, .. }
                | LightClientHeader::Deneb { beacon, .. }
                | LightClientHeader::Gloas { beacon, .. }) = h;
                beacon.slot = 21;
            },
            &s0,
            Error::SlotOrder,
        );
        m(
            "signature period store+1, next unknown",
            &|i| i.update.signature_slot = 64,
            &s0,
            Error::SignaturePeriod,
        );
        m(
            "next committee root",
            &|i| i.update.next_sync_committee.as_mut().unwrap().0[0] ^= 1,
            &s0,
            Error::InvalidNextCommitteeBranch,
        );
        m(
            "non-signer branch node",
            &|i| i.hints.non_signers[0].2[3][0] ^= 1,
            &s0,
            Error::InvalidKey,
        );
        m(
            "signature hint",
            &|i| i.hints.signature[191] ^= 1,
            &s0,
            Error::InvalidSignature,
        );
        drop(m);
        // Same-period update carrying another next committee than the stored one.
        let other_next = s.update(40, Some(32), Some(2), 41, 0, 30);
        cases.push((
            "same-period different next committee",
            other_next,
            s1.clone(),
            Error::NextCommitteeMismatch,
        ));
        // Header variant mismatched to its slot fork: a header built under another fork's layout.
        let other_fork = if fork == ForkName::Capella {
            ForkName::Deneb
        } else {
            ForkName::Capella
        };
        let (alien, _) = make_header(
            &cfg_for(other_fork),
            20,
            base.update.attested_header.beacon().state_root,
        );
        let mut variant = base.clone();
        variant.update.attested_header = alien;
        cases.push(("header variant", variant, s0.clone(), Error::HeaderVariant));
        // Off-preset config.
        let mut off = s.cfg.clone();
        off.seconds_per_slot += 1;
        assert_eq!(
            apply_update(&off, &s0, &base),
            Err(Error::PresetMismatch),
            "{fork:?}"
        );
        if fork == ForkName::Gloas {
            let mut wrong = base.clone();
            wrong.execution_header_rlp.as_mut().unwrap()[20] ^= 1;
            cases.push((
                "wrong execution preimage",
                wrong,
                s0.clone(),
                Error::ExecutionHashMismatch,
            ));
            let mut missing = base.clone();
            missing.execution_header_rlp = None;
            cases.push((
                "missing execution preimage",
                missing,
                s0.clone(),
                Error::MissingExecutionPreimage,
            ));
        } else {
            let mut extra = base.clone();
            extra.execution_header_rlp = Some(vec![0xc0]);
            cases.push((
                "unexpected execution preimage",
                extra,
                s0.clone(),
                Error::UnexpectedExecutionPreimage,
            ));
        }
        for (name, input, store, want) in &cases {
            assert_eq!(apply(&s, store, input), Err(*want), "{fork:?}: {name}");
        }
        println!("{fork:?}: {} mutations refused", cases.len());
    }
}

#[test]
fn bootstrap_mutations_fail() {
    for fork in SUPPORTED {
        let cfg = cfg_for(fork);
        let c = TestCommittee::new(1, 32);
        let good = make_bootstrap(&cfg, 8, &c.committee);
        assert!(initialize_store(&cfg, &good).is_ok());
        let mut wrong_root = good.clone();
        wrong_root.trusted_block_root[0] ^= 1;
        assert_eq!(
            initialize_store(&cfg, &wrong_root),
            Err(Error::TrustedRootMismatch)
        );
        let mut bad_branch = good.clone();
        bad_branch.bootstrap.current_sync_committee_branch[1][0] ^= 1;
        assert_eq!(
            initialize_store(&cfg, &bad_branch),
            Err(Error::InvalidCurrentCommitteeBranch)
        );
        let mut off = cfg.clone();
        off.slots_per_epoch = 32;
        assert_eq!(initialize_store(&off, &good), Err(Error::PresetMismatch));
        let mut zero = cfg.clone();
        zero.chain_id = 0;
        assert_eq!(
            initialize_store(&zero, &good),
            Err(Error::InvalidChainIdentity)
        );
    }
}
