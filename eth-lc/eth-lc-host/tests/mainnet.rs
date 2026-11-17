//! Recorded Fulu mainnet chain: bootstrap, four period updates, a finality update.

use eth_lc_core::{apply_update, initialize_store, Store};
use eth_lc_host::ChainDir;

fn chain() -> ChainDir {
    ChainDir::load(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/mainnet")).unwrap()
}

/// Applies every recorded update in order; returns the stores before each step and the last store.
fn replay(dir: &ChainDir) -> (Vec<Store>, Store) {
    let mut store = initialize_store(&dir.cfg, &dir.bootstrap).unwrap();
    let mut before = Vec::new();
    for u in dir.all_updates() {
        before.push(store.clone());
        store = apply_update(&dir.cfg, &store, &dir.update_input(&store, u).unwrap()).unwrap();
    }
    (before, store)
}

#[test]
fn recorded_chain_syncs_through_four_periods_and_a_finality_update() {
    let dir = chain();
    let (before, last) = replay(&dir);
    let cfg = &dir.cfg;
    for (i, s) in before.iter().enumerate() {
        println!(
            "step {i}: store slot {} period {} next_known={} execution_block={}",
            s.finalized.slot,
            cfg.period_at_slot(s.finalized.slot),
            s.next_committee_root.is_some(),
            s.execution.number
        );
    }
    // Step 0 fills the next committee; step 1 rotates it into current.
    assert!(before[0].next_committee_root.is_none());
    assert_eq!(
        before[2].current_committee_root,
        before[1].next_committee_root.unwrap()
    );
    assert!(last.finalized.slot > before[4].finalized.slot);
    assert_eq!(
        cfg.period_at_slot(last.finalized.slot),
        cfg.period_at_slot(before[0].finalized.slot) + 4
    );
}

// ---------------------------------------------------------------------------
// The instance accounts (proposal section 4), written through `init` and `advance`.

use eth_lc_core::instance::{self, AccountId, Event, FinalisedHeader, InstanceConfig};

/// A stand-in for the LEZ PDA: the seed itself.
fn pda(seed: &[u8; 32]) -> AccountId {
    *seed
}

/// Replays the chain-dir through `init` and `advance`; returns the instance
/// config, every written header, and every event.
fn replay_instance(dir: &ChainDir) -> (InstanceConfig, Vec<FinalisedHeader>, Vec<Event>) {
    let config = dir.cfg.instance_config(dir.bootstrap.trusted_block_root);
    let first = instance::init(&config, &dir.bootstrap, pda).unwrap();
    let (mut state, mut header) = (first.state, first.header.clone());
    let mut headers = vec![first.header];
    let mut events = Vec::new();
    let mut handed_off = None;
    let (before, _) = replay(dir);
    for (u, store) in dir.all_updates().zip(&before) {
        let input = dir.update_input(store, u).unwrap();
        match instance::advance(&config, &state, &header, handed_off.as_ref(), &input, pda) {
            Ok(out) => {
                assert_eq!(out.state.parent, state.block_number);
                events.extend(out.events);
                state = out.state;
                header = out.header;
                headers.push(header.clone());
                handed_off = None;
            }
            // Step 0 installs the first next committee at the checkpoint's block.
            Err(Error::NoProgress) => {
                let (committee, event) =
                    instance::hand_off(&config, &state, &header, &input, pda).unwrap();
                events.push(event);
                handed_off = Some(committee);
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    (config, headers, events)
}

#[test]
fn instance_accounts_follow_the_recorded_chain() {
    let dir = chain();
    let (config, headers, events) = replay_instance(&dir);
    let (_, last) = replay(&dir);
    let tip = headers.last().unwrap();
    assert_eq!(tip.block_number, last.execution.number);
    assert_eq!(tip.beacon_root, last.finalized.hash_tree_root());
    assert_eq!(headers[0].signers, 0);
    assert!(headers[1..].iter().all(|h| h.signers >= 342));
    let handoffs: Vec<u64> = events
        .iter()
        .filter_map(|e| match e {
            Event::CommitteeHandoff { period, .. } => Some(*period),
            _ => None,
        })
        .collect();
    let first = dir.cfg.period_at_slot(headers[0].slot);
    assert_eq!(handoffs, (first + 1..=first + 4).collect::<Vec<_>>());
    let finalised = events
        .iter()
        .filter(|e| matches!(e, Event::HeaderFinalised { .. }))
        .count();
    assert_eq!(finalised, headers.len() - 1);
    assert_eq!(headers.len(), 5);
    // The update window is the WS period past the state's header.
    assert_eq!(
        instance::update_deadline_ms(&config, tip),
        dir.cfg.slot_start_ms(tip.slot) + 98_304_000
    );
}

#[test]
fn instance_refuses_a_foreign_checkpoint_or_state() {
    let dir = chain();
    let mut config = dir.cfg.instance_config(dir.bootstrap.trusted_block_root);
    config.checkpoint[0] ^= 1;
    assert_eq!(
        instance::init(&config, &dir.bootstrap, pda).err(),
        Some(Error::CheckpointRootMismatch)
    );
    config.checkpoint[0] ^= 1;
    let first = instance::init(&config, &dir.bootstrap, pda).unwrap();
    let store = initialize_store(&dir.cfg, &dir.bootstrap).unwrap();
    let input = dir.update_input(&store, &dir.updates[0]).unwrap();
    let mut other = config.clone();
    other.finality.min_participants = 400;
    assert_eq!(
        instance::advance(&other, &first.state, &first.header, None, &input, pda).err(),
        Some(Error::AccountMismatch)
    );
    let mut header = first.header.clone();
    header.block_number += 1;
    assert_eq!(
        instance::advance(&config, &first.state, &header, None, &input, pda).err(),
        Some(Error::AccountMismatch)
    );
    // Step 0 reaches no new block: `advance` refuses it, `hand_off` writes the committee.
    assert_eq!(
        instance::advance(&config, &first.state, &first.header, None, &input, pda).err(),
        Some(Error::NoProgress)
    );
    let (committee, _) =
        instance::hand_off(&config, &first.state, &first.header, &input, pda).unwrap();
    assert_eq!(committee.period, first.state.period + 1);
    let mut wrong = committee.clone();
    wrong.period += 1;
    let next = initialize_store(&dir.cfg, &dir.bootstrap)
        .and_then(|s| apply_update(&dir.cfg, &s, &input))
        .unwrap();
    let step1 = dir.update_input(&next, &dir.updates[1]).unwrap();
    assert_eq!(
        instance::advance(
            &config,
            &first.state,
            &first.header,
            Some(&wrong),
            &step1,
            pda
        )
        .err(),
        Some(Error::AccountMismatch)
    );
    assert!(instance::advance(
        &config,
        &first.state,
        &first.header,
        Some(&committee),
        &step1,
        pda
    )
    .is_ok());
}

// ---------------------------------------------------------------------------
// Claims against the header of a light-client-verified block.

use eth_lc_core::claim::{check_claim, Claim, Class, Condition, Fact, Op, Proof, Subject};
use eth_lc_core::crypto::keccak256;
use eth_lc_core::Error;
use eth_lc_host::evidence::{account_from_get_proof, hex_bytes, storage_from_proof_value};
use eth_lc_host::forks::{self, Preset, Wire};
use serde_json::Value;

fn evidence_json(name: &str) -> Value {
    let path = format!(
        "{}/../vectors/mainnet/evidence/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// Header of the evidence block: replay the chain-dir through the instance,
/// then advance by the finality update recorded with the evidence.
fn anchored_header() -> FinalisedHeader {
    let dir = chain();
    let (config, headers, _) = replay_instance(&dir);
    let (before, _) = replay(&dir);
    let meta = evidence_json("finality-update.json");
    let bytes = std::fs::read(format!(
        "{}/../vectors/mainnet/evidence/finality-update.ssz",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let fork = forks::parse_fork(meta["fork"].as_str().unwrap()).unwrap();
    let raw = forks::decode_finality_update(fork, Preset::Mainnet, Wire::Ssz(&bytes)).unwrap();
    let update = forks::to_core_update(&dir.cfg, &raw).unwrap();
    // The evidence update builds on the state before the chain-dir's own finality update.
    let store = &before[4];
    let base = &headers[headers.len() - 2];
    assert_eq!(base.block_number, store.execution.number);
    let state = instance_state(&config, store, base);
    let input = dir.update_input(store, &update).unwrap();
    let header = instance::advance(&config, &state, base, None, &input, pda)
        .unwrap()
        .header;
    let block = evidence_json("block.json");
    assert_eq!(
        format!("0x{}", hex::encode(header.block_hash)),
        block["hash"].as_str().unwrap()
    );
    assert_eq!(
        format!("0x{}", hex::encode(header.state_root)),
        block["stateRoot"].as_str().unwrap()
    );
    header
}

/// The consensus state of `store` whose header is `header`.
fn instance_state(
    config: &InstanceConfig,
    store: &Store,
    header: &FinalisedHeader,
) -> instance::ConsensusState {
    let id = pda(&config.seed());
    instance::ConsensusState {
        instance: id,
        block_number: header.block_number,
        parent: header.block_number,
        period: chain().cfg.period_at_slot(header.slot),
        current_committee: store.current_committee_root,
        next_committee: store.next_committee_root,
        finalised_header: pda(&instance::header_seed(&id, header.block_number)),
    }
}

/// A header with only `receipts_root` set, for receipts outside the recorded chain.
fn receipts_header(receipts_root: [u8; 32]) -> FinalisedHeader {
    FinalisedHeader {
        instance: [0; 32],
        chain: instance::ChainBinding {
            chain_id: 1,
            genesis_validators_root: [0; 32],
        },
        slot: 0,
        beacon_root: [0; 32],
        block_number: 0,
        block_hash: [0; 32],
        state_root: [0; 32],
        receipts_root,
        signers: 0,
        committee_period: 0,
    }
}

fn word(v: &Value) -> [u8; 32] {
    let b = hex_bytes(v).unwrap();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

fn quantity_word(v: &Value) -> [u8; 32] {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    let b = hex::decode(s).unwrap();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

fn cond(subject: Subject, op: Op, rhs: [u8; 32]) -> Condition {
    Condition { subject, op, rhs }
}

fn claim_of(proof: Proof, conditions: Vec<Condition>) -> Claim {
    Claim {
        chain_id: 1,
        facts: vec![Fact { proof, conditions }],
    }
}

#[test]
fn account_and_storage_claims() {
    let header = anchored_header();
    let weth = evidence_json("weth-proof.json");
    // Existing account.
    let claim = claim_of(
        account_from_get_proof(&weth).unwrap(),
        vec![
            cond(
                Subject::AccountBalance,
                Op::Equal,
                quantity_word(&weth["balance"]),
            ),
            cond(
                Subject::AccountNonce,
                Op::Equal,
                quantity_word(&weth["nonce"]),
            ),
            cond(Subject::AccountCodeHash, Op::Equal, word(&weth["codeHash"])),
            cond(Subject::AccountBalance, Op::Greater, [0; 32]),
        ],
    );
    let s = check_claim(&header, &claim).unwrap();
    assert_eq!(s.chain_id, 1);
    assert_eq!(s.block_number, header.block_number);
    assert_eq!(s.facts[0].class, Class::State);
    // Nonzero WETH slot (slot 0, the name), whole and as packed fields.
    let value = quantity_word(&weth["storageProof"][0]["value"]);
    let slot = claim_of(
        storage_from_proof_value(&weth, 0).unwrap(),
        vec![
            cond(
                Subject::StorageValue {
                    offset: 0,
                    width: 32,
                },
                Op::Equal,
                value,
            ),
            cond(Subject::AccountBalance, Op::Greater, [0; 32]),
        ],
    );
    let slot_statement = check_claim(&header, &slot).unwrap();
    let mut low = [0u8; 32];
    low[31] = value[31];
    check_claim(
        &header,
        &claim_of(
            storage_from_proof_value(&weth, 0).unwrap(),
            vec![cond(
                Subject::StorageValue {
                    offset: 0,
                    width: 1,
                },
                Op::Equal,
                low,
            )],
        ),
    )
    .unwrap();
    // Absent slot reads zero.
    let absent_slot = claim_of(
        storage_from_proof_value(&weth, 1).unwrap(),
        vec![cond(
            Subject::StorageValue {
                offset: 0,
                width: 32,
            },
            Op::Equal,
            [0; 32],
        )],
    );
    check_claim(&header, &absent_slot).unwrap();
    // Two facts under one header: one statement, one ID each, in order.
    let compound = Claim {
        chain_id: 1,
        facts: vec![slot.facts[0].clone(), absent_slot.facts[0].clone()],
    };
    let both = check_claim(&header, &compound).unwrap();
    assert_eq!(both.facts.len(), 2);
    assert_eq!(both.facts[0].id, slot_statement.facts[0].id);
    assert_ne!(both.facts[0].id, both.facts[1].id);
    // Absent account reads as nonce 0, balance 0, empty code.
    let absent = evidence_json("absent-account-proof.json");
    let claim = claim_of(
        account_from_get_proof(&absent).unwrap(),
        vec![
            cond(Subject::AccountNonce, Op::Equal, [0; 32]),
            cond(Subject::AccountBalance, Op::Equal, [0; 32]),
            cond(Subject::AccountCodeHash, Op::Equal, keccak256(&[])),
        ],
    );
    check_claim(&header, &claim).unwrap();

    // Mutations.
    let fails = |c: &Claim, e: Error| assert_eq!(check_claim(&header, c).err(), Some(e));
    let storage = |c: &mut Claim, f: &dyn Fn(&mut Proof)| f(&mut c.facts[0].proof);
    let mut m = slot.clone();
    storage(&mut m, &|p| {
        if let Proof::Storage { storage_proof, .. } = p {
            storage_proof[0][3] ^= 1;
        }
    });
    fails(&m, Error::InvalidProof);
    let mut m = slot.clone();
    storage(&mut m, &|p| {
        if let Proof::Storage { slot, .. } = p {
            slot[31] = 9;
        }
    });
    fails(&m, Error::InvalidProof);
    let mut m = slot.clone();
    storage(&mut m, &|p| {
        if let Proof::Storage { value, .. } = p {
            value[31] ^= 1;
        }
    });
    fails(&m, Error::InvalidInclusionProof);
    let mut m = slot.clone();
    storage(&mut m, &|p| {
        if let Proof::Storage { account, .. } = p {
            account.nonce += 1;
        }
    });
    fails(&m, Error::InvalidInclusionProof);
    let mut m = slot.clone();
    m.chain_id = 5;
    fails(&m, Error::ChainIdMismatch);
    let mut m = slot.clone();
    m.facts.clear();
    fails(&m, Error::MalformedInput);
    let mut m = slot.clone();
    m.facts[0].conditions = vec![cond(Subject::LogEmitter, Op::Equal, [0; 32])];
    fails(&m, Error::MalformedInput);
    let mut m = slot.clone();
    m.facts[0].conditions = vec![cond(
        Subject::StorageValue {
            offset: 31,
            width: 2,
        },
        Op::Equal,
        [0; 32],
    )];
    fails(&m, Error::MalformedInput);
    let mut m = slot.clone();
    m.facts[0].conditions = vec![cond(
        Subject::StorageValue {
            offset: 0,
            width: 32,
        },
        Op::Equal,
        [0; 32],
    )];
    fails(&m, Error::ConditionUnsatisfied);
    let mut m = claim.clone();
    m.facts[0].conditions = vec![cond(
        Subject::StorageValue {
            offset: 0,
            width: 32,
        },
        Op::Equal,
        [0; 32],
    )];
    fails(&m, Error::MalformedInput);
}

/// Checks the log claims of a recorded receipt against its JSON, under a
/// header built from the receipt's block header.
fn check_receipt_file(name: &str, header: Option<&FinalisedHeader>) {
    let r = evidence_json(name);
    let receipts_root = word(&r["block"]["receiptsRoot"]);
    let own;
    let header = match header {
        Some(h) => {
            assert_eq!(h.receipts_root, receipts_root);
            h
        }
        None => {
            own = receipts_header(receipts_root);
            &own
        }
    };
    let tx_index = r["tx_index"].as_u64().unwrap();
    let log_index = r["log_index"].as_u64().unwrap();
    let proof: Vec<Vec<u8>> = r["receipt_proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| hex_bytes(n).unwrap())
        .collect();
    let receipt = eth_lc_host::evidence::receipt_encoding(&r["receipt"]).unwrap();
    let log = &r["receipt"]["logs"][log_index as usize];
    let data = hex_bytes(&log["data"]).unwrap();
    let topics = log["topics"].as_array().unwrap();
    let count = |n: usize| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&(n as u64).to_be_bytes());
        w
    };
    let mut conditions = vec![
        cond(Subject::LogEmitter, Op::Equal, word(&log["address"])),
        cond(Subject::LogTopicCount, Op::Equal, count(topics.len())),
        cond(Subject::LogDataLength, Op::Equal, count(data.len())),
    ];
    for (i, t) in topics.iter().enumerate() {
        conditions.push(cond(Subject::LogTopic(i as u8), Op::Equal, word(t)));
    }
    for (i, w) in data.chunks_exact(32).enumerate().take(256) {
        conditions.push(cond(
            Subject::LogDataWord(i as u8),
            Op::Equal,
            w.try_into().unwrap(),
        ));
    }
    let claim = claim_of(
        Proof::Log {
            tx_index,
            receipt,
            proof,
            log_index,
        },
        conditions,
    );
    let s = check_claim(header, &claim).unwrap();
    assert_eq!(s.facts[0].class, Class::Occurrence);
    println!(
        "{name}: type {} tx {tx_index} log {log_index}: {} conditions hold",
        r["receipt"]["type"],
        claim.facts[0].conditions.len()
    );

    // Mutations on this receipt.
    let fails = |c: &Claim, e: Error| assert_eq!(check_claim(header, c).err(), Some(e), "{name}");
    let mut m = claim.clone();
    if let Proof::Log { log_index, .. } = &mut m.facts[0].proof {
        *log_index = r["receipt"]["logs"].as_array().unwrap().len() as u64;
    }
    fails(&m, Error::MalformedInput);
    let mut m = claim.clone();
    if let Proof::Log { receipt, .. } = &mut m.facts[0].proof {
        let last = receipt.len() - 1;
        receipt[last] ^= 1;
    }
    fails(&m, Error::InvalidInclusionProof);
    let mut m = claim.clone();
    m.facts[0].conditions = vec![cond(
        Subject::LogDataWord((data.len() / 32) as u8),
        Op::Equal,
        [0; 32],
    )];
    fails(&m, Error::MalformedInput);
    let mut m = claim.clone();
    m.facts[0].conditions = vec![cond(
        Subject::LogTopic(topics.len() as u8),
        Op::Equal,
        [0; 32],
    )];
    fails(&m, Error::MalformedInput);
    let mut m = claim.clone();
    m.facts[0].conditions = vec![cond(Subject::AccountNonce, Op::Equal, [0; 32])];
    fails(&m, Error::MalformedInput);
    let mut m = claim.clone();
    m.facts[0].conditions[0].op = Op::NotEqual;
    fails(&m, Error::ConditionUnsatisfied);
}

#[test]
fn receipt_claims_for_index_zero_and_each_type() {
    let header = anchored_header();
    check_receipt_file("receipt-index0.json", Some(&header));
    for t in [0, 2, 3, 4] {
        check_receipt_file(&format!("receipt-type-{t}.json"), None);
    }
}

#[test]
fn crafted_receipts_fail() {
    // A one-receipt trie whose value is a typed receipt with a given type byte, or with trailing bytes.
    let base = evidence_json("receipt-type-2.json")["receipt"].clone();
    let encoded = eth_lc_host::evidence::receipt_encoding(&base).unwrap();
    let run = |value: Vec<u8>, tx_index: u64| {
        let key = alloy_trie::Nibbles::unpack([0x80]);
        let mut target = Vec::new();
        alloy_rlp::Encodable::encode(&tx_index, &mut target);
        let target = alloy_trie::Nibbles::unpack(target);
        let mut hb = alloy_trie::HashBuilder::default()
            .with_proof_retainer(alloy_trie::proof::ProofRetainer::new(vec![target.clone()]));
        hb.add_leaf(key, &value);
        let root = hb.root();
        let proof: Vec<Vec<u8>> = hb
            .take_proof_nodes()
            .matching_nodes_sorted(&target)
            .into_iter()
            .map(|(_, n)| n.to_vec())
            .collect();
        let claim = claim_of(
            Proof::Log {
                tx_index,
                receipt: value,
                proof,
                log_index: 0,
            },
            vec![],
        );
        check_claim(&receipts_header(root.0), &claim).err()
    };
    assert_eq!(run(encoded.clone(), 0), None);
    let mut unknown = encoded.clone();
    unknown[0] = 0x05;
    assert_eq!(run(unknown, 0), Some(Error::UnknownReceiptType));
    let mut trailing = encoded.clone();
    trailing.push(0x80);
    assert_eq!(run(trailing, 0), Some(Error::InvalidReceipt));
    // A reverted transaction's receipt proves no log.
    let mut reverted_json = base.clone();
    reverted_json["status"] = Value::String("0x0".into());
    let reverted = eth_lc_host::evidence::receipt_encoding(&reverted_json).unwrap();
    assert_eq!(run(reverted, 0), Some(Error::ConditionUnsatisfied));
    // Index 1 is absent from a one-receipt trie.
    assert_eq!(run(encoded, 1), Some(Error::ReceiptAbsent));
}

#[test]
fn mainnet_update_mutations_fail() {
    let dir = chain();
    let (before, _) = replay(&dir);
    // Step 1: the committee handoff on real data.
    let store = &before[1];
    let base = dir.update_input(store, &dir.updates[1]).unwrap();
    assert!(apply_update(&dir.cfg, store, &base).is_ok());
    let cases: Vec<(&str, Box<dyn Fn(&mut eth_lc_core::UpdateInput)>, Error)> = vec![
        (
            "signature byte",
            Box::new(|i| i.update.sync_aggregate.signature[7] ^= 1),
            Error::InvalidSignature,
        ),
        (
            "bit cleared without hint",
            Box::new(|i| {
                let byte = i
                    .update
                    .sync_aggregate
                    .bits
                    .iter()
                    .position(|b| *b == 0xff)
                    .unwrap();
                i.update.sync_aggregate.bits[byte] = 0xfe;
            }),
            Error::HintMismatch,
        ),
        (
            "duplicate hint",
            Box::new(|i| {
                let h = i.hints.non_signers[0].clone();
                i.hints.non_signers.push(h);
            }),
            Error::HintMismatch,
        ),
        (
            "aggregate hint",
            Box::new(|i| i.hints.aggregate[50] ^= 1),
            Error::InvalidKey,
        ),
        (
            "wrong committee",
            Box::new(|i| i.hints.pubkeys_root[0] ^= 1),
            Error::CommitteeMismatch,
        ),
        (
            "finality branch node",
            Box::new(|i| i.update.finality.as_mut().unwrap().1[0][0] ^= 1),
            Error::InvalidFinalityBranch,
        ),
        (
            "next-committee branch node",
            Box::new(|i| i.update.next_sync_committee.as_mut().unwrap().1[4][9] ^= 1),
            Error::InvalidNextCommitteeBranch,
        ),
        (
            "signature slot",
            Box::new(|i| i.update.signature_slot = i.update.attested_header.beacon().slot),
            Error::SlotOrder,
        ),
    ];
    for (name, f, want) in cases {
        let mut i = base.clone();
        f(&mut i);
        assert_eq!(apply_update(&dir.cfg, store, &i), Err(want), "{name}");
    }
    // Preset fields are pinned: each deviation is refused before any check.
    let preset: Vec<fn(&mut eth_lc_core::ChainConfig)> = vec![
        |c| c.seconds_per_slot = 6,
        |c| c.slots_per_epoch = 16,
        |c| c.epochs_per_sync_committee_period = 128,
        |c| c.sync_committee_size = 256,
    ];
    for f in preset {
        let mut cfg = dir.cfg.clone();
        f(&mut cfg);
        assert_eq!(apply_update(&cfg, store, &base), Err(Error::PresetMismatch));
    }
    // Chain identity comes from Init: structural violations are refused.
    let structural: Vec<fn(&mut eth_lc_core::ChainConfig)> = vec![
        |c| c.chain_id = 0,
        |c| c.genesis_validators_root = [0; 32],
        |c| c.forks[6].version = c.forks[5].version,
        |c| c.forks[6].epoch = c.forks[5].epoch - 1,
    ];
    for f in structural {
        let mut cfg = dir.cfg.clone();
        f(&mut cfg);
        assert_eq!(
            apply_update(&cfg, store, &base),
            Err(Error::InvalidChainIdentity)
        );
    }
    // Another identity passes the structure. The signing domain binds the
    // genesis root and the fork version; the operator binds the other
    // identity fields with `verify_instance_config`.
    let domain: Vec<fn(&mut eth_lc_core::ChainConfig)> =
        vec![|c| c.genesis_validators_root[31] ^= 1, |c| {
            c.forks[6].version[3] = 1
        }];
    for f in domain {
        let mut cfg = dir.cfg.clone();
        f(&mut cfg);
        assert_eq!(
            apply_update(&cfg, store, &base),
            Err(Error::InvalidSignature)
        );
    }
    let mut other = dir.cfg.clone();
    other.chain_id = 17_000;
    other.genesis_time -= 1;
    other.forks[7].epoch = 600_000;
    assert!(apply_update(&other, store, &base).is_ok());
}
