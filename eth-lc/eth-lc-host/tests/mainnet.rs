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
// Claims against the record of a light-client-verified block.

use eth_lc_core::claim::{
    check_claim, Claim, Condition, Evidence, Field, HeaderRecord, Op, Subject,
};
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

/// Record of the evidence block: replay the chain-dir, then apply the
/// finality update recorded with the evidence.
fn anchored_record() -> HeaderRecord {
    let dir = chain();
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
    let store = &before[4];
    let next = apply_update(&dir.cfg, store, &dir.update_input(store, &update).unwrap()).unwrap();
    let record = HeaderRecord::from_store(&dir.cfg, &next);
    let block = evidence_json("block.json");
    assert_eq!(
        format!("0x{}", hex::encode(record.block_hash)),
        block["hash"].as_str().unwrap()
    );
    assert_eq!(
        format!("0x{}", hex::encode(record.state_root)),
        block["stateRoot"].as_str().unwrap()
    );
    record
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

fn cond(field: Field, op: Op, value: [u8; 32]) -> Condition {
    Condition { field, op, value }
}

#[test]
fn account_and_storage_claims() {
    let record = anchored_record();
    let weth = evidence_json("weth-proof.json");
    // Existing account.
    let claim = Claim {
        chain_id: 1,
        evidence: account_from_get_proof(&weth).unwrap(),
        conditions: vec![
            cond(Field::Balance, Op::Eq, quantity_word(&weth["balance"])),
            cond(Field::Nonce, Op::Eq, quantity_word(&weth["nonce"])),
            cond(Field::CodeHash, Op::Eq, word(&weth["codeHash"])),
            cond(Field::StorageRoot, Op::Eq, word(&weth["storageHash"])),
            cond(Field::Balance, Op::Gt, [0; 32]),
        ],
    };
    let a = check_claim(&record, &claim).unwrap();
    assert!(matches!(a.subject, Subject::Account { .. }));
    // Nonzero WETH slot (slot 0, the name).
    let slot = Claim {
        chain_id: 1,
        evidence: storage_from_proof_value(&weth, 0).unwrap(),
        conditions: vec![cond(
            Field::StorageValue,
            Op::Eq,
            quantity_word(&weth["storageProof"][0]["value"]),
        )],
    };
    check_claim(&record, &slot).unwrap();
    // Absent slot reads zero.
    let absent_slot = Claim {
        chain_id: 1,
        evidence: storage_from_proof_value(&weth, 1).unwrap(),
        conditions: vec![cond(Field::StorageValue, Op::Eq, [0; 32])],
    };
    check_claim(&record, &absent_slot).unwrap();
    // Absent account reads as nonce 0, balance 0, empty code.
    let absent = evidence_json("absent-account-proof.json");
    let claim = Claim {
        chain_id: 1,
        evidence: account_from_get_proof(&absent).unwrap(),
        conditions: vec![
            cond(Field::Nonce, Op::Eq, [0; 32]),
            cond(Field::Balance, Op::Eq, [0; 32]),
            cond(Field::CodeHash, Op::Eq, keccak256(&[])),
            cond(
                Field::StorageRoot,
                Op::Eq,
                eth_lc_core::mpt::EMPTY_TRIE_ROOT,
            ),
        ],
    };
    check_claim(&record, &claim).unwrap();

    // Mutations.
    let fails = |c: &Claim, e: Error| assert_eq!(check_claim(&record, c).err(), Some(e));
    let mut m = slot.clone();
    if let Evidence::Storage { storage_proof, .. } = &mut m.evidence {
        storage_proof[0][3] ^= 1;
    }
    fails(&m, Error::InvalidProof);
    let mut m = slot.clone();
    if let Evidence::Storage { key, .. } = &mut m.evidence {
        key[31] = 9;
    }
    fails(&m, Error::InvalidProof);
    let mut m = slot.clone();
    if let Evidence::Storage { storage_proof, .. } = &mut m.evidence {
        storage_proof.clear();
    }
    fails(&m, Error::InvalidProof);
    let mut m = slot.clone();
    m.chain_id = 5;
    fails(&m, Error::ChainIdMismatch);
    let mut m = slot.clone();
    m.conditions = vec![cond(Field::Balance, Op::Eq, [0; 32])];
    fails(&m, Error::FieldMismatch);
    let mut m = slot.clone();
    m.conditions = vec![cond(Field::StorageValue, Op::Eq, [0; 32])];
    fails(&m, Error::ConditionFailed);
}

/// Checks the log claims of a recorded receipt against its JSON, under a
/// record built from the receipt's block header.
fn check_receipt_file(name: &str, record: Option<&HeaderRecord>) {
    let r = evidence_json(name);
    let receipts_root = word(&r["block"]["receiptsRoot"]);
    let own;
    let record = match record {
        Some(rec) => {
            assert_eq!(rec.receipts_root, receipts_root);
            rec
        }
        None => {
            own = HeaderRecord {
                chain_id: 1,
                slot: 0,
                beacon_root: [0; 32],
                block_number: 0,
                block_hash: [0; 32],
                state_root: [0; 32],
                receipts_root,
            };
            &own
        }
    };
    let tx_index = r["tx_index"].as_u64().unwrap();
    let log_index = r["log_index"].as_u64().unwrap() as u32;
    let proof: Vec<Vec<u8>> = r["receipt_proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| hex_bytes(n).unwrap())
        .collect();
    let log = &r["receipt"]["logs"][log_index as usize];
    let data = hex_bytes(&log["data"]).unwrap();
    let mut conditions = vec![cond(Field::LogAddress, Op::Eq, word(&log["address"]))];
    for (i, t) in log["topics"].as_array().unwrap().iter().enumerate() {
        conditions.push(cond(Field::LogTopic(i as u8), Op::Eq, word(t)));
    }
    for (i, w) in data.chunks_exact(32).enumerate() {
        conditions.push(cond(
            Field::LogDataWord(i as u32),
            Op::Eq,
            w.try_into().unwrap(),
        ));
    }
    let claim = Claim {
        chain_id: 1,
        evidence: Evidence::ReceiptLog {
            tx_index,
            receipt_proof: proof,
            log_index,
        },
        conditions,
    };
    let a = check_claim(record, &claim).unwrap();
    assert_eq!(
        a.subject,
        Subject::Log {
            tx_index,
            log_index
        }
    );
    println!(
        "{name}: type {} tx {tx_index} log {log_index}: {} conditions hold",
        r["receipt"]["type"],
        claim.conditions.len()
    );

    // Mutations on this receipt.
    let fails = |c: &Claim, e: Error| assert_eq!(check_claim(record, c).err(), Some(e), "{name}");
    let mut m = claim.clone();
    if let Evidence::ReceiptLog { log_index, .. } = &mut m.evidence {
        *log_index = r["receipt"]["logs"].as_array().unwrap().len() as u32;
    }
    fails(&m, Error::OutOfRange);
    let mut m = claim.clone();
    m.conditions = vec![cond(
        Field::LogDataWord((data.len() / 32) as u32),
        Op::Eq,
        [0; 32],
    )];
    fails(&m, Error::OutOfRange);
    let mut m = claim.clone();
    m.conditions = vec![cond(
        Field::LogTopic(log["topics"].as_array().unwrap().len() as u8),
        Op::Eq,
        [0; 32],
    )];
    fails(&m, Error::OutOfRange);
    let mut m = claim.clone();
    m.conditions = vec![cond(Field::Nonce, Op::Eq, [0; 32])];
    fails(&m, Error::FieldMismatch);
    let mut m = claim.clone();
    m.conditions[0].op = Op::Ne;
    fails(&m, Error::ConditionFailed);
}

#[test]
fn receipt_claims_for_index_zero_and_each_type() {
    let record = anchored_record();
    check_receipt_file("receipt-index0.json", Some(&record));
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
        let record = HeaderRecord {
            chain_id: 1,
            slot: 0,
            beacon_root: [0; 32],
            block_number: 0,
            block_hash: [0; 32],
            state_root: [0; 32],
            receipts_root: root.0,
        };
        let claim = Claim {
            chain_id: 1,
            evidence: Evidence::ReceiptLog {
                tx_index,
                receipt_proof: proof,
                log_index: 0,
            },
            conditions: vec![],
        };
        check_claim(&record, &claim).err()
    };
    assert_eq!(run(encoded.clone(), 0), None);
    let mut unknown = encoded.clone();
    unknown[0] = 0x05;
    assert_eq!(run(unknown, 0), Some(Error::UnknownReceiptType));
    let mut trailing = encoded.clone();
    trailing.push(0x80);
    assert_eq!(run(trailing, 0), Some(Error::InvalidReceipt));
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
                let h = i.hints.non_signers[0];
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
            Box::new(|i| i.committee.pubkeys.swap(3, 4)),
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
