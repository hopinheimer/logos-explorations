//! Golden borsh encodings of every public core type. A change here changes
//! state bytes and wire inputs: it needs a minor version bump while at 0.x.

use borsh::BorshSerialize;
use eth_lc_core::claim::{
    Attestation, Claim, Condition, Evidence, Field, HeaderRecord, Op, Subject,
};
use eth_lc_core::crypto::sha256;
fn mainnet() -> ChainConfig {
    ChainConfig::mainnet()
}
use eth_lc_core::*;

fn digest<T: BorshSerialize>(v: &T) -> String {
    let bytes = borsh::to_vec(v).unwrap();
    format!("{} {}", bytes.len(), hex(&sha256(&bytes)[..8]))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn beacon() -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot: 1,
        proposer_index: 2,
        parent_root: [3; 32],
        state_root: [4; 32],
        body_root: [5; 32],
    }
}

fn capella() -> ExecutionPayloadHeaderCapella {
    ExecutionPayloadHeaderCapella {
        block_number: 6,
        extra_data: vec![7, 8],
        logs_bloom: [9; 256],
        ..Default::default()
    }
}

fn deneb() -> ExecutionPayloadHeaderDeneb {
    ExecutionPayloadHeaderDeneb {
        block_number: 6,
        extra_data: vec![7, 8],
        blob_gas_used: 10,
        excess_blob_gas: 11,
        ..Default::default()
    }
}

fn committee() -> SyncCommittee {
    SyncCommittee {
        pubkeys: vec![[12; 48], [13; 48]],
        aggregate_pubkey: [14; 48],
    }
}

fn headers() -> [LightClientHeader; 3] {
    [
        LightClientHeader::Capella {
            beacon: beacon(),
            execution: capella(),
            execution_branch: vec![[15; 32]],
        },
        LightClientHeader::Deneb {
            beacon: beacon(),
            execution: deneb(),
            execution_branch: vec![[16; 32]],
        },
        LightClientHeader::Gloas {
            beacon: beacon(),
            execution_block_hash: [17; 32],
            execution_branch: vec![[18; 32]],
        },
    ]
}

fn update() -> LightClientUpdate {
    let [_, d, _] = headers();
    LightClientUpdate {
        attested_header: d.clone(),
        next_sync_committee: Some((committee(), vec![[19; 32]])),
        finality: Some((d, vec![[20; 32]])),
        sync_aggregate: SyncAggregate {
            bits: vec![0xff, 0x7f],
            signature: [21; 96],
        },
        signature_slot: 22,
    }
}

fn store() -> Store {
    Store {
        finalized: beacon(),
        execution: ExecutionAnchor {
            block_hash: [23; 32],
            number: 24,
            state_root: [25; 32],
            receipts_root: [26; 32],
        },
        current_committee_root: [27; 32],
        next_committee_root: Some([28; 32]),
    }
}

fn record() -> HeaderRecord {
    HeaderRecord::from_store(&mainnet(), &store())
}

fn claim() -> Claim {
    Claim {
        chain_id: 1,
        evidence: Evidence::Storage {
            address: [29; 20],
            account_proof: vec![vec![30]],
            key: [31; 32],
            storage_proof: vec![vec![32]],
        },
        conditions: vec![Condition {
            field: Field::LogTopic(2),
            op: Op::Ge,
            value: [33; 32],
        }],
    }
}

#[test]
fn golden_encodings() {
    let [c, d, g] = headers();
    let got = [
        (
            "Fork",
            digest(&Fork {
                version: [1, 2, 3, 4],
                epoch: 5,
            }),
        ),
        ("ChainConfig mainnet", digest(&mainnet())),
        ("BeaconBlockHeader", digest(&beacon())),
        ("ExecutionPayloadHeaderCapella", digest(&capella())),
        ("ExecutionPayloadHeaderDeneb", digest(&deneb())),
        ("LightClientHeader::Capella", digest(&c)),
        ("LightClientHeader::Deneb", digest(&d)),
        ("LightClientHeader::Gloas", digest(&g)),
        ("SyncCommittee", digest(&committee())),
        (
            "LightClientBootstrap",
            digest(&LightClientBootstrap {
                header: g.clone(),
                current_sync_committee: committee(),
                current_sync_committee_branch: vec![[34; 32]],
            }),
        ),
        ("LightClientUpdate", digest(&update())),
        ("Store", digest(&store())),
        (
            "KeyHints",
            digest(&KeyHints {
                aggregate: [35; 96],
                non_signers: vec![(36, [37; 96])],
            }),
        ),
        (
            "UpdateInput",
            digest(&UpdateInput {
                update: update(),
                committee: committee(),
                hints: KeyHints {
                    aggregate: [35; 96],
                    non_signers: vec![],
                },
                execution_header_rlp: Some(vec![38]),
            }),
        ),
        (
            "BootstrapInput",
            digest(&BootstrapInput {
                trusted_block_root: [39; 32],
                bootstrap: LightClientBootstrap {
                    header: c,
                    current_sync_committee: committee(),
                    current_sync_committee_branch: vec![],
                },
                execution_header_rlp: None,
            }),
        ),
        ("(ChainConfig, Store)", digest(&(mainnet(), store()))),
        ("HeaderRecord", digest(&record())),
        (
            "Subject::Log",
            digest(&Subject::Log {
                tx_index: 40,
                log_index: 41,
            }),
        ),
        (
            "Evidence::ReceiptLog",
            digest(&Evidence::ReceiptLog {
                tx_index: 42,
                receipt_proof: vec![vec![43, 44]],
                log_index: 45,
            }),
        ),
        (
            "Evidence::Account",
            digest(&Evidence::Account {
                address: [46; 20],
                account_proof: vec![],
            }),
        ),
        ("Field::LogDataWord", digest(&Field::LogDataWord(47))),
        ("Op::Lt", digest(&Op::Lt)),
        ("Claim", digest(&claim())),
        (
            "Attestation",
            digest(&Attestation {
                record: record(),
                subject: Subject::Account { address: [48; 20] },
                conditions: claim().conditions,
            }),
        ),
    ];
    let now: Vec<(&str, &str)> = got.iter().map(|(n, d)| (*n, d.as_str())).collect();
    if now != GOLDEN {
        for (name, d) in &now {
            println!("    (\"{name}\", \"{d}\"),");
        }
        panic!("borsh layout changed; bump the minor version and update GOLDEN");
    }
}

/// `(type, "length sha256-prefix")` of each encoding.
const GOLDEN: &[(&str, &str)] = &[
    ("Fork", "12 89e68c2b49a8b038"),
    ("ChainConfig mainnet", "176 a37d59c5df2fb874"),
    ("BeaconBlockHeader", "112 6a74b6d31d1c523c"),
    ("ExecutionPayloadHeaderCapella", "570 5b39febf2a094902"),
    ("ExecutionPayloadHeaderDeneb", "586 9ac34d9a09a690bc"),
    ("LightClientHeader::Capella", "719 46be16f48ba6e753"),
    ("LightClientHeader::Deneb", "735 306a2ca22ecec9ff"),
    ("LightClientHeader::Gloas", "181 5106d72af5d33115"),
    ("SyncCommittee", "148 e76812f1fc46a522"),
    ("LightClientBootstrap", "365 7098a1ae05a86472"),
    ("LightClientUpdate", "1802 49e08258cae79228"),
    ("Store", "281 c59266f0765f30a6"),
    ("KeyHints", "200 289eaa755ef03658"),
    ("UpdateInput", "2056 24273338a56762c1"),
    ("BootstrapInput", "904 45b54820f494ee6d"),
    ("(ChainConfig, Store)", "457 5d3623ced8f389db"),
    ("HeaderRecord", "152 de1f4c31af1abff1"),
    ("Subject::Log", "13 b4b80b026f0beb62"),
    ("Evidence::ReceiptLog", "23 72eaa9c5bafa2167"),
    ("Evidence::Account", "25 edd70a7008195d57"),
    ("Field::LogDataWord", "5 05c2f294571495f3"),
    ("Op::Lt", "1 dbc1b4c900ffe48d"),
    ("Claim", "118 33ebb9b7896b0910"),
    ("Attestation", "212 bbd165bd8dc14ebf"),
];
