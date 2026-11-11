//! Golden borsh encodings of every public core type. A change here changes
//! state bytes and wire inputs: it needs a minor version bump while at 0.x.

use borsh::BorshSerialize;
use eth_lc_core::claim::{
    Claim, Class, Condition, EthAccount, Fact, Op, Proof, ProvenFact, Statement, Subject,
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

fn config() -> InstanceConfig {
    mainnet().instance_config([29; 32])
}

fn header() -> FinalisedHeader {
    FinalisedHeader {
        instance: [30; 32],
        chain: config().chain,
        slot: 31,
        beacon_root: [32; 32],
        block_number: 33,
        block_hash: [34; 32],
        state_root: [35; 32],
        receipts_root: [36; 32],
        signers: 400,
        committee_period: 37,
    }
}

fn account() -> EthAccount {
    EthAccount {
        nonce: 38,
        balance: [39; 32],
        storage_root: [40; 32],
        code_hash: [41; 32],
    }
}

fn condition() -> Condition {
    Condition {
        subject: Subject::StorageValue {
            offset: 2,
            width: 3,
        },
        op: Op::AtLeast,
        rhs: [42; 32],
    }
}

fn claim() -> Claim {
    Claim {
        chain_id: 1,
        facts: vec![Fact {
            proof: Proof::Storage {
                address: [43; 20],
                account: account(),
                account_proof: vec![vec![44]],
                slot: [45; 32],
                value: [46; 32],
                storage_proof: vec![vec![47]],
            },
            conditions: vec![condition()],
        }],
    }
}

fn statement() -> Statement {
    Statement {
        instance: [48; 32],
        chain_id: 1,
        block_number: 49,
        facts: vec![ProvenFact {
            class: Class::Occurrence,
            id: [50; 32],
            conditions: vec![condition()],
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
        ("InstanceConfig mainnet", digest(&config())),
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
        (
            "ConsensusState",
            digest(&ConsensusState {
                instance: [51; 32],
                block_number: 52,
                parent: 53,
                period: 54,
                current_committee: [55; 32],
                next_committee: Some([56; 32]),
                finalised_header: [57; 32],
            }),
        ),
        (
            "Committee",
            digest(&Committee {
                instance: [58; 32],
                period: 59,
                root: [60; 32],
                handoff_slot: 61,
            }),
        ),
        ("FinalisedHeader", digest(&header())),
        ("Condition", digest(&condition())),
        ("Subject::LogDataWord", digest(&Subject::LogDataWord(62))),
        ("Op::Less", digest(&Op::Less)),
        ("Claim", digest(&claim())),
        (
            "Proof::Log",
            digest(&Proof::Log {
                tx_index: 63,
                receipt: vec![64, 65],
                proof: vec![vec![66]],
                log_index: 67,
            }),
        ),
        (
            "Proof::Account",
            digest(&Proof::Account {
                address: [68; 20],
                account: account(),
                account_proof: vec![],
            }),
        ),
        ("Statement", digest(&statement())),
        (
            "Event::CommitteeHandoff",
            digest(&Event::CommitteeHandoff {
                instance: [69; 32],
                period: 70,
                committee_root: [71; 32],
            }),
        ),
        (
            "Event::HeaderFinalised",
            digest(&Event::HeaderFinalised {
                instance: [72; 32],
                block_number: 73,
                header: [74; 32],
            }),
        ),
        (
            "Event::Attested",
            digest(&Event::Attested {
                statement: statement(),
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
    ("InstanceConfig mainnet", "190 0b26e80a6e44885a"),
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
    ("ConsensusState", "153 c9a2ec750bf5cc6a"),
    ("Committee", "80 4ba39713f332eabe"),
    ("FinalisedHeader", "226 2a3b00603a9a8b58"),
    ("Condition", "36 6e37b5e061635d93"),
    ("Subject::LogDataWord", "2 3b7d11628fc2f0c9"),
    ("Op::Less", "1 dbc1b4c900ffe48d"),
    ("Claim", "259 bb7d9d6e58febd52"),
    ("Proof::Log", "32 c22e846ed1672831"),
    ("Proof::Account", "129 6c4d77a3b0a3aef8"),
    ("Statement", "125 5b21dec7fe3a6de3"),
    ("Event::CommitteeHandoff", "73 6aa49776cdf22424"),
    ("Event::HeaderFinalised", "73 bb772b72d12520ad"),
    ("Event::Attested", "126 6da74b12119969b2"),
];
