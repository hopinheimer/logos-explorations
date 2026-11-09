//! consensus-specs `v1.7.0-beta.4` `single_merkle_proof` vectors: each
//! `leaf_index` equals the gindex the core uses for that fork.

use std::path::{Path, PathBuf};

use eth_lc_core::fork::{
    current_sync_committee_gindex, execution_gindex, finalized_root_gindex,
    next_sync_committee_gindex,
};
use eth_lc_core::ssz::floorlog2;
use eth_lc_core::ForkName;

fn data_dir() -> PathBuf {
    std::env::var("SPEC_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec-data"))
}

#[test]
fn leaf_indices_match_core_gindices() {
    let root = data_dir().join("tests");
    assert!(
        root.exists(),
        "spec data missing at {}: run `just spec-tests`",
        root.display()
    );
    let forks = [
        ("altair", ForkName::Altair),
        ("bellatrix", ForkName::Bellatrix),
        ("capella", ForkName::Capella),
        ("deneb", ForkName::Deneb),
        ("electra", ForkName::Electra),
        ("fulu", ForkName::Fulu),
        ("gloas", ForkName::Gloas),
    ];
    let mut checked = 0;
    for preset in ["minimal", "mainnet"] {
        for (name, fork) in forks {
            let base = root
                .join(preset)
                .join(name)
                .join("light_client/single_merkle_proof");
            for object in ["BeaconState", "BeaconBlockBody"] {
                let Ok(cases) = std::fs::read_dir(base.join(object)) else {
                    continue;
                };
                for case in cases {
                    let case = case.unwrap().path();
                    let case_name = case.file_name().unwrap().to_string_lossy().to_string();
                    let proof: serde_yaml::Value =
                        serde_yaml::from_slice(&std::fs::read(case.join("proof.yaml")).unwrap())
                            .unwrap();
                    let leaf_index = proof["leaf_index"].as_u64().unwrap();
                    let ours = match case_name.as_str() {
                        "current_sync_committee_merkle_proof" => {
                            current_sync_committee_gindex(fork)
                        }
                        "next_sync_committee_merkle_proof" => next_sync_committee_gindex(fork),
                        "finality_root_merkle_proof" => finalized_root_gindex(fork),
                        "execution_merkle_proof" | "execution_block_hash_merkle_proof" => {
                            execution_gindex(fork).unwrap()
                        }
                        other => panic!("unexpected case {other}"),
                    };
                    assert_eq!(leaf_index, ours, "{preset}/{name}/{object}/{case_name}");
                    let branch = proof["branch"].as_sequence().unwrap().len();
                    assert_eq!(
                        branch as u32,
                        floorlog2(leaf_index),
                        "{preset}/{name}/{case_name} branch length"
                    );
                    checked += 1;
                }
            }
            println!("{preset}/{name}: ok");
        }
    }
    println!("{checked} proofs checked; heze skipped (fork outside Capella..Gloas)");
    assert!(checked >= 50);
}
