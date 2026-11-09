//! `ethereum/tests` `TrieTests` (commit `c67e485ff8b5be9abc8ad15345ec21aa22e290d9`):
//! `alloy-trie` rebuilds each trie and must reach the expected root; the core
//! walker then returns every value from an `alloy-trie` proof, proves absence
//! of deleted and unknown keys, and rejects an empty proof against the root.
//! Cases with a key that prefixes another key are skipped: `alloy-trie`
//! builds prefix-free tries only.
//!
//! Data: `SPEC_DATA/TrieTests` (default `../spec-data`), filled by `just eth-tests`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use alloy_trie::proof::ProofRetainer;
use alloy_trie::{HashBuilder, Nibbles};
use eth_lc_core::crypto::keccak256;
use eth_lc_core::mpt::{get, EMPTY_TRIE_ROOT};
use serde_json::Value;

fn data_dir() -> PathBuf {
    std::env::var("SPEC_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec-data"))
}

fn bytes(v: &Value) -> Option<Vec<u8>> {
    let s = v.as_str()?;
    Some(match s.strip_prefix("0x") {
        Some(h) => hex::decode(h).unwrap(),
        None => s.as_bytes().to_vec(),
    })
}

fn run(file: &str, secure: bool) -> usize {
    let path = data_dir().join("TrieTests").join(file);
    let tests: Value = serde_json::from_slice(
        &std::fs::read(&path)
            .unwrap_or_else(|e| panic!("{}: {e} (run `just eth-tests`)", path.display())),
    )
    .unwrap();
    let mut n = 0;
    for (name, t) in tests.as_object().unwrap() {
        let pairs: Vec<(Vec<u8>, Option<Vec<u8>>)> = match &t["in"] {
            Value::Array(a) => a
                .iter()
                .map(|p| (bytes(&p[0]).unwrap(), bytes(&p[1])))
                .collect(),
            Value::Object(o) => o
                .iter()
                .map(|(k, v)| (bytes(&Value::String(k.clone())).unwrap(), bytes(v)))
                .collect(),
            other => panic!("{name}: unexpected input {other}"),
        };
        let mut state: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let mut touched = Vec::new();
        for (k, v) in pairs {
            let key = if secure { keccak256(&k).to_vec() } else { k };
            touched.push(key.clone());
            match v.filter(|v| !v.is_empty()) {
                Some(v) => state.insert(key, v),
                None => state.remove(&key),
            };
        }
        // `alloy-trie` builds tries of prefix-free keys only (values in leaves only).
        let keys: Vec<&Vec<u8>> = state.keys().collect();
        if keys
            .iter()
            .any(|a| keys.iter().any(|b| a != b && b.starts_with(a)))
        {
            println!("{file}/{name}: skipped (a key is a prefix of another key)");
            continue;
        }
        touched.push(b"absent key not in any test".to_vec());
        let targets: Vec<Nibbles> = touched.iter().map(Nibbles::unpack).collect();
        let mut hb =
            HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets.clone()));
        let mut leaves: Vec<(Nibbles, &Vec<u8>)> =
            state.iter().map(|(k, v)| (Nibbles::unpack(k), v)).collect();
        leaves.sort_by(|a, b| a.0.cmp(&b.0));
        for (k, v) in &leaves {
            hb.add_leaf(k.clone(), v);
        }
        let root = hb.root().0;
        let expected = bytes(&t["root"]).unwrap();
        assert_eq!(root.to_vec(), expected, "{file}/{name}: alloy-trie root");
        let nodes = hb.take_proof_nodes();
        for (key, target) in touched.iter().zip(&targets) {
            let proof: Vec<Vec<u8>> = nodes
                .matching_nodes_sorted(target)
                .into_iter()
                .map(|(_, n)| n.to_vec())
                .collect();
            let want = state.get(key).cloned();
            assert_eq!(
                get(&root, key, &proof),
                Ok(want),
                "{file}/{name}: key {}",
                hex::encode(key)
            );
            n += 1;
        }
        if root != EMPTY_TRIE_ROOT {
            assert!(
                get(&root, &touched[0], &[]).is_err(),
                "{file}/{name}: empty proof"
            );
        }
    }
    println!(
        "{file}: {} tests, {n} lookups",
        tests.as_object().unwrap().len()
    );
    n
}

#[test]
fn trie_tests() {
    let mut n = 0;
    n += run("trietest.json", false);
    n += run("trieanyorder.json", false);
    n += run("trietest_secureTrie.json", true);
    n += run("trieanyorder_secureTrie.json", true);
    n += run("hex_encoded_securetrie_test.json", true);
    assert!(n > 50);
}
