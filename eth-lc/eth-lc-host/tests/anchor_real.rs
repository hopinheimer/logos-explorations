//! Execution anchors from recorded mainnet blocks: `header_rlp_from_rpc`
//! encodes each RPC header, its Keccak-256 equals the RPC hash, and the core reads
//! the same state root, receipts root and number from that RLP.

use eth_lc_core::crypto::keccak256;
use eth_lc_core::execution::header_fields;
use eth_lc_core::{BeaconBlockHeader, LightClientHeader};
use eth_lc_host::execution::header_rlp_from_rpc;
use serde_json::Value;

fn block(name: &str) -> Value {
    let path = format!(
        "{}/../vectors/mainnet/evidence/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn root(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}

fn check(name: &str, fields: usize) -> Vec<u8> {
    let json = block(name);
    let rlp = header_rlp_from_rpc(&json).unwrap();
    assert_eq!(keccak256(&rlp), root(&json["hash"]), "{name}: hash");
    let (state_root, receipts_root, number) = header_fields(&rlp).unwrap();
    assert_eq!(state_root, root(&json["stateRoot"]), "{name}");
    assert_eq!(receipts_root, root(&json["receiptsRoot"]), "{name}");
    assert_eq!(
        number,
        u64::from_str_radix(
            json["number"].as_str().unwrap().trim_start_matches("0x"),
            16
        )
        .unwrap(),
        "{name}"
    );
    let mut buf = rlp.as_slice();
    let list = alloy_rlp::Header::decode(&mut buf).unwrap();
    let mut count = 0;
    while !buf.is_empty() {
        let item = alloy_rlp::Header::decode(&mut buf).unwrap();
        buf = &buf[item.payload_length..];
        count += 1;
    }
    assert!(list.list);
    assert_eq!(count, fields, "{name}: field count");
    println!("{name}: block {number}, {fields} header fields, anchor fields match");
    rlp
}

#[test]
fn pre_and_post_prague_headers() {
    // Pre-Prague (Cancun, block 22,000,000): 20 fields. Post-Prague (Fulu era): 21 fields.
    check("block-pre-prague.json", 20);
    let rlp = check("block.json", 21);
    // The same RLP as a Gloas anchor preimage.
    let json = block("block.json");
    let header = LightClientHeader::Gloas {
        beacon: BeaconBlockHeader::default(),
        execution_block_hash: root(&json["hash"]),
        execution_branch: vec![],
    };
    let anchor = eth_lc_core::execution::execution_anchor(&header, Some(&rlp)).unwrap();
    assert_eq!(anchor.state_root, root(&json["stateRoot"]));
    let mut wrong = rlp.clone();
    let last = wrong.len() - 1;
    wrong[last] ^= 1;
    assert_eq!(
        eth_lc_core::execution::execution_anchor(&header, Some(&wrong)),
        Err(eth_lc_core::Error::ExecutionHashMismatch)
    );
}
