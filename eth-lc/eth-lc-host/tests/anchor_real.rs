//! Execution anchors from recorded mainnet blocks: `alloy-consensus` encodes
//! each RPC header, its Keccak-256 equals the RPC hash, and the core reads
//! the same state root, receipts root and number from that RLP.

use alloy_consensus::Header;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use alloy_rlp::Encodable;
use eth_lc_core::crypto::keccak256;
use eth_lc_core::execution::header_fields;
use eth_lc_core::{BeaconBlockHeader, LightClientHeader};
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

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn q(v: &Value) -> Option<u64> {
    v.as_str()
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
}

fn h(v: &Value) -> Option<B256> {
    v.as_str().map(|_| B256::from_slice(&bytes(v)))
}

/// An `alloy-consensus` header from RPC block JSON.
fn header(j: &Value) -> Header {
    Header {
        parent_hash: h(&j["parentHash"]).unwrap(),
        ommers_hash: h(&j["sha3Uncles"]).unwrap(),
        beneficiary: Address::from_slice(&bytes(&j["miner"])),
        state_root: h(&j["stateRoot"]).unwrap(),
        transactions_root: h(&j["transactionsRoot"]).unwrap(),
        receipts_root: h(&j["receiptsRoot"]).unwrap(),
        logs_bloom: Bloom::from_slice(&bytes(&j["logsBloom"])),
        difficulty: U256::from(q(&j["difficulty"]).unwrap()),
        number: q(&j["number"]).unwrap(),
        gas_limit: q(&j["gasLimit"]).unwrap(),
        gas_used: q(&j["gasUsed"]).unwrap(),
        timestamp: q(&j["timestamp"]).unwrap(),
        extra_data: Bytes::from(bytes(&j["extraData"])),
        mix_hash: h(&j["mixHash"]).unwrap(),
        nonce: B64::from_slice(&bytes(&j["nonce"])),
        base_fee_per_gas: q(&j["baseFeePerGas"]),
        withdrawals_root: h(&j["withdrawalsRoot"]),
        blob_gas_used: q(&j["blobGasUsed"]),
        excess_blob_gas: q(&j["excessBlobGas"]),
        parent_beacon_block_root: h(&j["parentBeaconBlockRoot"]),
        requests_hash: h(&j["requestsHash"]),
        block_access_list_hash: h(&j["blockAccessListHash"]),
        slot_number: q(&j["slotNumber"]),
    }
}

fn check(name: &str, fields: usize) -> Vec<u8> {
    let json = block(name);
    let header = header(&json);
    let mut rlp = Vec::new();
    header.encode(&mut rlp);
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
