//! Execution headers from JSON-RPC: the RLP preimage that the anchor of a
//! Gloas-variant header needs (`eth_lc_core::execution::execution_anchor`).

use alloy_consensus::Header;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use alloy_rlp::Encodable;
use anyhow::{ensure, Context, Result};
use eth_lc_core::crypto::keccak256;
use eth_lc_core::Root;
use serde_json::{json, Value};

use crate::evidence::{hex_bytes, quantity};
use crate::http::rpc;

fn hash(v: &Value) -> Result<B256> {
    let b = hex_bytes(v)?;
    ensure!(b.len() == 32, "expected 32 bytes");
    Ok(B256::from_slice(&b))
}

/// An optional field: absent or `null` reads as `None`.
fn opt<T>(v: &Value, f: impl Fn(&Value) -> Result<T>) -> Result<Option<T>> {
    match v {
        Value::Null => Ok(None),
        v => f(v).map(Some),
    }
}

/// An `alloy-consensus` header from an RPC block object
/// (`eth_getBlockByHash`, `eth_getBlockByNumber`).
pub fn header_from_rpc(j: &Value) -> Result<Header> {
    let difficulty = j["difficulty"].as_str().context("difficulty")?;
    Ok(Header {
        parent_hash: hash(&j["parentHash"]).context("parentHash")?,
        ommers_hash: hash(&j["sha3Uncles"]).context("sha3Uncles")?,
        beneficiary: Address::from_slice(&hex_bytes(&j["miner"]).context("miner")?),
        state_root: hash(&j["stateRoot"]).context("stateRoot")?,
        transactions_root: hash(&j["transactionsRoot"]).context("transactionsRoot")?,
        receipts_root: hash(&j["receiptsRoot"]).context("receiptsRoot")?,
        logs_bloom: Bloom::from_slice(&hex_bytes(&j["logsBloom"]).context("logsBloom")?),
        difficulty: U256::from_str_radix(difficulty.trim_start_matches("0x"), 16)?,
        number: quantity(&j["number"]).context("number")?,
        gas_limit: quantity(&j["gasLimit"]).context("gasLimit")?,
        gas_used: quantity(&j["gasUsed"]).context("gasUsed")?,
        timestamp: quantity(&j["timestamp"]).context("timestamp")?,
        extra_data: Bytes::from(hex_bytes(&j["extraData"]).context("extraData")?),
        mix_hash: hash(&j["mixHash"]).context("mixHash")?,
        nonce: B64::from_slice(&hex_bytes(&j["nonce"]).context("nonce")?),
        base_fee_per_gas: opt(&j["baseFeePerGas"], quantity)?,
        withdrawals_root: opt(&j["withdrawalsRoot"], hash)?,
        blob_gas_used: opt(&j["blobGasUsed"], quantity)?,
        excess_blob_gas: opt(&j["excessBlobGas"], quantity)?,
        parent_beacon_block_root: opt(&j["parentBeaconBlockRoot"], hash)?,
        requests_hash: opt(&j["requestsHash"], hash)?,
        block_access_list_hash: opt(&j["blockAccessListHash"], hash)?,
        slot_number: opt(&j["slotNumber"], quantity)?,
    })
}

/// The RLP header of an RPC block object. Fails unless its Keccak-256
/// equals the block's `hash`.
pub fn header_rlp_from_rpc(j: &Value) -> Result<Vec<u8>> {
    let mut rlp = Vec::new();
    header_from_rpc(j)?.encode(&mut rlp);
    let want = hash(&j["hash"]).context("hash")?;
    ensure!(
        keccak256(&rlp) == want.0,
        "RLP header of block {want} hashes to another value"
    );
    Ok(rlp)
}

/// The RLP header of the execution block `block_hash`, from
/// `eth_getBlockByHash` at `rpc_url`, checked by Keccak-256.
pub fn fetch_header_rlp(rpc_url: &str, block_hash: Root) -> Result<Vec<u8>> {
    let hex = format!("0x{}", hex::encode(block_hash));
    let block = rpc(rpc_url, "eth_getBlockByHash", json!([hex, false]))?;
    ensure!(!block.is_null(), "block {hex} unknown at {rpc_url}");
    let rlp = header_rlp_from_rpc(&block)?;
    ensure!(
        keccak256(&rlp) == block_hash,
        "{rpc_url} served another block for {hex}"
    );
    Ok(rlp)
}
