//! Execution evidence for `eth_lc_core::claim`: EIP-1186 proofs from
//! `eth_getProof` JSON, and receipt trie proofs built from RPC receipts.

use std::path::Path;

use alloy_primitives::B256;
use alloy_rlp::{Encodable, Header};
use alloy_trie::proof::ProofRetainer;
use alloy_trie::{HashBuilder, Nibbles};
use anyhow::{bail, ensure, Context, Result};
use eth_lc_core::claim::{EthAccount, Proof};
use serde_json::Value;

/// Bytes of a `0x` hex string.
pub fn hex_bytes(v: &Value) -> Result<Vec<u8>> {
    let s = v.as_str().context("expected a hex string")?;
    Ok(hex::decode(s.trim_start_matches("0x"))?)
}

fn hex_array<const N: usize>(v: &Value) -> Result<[u8; N]> {
    let b = hex_bytes(v)?;
    b.try_into()
        .map_err(|_| anyhow::anyhow!("expected {N} bytes"))
}

/// A `0x` hex quantity as u64.
pub fn quantity(v: &Value) -> Result<u64> {
    let s = v.as_str().context("expected a hex quantity")?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

fn nodes(v: &Value) -> Result<Vec<Vec<u8>>> {
    v.as_array()
        .context("expected a proof array")?
        .iter()
        .map(hex_bytes)
        .collect()
}

/// A `0x` hex quantity of up to 32 bytes, left-padded to a 32-byte word.
fn word(v: &Value) -> Result<[u8; 32]> {
    let b = uint_bytes(v)?;
    ensure!(b.len() <= 32, "quantity longer than 32 bytes");
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    Ok(out)
}

/// The account of an `eth_getProof` result. Clients report an absent account
/// with zero `storageHash` and `codeHash`; it maps to [`EthAccount::empty`],
/// the value the core reads for an absent account.
fn eth_account(proof: &Value) -> Result<EthAccount> {
    let zero = [0u8; 32];
    if hex_array::<32>(&proof["storageHash"])? == zero
        && hex_array::<32>(&proof["codeHash"])? == zero
    {
        return Ok(EthAccount::empty());
    }
    Ok(EthAccount {
        nonce: quantity(&proof["nonce"])?,
        balance: word(&proof["balance"])?,
        storage_root: hex_array(&proof["storageHash"])?,
        code_hash: hex_array(&proof["codeHash"])?,
    })
}

/// `Proof::Account` from an `eth_getProof` result.
pub fn account_from_get_proof(proof: &Value) -> Result<Proof> {
    Ok(Proof::Account {
        address: hex_array(&proof["address"])?,
        account: eth_account(proof)?,
        account_proof: nodes(&proof["accountProof"])?,
    })
}

/// `Proof::Storage` for storage proof `i` of an `eth_getProof` result.
pub fn storage_from_proof_value(proof: &Value, i: usize) -> Result<Proof> {
    let sp = &proof["storageProof"][i];
    Ok(Proof::Storage {
        address: hex_array(&proof["address"])?,
        account: eth_account(proof)?,
        account_proof: nodes(&proof["accountProof"])?,
        slot: word(&sp["key"])?,
        value: word(&sp["value"])?,
        storage_proof: nodes(&sp["proof"])?,
    })
}

/// `Proof::Storage` for the first storage proof of a recorded
/// `eth_getProof` result file.
pub fn storage_from_get_proof(path: impl AsRef<Path>) -> Result<Proof> {
    let v: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    storage_from_proof_value(&v, 0)
}

fn enc<T: Encodable + ?Sized>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    v.encode(&mut out);
    out
}

fn list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    Header {
        list: true,
        payload_length: items.iter().map(Vec::len).sum(),
    }
    .encode(&mut out);
    items.iter().for_each(|i| out.extend(i));
    out
}

/// Minimal big-endian bytes of a quantity.
fn uint_bytes(v: &Value) -> Result<Vec<u8>> {
    let s = v
        .as_str()
        .context("expected a hex quantity")?
        .trim_start_matches("0x");
    let padded = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    let b = hex::decode(padded)?;
    Ok(b.into_iter().skip_while(|&x| x == 0).collect())
}

/// Receipt trie value of an RPC receipt (EIP-2718 envelope for typed receipts).
pub fn receipt_encoding(r: &Value) -> Result<Vec<u8>> {
    let ty = quantity(&r["type"])?;
    let status = match r.get("root").filter(|v| !v.is_null()) {
        Some(root) => enc(&hex_bytes(root)?[..]),
        None => enc(&uint_bytes(&r["status"])?[..]),
    };
    let logs: Vec<Vec<u8>> = r["logs"]
        .as_array()
        .context("logs")?
        .iter()
        .map(|l| {
            let topics: Vec<Vec<u8>> = l["topics"]
                .as_array()
                .context("topics")?
                .iter()
                .map(|t| Ok(enc(&hex_bytes(t)?[..])))
                .collect::<Result<_>>()?;
            Ok(list(&[
                enc(&hex_bytes(&l["address"])?[..]),
                list(&topics),
                enc(&hex_bytes(&l["data"])?[..]),
            ]))
        })
        .collect::<Result<_>>()?;
    let full = list(&[
        status,
        enc(&uint_bytes(&r["cumulativeGasUsed"])?[..]),
        enc(&hex_bytes(&r["logsBloom"])?[..]),
        list(&logs),
    ]);
    Ok(match ty {
        0 => full,
        1..=4 => [vec![ty as u8], full].concat(),
        t => bail!("receipt type {t} is outside the supported set"),
    })
}

/// Builds the receipts trie of a block; returns its root and the proof for `tx_index`.
pub fn receipt_proof(receipts: &[Value], tx_index: u64) -> Result<(B256, Vec<Vec<u8>>)> {
    let mut leaves: Vec<(Nibbles, Vec<u8>)> = receipts
        .iter()
        .enumerate()
        .map(|(i, r)| Ok((Nibbles::unpack(enc(&(i as u64))), receipt_encoding(r)?)))
        .collect::<Result<_>>()?;
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    let target = Nibbles::unpack(enc(&tx_index));
    let mut hb =
        HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![target.clone()]));
    for (k, v) in &leaves {
        hb.add_leaf(k.clone(), v);
    }
    let root = hb.root();
    let proof = hb
        .take_proof_nodes()
        .matching_nodes_sorted(&target)
        .into_iter()
        .map(|(_, n)| n.to_vec())
        .collect();
    Ok((root, proof))
}

/// `Proof::Log` for `tx_index` / `log_index` of a block's receipts.
pub fn log_proof(receipts: &[Value], tx_index: u64, log_index: u64) -> Result<(B256, Proof)> {
    let (root, proof) = receipt_proof(receipts, tx_index)?;
    let receipt = receipt_encoding(
        receipts
            .get(tx_index as usize)
            .context("tx_index past the block's receipts")?,
    )?;
    Ok((
        root,
        Proof::Log {
            tx_index,
            receipt,
            proof,
            log_index,
        },
    ))
}
