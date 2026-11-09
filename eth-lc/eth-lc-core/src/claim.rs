//! Claims about execution state and receipts, checked against a header record.
//!
//! Sources: Yellow Paper 4.1 (account state), 4.3 (header), 4.4.1
//! (receipts), App. B (RLP), App. D (trie); EIP-1186 (account and storage
//! proofs); EIP-2718 (typed receipts) with the receipt payloads of EIP-2930,
//! EIP-1559, EIP-4844 and EIP-7702.
//!
//! An [`Attestation`] is plain data. It is a result for the program that
//! ran [`check_claim`]. A consumer that needs authentication re-checks the
//! claim against a store or record it holds itself.

use alloc::vec::Vec;

use alloy_rlp::Encodable;
use borsh::{BorshDeserialize, BorshSerialize};

use crate::config::ChainConfig;
use crate::crypto::keccak256;
use crate::mpt::{self, list_items, Item, EMPTY_TRIE_ROOT};
use crate::types::{Root, Store};
use crate::Error;

/// A finalized execution block as a light-client store records it. Records
/// are keyed by beacon slot: two beacon slots can name the same execution
/// block at Gloas.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct HeaderRecord {
    pub chain_id: u64,
    pub slot: u64,
    pub beacon_root: Root,
    pub block_number: u64,
    pub block_hash: Root,
    pub state_root: Root,
    pub receipts_root: Root,
}

impl HeaderRecord {
    /// The record of `store`'s finalized header.
    pub fn from_store(cfg: &ChainConfig, store: &Store) -> Self {
        Self {
            chain_id: cfg.chain_id,
            slot: store.finalized.slot,
            beacon_root: store.finalized.hash_tree_root(),
            block_number: store.execution.number,
            block_hash: store.execution.block_hash,
            state_root: store.execution.state_root,
            receipts_root: store.execution.receipts_root,
        }
    }
}

/// What a claim is about.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum Subject {
    Account { address: [u8; 20] },
    Storage { address: [u8; 20], key: Root },
    Log { tx_index: u64, log_index: u32 },
}

/// Trie proofs behind a claim.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum Evidence {
    /// EIP-1186 `accountProof`.
    Account {
        address: [u8; 20],
        account_proof: Vec<Vec<u8>>,
    },
    /// EIP-1186 `accountProof` and one `storageProof`.
    Storage {
        address: [u8; 20],
        account_proof: Vec<Vec<u8>>,
        key: Root,
        storage_proof: Vec<Vec<u8>>,
    },
    /// Receipt trie proof for `rlp(tx_index)`, and the log within the receipt.
    ReceiptLog {
        tx_index: u64,
        receipt_proof: Vec<Vec<u8>>,
        log_index: u32,
    },
}

/// A value a condition reads. Integers and addresses are left-padded to 32
/// bytes, big-endian.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Field {
    Nonce,
    Balance,
    StorageRoot,
    CodeHash,
    StorageValue,
    LogAddress,
    LogTopic(u8),
    LogDataWord(u32),
}

/// Comparison of two 32-byte big-endian values.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// `field op value`.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct Condition {
    pub field: Field,
    pub op: Op,
    pub value: Root,
}

/// Evidence and the conditions it must satisfy.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct Claim {
    pub chain_id: u64,
    pub evidence: Evidence,
    pub conditions: Vec<Condition>,
}

/// The result of a successful [`check_claim`]. Unauthenticated: see the
/// module docs.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct Attestation {
    pub record: HeaderRecord,
    pub subject: Subject,
    pub conditions: Vec<Condition>,
}

/// Account fields (Yellow Paper 4.1). Absent accounts read as nonce 0,
/// balance 0, the empty storage root and `keccak256("")` as code hash.
struct Account {
    nonce: Root,
    balance: Root,
    storage_root: Root,
    code_hash: Root,
}

/// A canonical RLP integer (minimal big-endian bytes, at most 32), left-padded.
fn uint(it: &Item) -> Result<Root, Error> {
    let b = it.payload;
    if it.list || b.len() > 32 || b.first() == Some(&0) {
        return Err(Error::InvalidInteger);
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(out)
}

fn bytes32(it: &Item, err: Error) -> Result<Root, Error> {
    if it.list || it.payload.len() != 32 {
        return Err(err);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(it.payload);
    Ok(out)
}

fn account(state_root: &Root, address: &[u8; 20], proof: &[Vec<u8>]) -> Result<Account, Error> {
    match mpt::get(state_root, &keccak256(address), proof)? {
        None => Ok(Account {
            nonce: [0; 32],
            balance: [0; 32],
            storage_root: EMPTY_TRIE_ROOT,
            code_hash: keccak256(&[]),
        }),
        Some(rlp) => {
            let items = list_items(&rlp).map_err(|_| Error::InvalidAccount)?;
            let [n, b, s, c] = items.as_slice() else {
                return Err(Error::InvalidAccount);
            };
            Ok(Account {
                nonce: uint(n)?,
                balance: uint(b)?,
                storage_root: bytes32(s, Error::InvalidAccount)?,
                code_hash: bytes32(c, Error::InvalidAccount)?,
            })
        }
    }
}

fn storage_value(storage_root: &Root, key: &Root, proof: &[Vec<u8>]) -> Result<Root, Error> {
    match mpt::get(storage_root, &keccak256(key), proof)? {
        None => Ok([0; 32]),
        Some(rlp) => {
            let mut buf = rlp.as_slice();
            let it = mpt::item(&mut buf).map_err(|_| Error::InvalidInteger)?;
            if !buf.is_empty() {
                return Err(Error::InvalidInteger);
            }
            uint(&it)
        }
    }
}

/// A log of a receipt: address, topics, data.
struct Log {
    address: [u8; 20],
    topics: Vec<Root>,
    data: Vec<u8>,
}

/// Decodes a receipt trie value: legacy (`>= 0xc0`) or typed `0x01` to
/// `0x04`, each `rlp([status_or_root, cumulative_gas_used, logs_bloom, logs])`.
fn receipt_logs(value: &[u8]) -> Result<Vec<Log>, Error> {
    let body = match value.first() {
        Some(&b) if b >= 0xc0 => value,
        Some(0x01..=0x04) => &value[1..],
        _ => return Err(Error::UnknownReceiptType),
    };
    let bad = |_| Error::InvalidReceipt;
    let items = list_items(body).map_err(bad)?;
    let [status, gas, bloom, logs] = items.as_slice() else {
        return Err(Error::InvalidReceipt);
    };
    if status.list || gas.list || bloom.list || bloom.payload.len() != 256 || !logs.list {
        return Err(Error::InvalidReceipt);
    }
    uint(gas).map_err(|_| Error::InvalidReceipt)?;
    let mut out = Vec::new();
    let mut rest = logs.payload;
    while !rest.is_empty() {
        let log = mpt::item(&mut rest).map_err(bad)?;
        let fields = list_items(log.raw).map_err(bad)?;
        let [addr, topics, data] = fields.as_slice() else {
            return Err(Error::InvalidReceipt);
        };
        if addr.list || addr.payload.len() != 20 || !topics.list || data.list {
            return Err(Error::InvalidReceipt);
        }
        let mut address = [0u8; 20];
        address.copy_from_slice(addr.payload);
        let mut t = Vec::new();
        let mut trest = topics.payload;
        while !trest.is_empty() {
            let topic = mpt::item(&mut trest).map_err(bad)?;
            t.push(bytes32(&topic, Error::InvalidReceipt)?);
        }
        out.push(Log {
            address,
            topics: t,
            data: data.payload.to_vec(),
        });
    }
    Ok(out)
}

fn compare(a: &Root, op: Op, b: &Root) -> bool {
    match op {
        Op::Eq => a == b,
        Op::Ne => a != b,
        Op::Lt => a < b,
        Op::Le => a <= b,
        Op::Gt => a > b,
        Op::Ge => a >= b,
    }
}

/// Checks `claim` against `record` and returns what it proves.
///
/// Rules: chain ids match; account at `keccak256(address)` under the state
/// root; storage at `keccak256(key)` under the account's storage root;
/// receipt at `rlp(tx_index)` under the receipts root. Absent accounts and
/// slots read as zero values; an absent receipt fails. Each condition's field
/// must belong to the evidence kind, and each condition must hold.
pub fn check_claim(record: &HeaderRecord, claim: &Claim) -> Result<Attestation, Error> {
    if claim.chain_id != record.chain_id {
        return Err(Error::ChainIdMismatch);
    }
    let (subject, read): (
        Subject,
        alloc::boxed::Box<dyn Fn(Field) -> Result<Root, Error>>,
    ) = match &claim.evidence {
        Evidence::Account {
            address,
            account_proof,
        } => {
            let a = account(&record.state_root, address, account_proof)?;
            (
                Subject::Account { address: *address },
                alloc::boxed::Box::new(move |f| match f {
                    Field::Nonce => Ok(a.nonce),
                    Field::Balance => Ok(a.balance),
                    Field::StorageRoot => Ok(a.storage_root),
                    Field::CodeHash => Ok(a.code_hash),
                    _ => Err(Error::FieldMismatch),
                }),
            )
        }
        Evidence::Storage {
            address,
            account_proof,
            key,
            storage_proof,
        } => {
            let a = account(&record.state_root, address, account_proof)?;
            let v = storage_value(&a.storage_root, key, storage_proof)?;
            (
                Subject::Storage {
                    address: *address,
                    key: *key,
                },
                alloc::boxed::Box::new(move |f| match f {
                    Field::StorageValue => Ok(v),
                    _ => Err(Error::FieldMismatch),
                }),
            )
        }
        Evidence::ReceiptLog {
            tx_index,
            receipt_proof,
            log_index,
        } => {
            let mut key = Vec::new();
            tx_index.encode(&mut key);
            let value = mpt::get(&record.receipts_root, &key, receipt_proof)?
                .ok_or(Error::ReceiptAbsent)?;
            let mut logs = receipt_logs(&value)?;
            let i = *log_index as usize;
            if i >= logs.len() {
                return Err(Error::OutOfRange);
            }
            let log = logs.swap_remove(i);
            (
                Subject::Log {
                    tx_index: *tx_index,
                    log_index: *log_index,
                },
                alloc::boxed::Box::new(move |f| match f {
                    Field::LogAddress => {
                        let mut out = [0u8; 32];
                        out[12..].copy_from_slice(&log.address);
                        Ok(out)
                    }
                    Field::LogTopic(t) => {
                        log.topics.get(t as usize).copied().ok_or(Error::OutOfRange)
                    }
                    Field::LogDataWord(w) => {
                        let start = (w as usize).checked_mul(32).ok_or(Error::OutOfRange)?;
                        let word = log.data.get(start..start + 32).ok_or(Error::OutOfRange)?;
                        let mut out = [0u8; 32];
                        out.copy_from_slice(word);
                        Ok(out)
                    }
                    _ => Err(Error::FieldMismatch),
                }),
            )
        }
    };
    for c in &claim.conditions {
        if !compare(&read(c.field)?, c.op, &c.value) {
            return Err(Error::ConditionFailed);
        }
    }
    Ok(Attestation {
        record: record.clone(),
        subject,
        conditions: claim.conditions.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::Header;

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

    fn enc<T: Encodable + ?Sized>(v: &T) -> Vec<u8> {
        let mut out = Vec::new();
        v.encode(&mut out);
        out
    }

    fn receipt(logs: Vec<Vec<u8>>) -> Vec<u8> {
        list(&[
            enc(&1u8),
            enc(&21_000u64),
            enc(&[0u8; 256][..]),
            list(&logs),
        ])
    }

    fn log(topics: usize, data: &[u8]) -> Vec<u8> {
        let t: Vec<Vec<u8>> = (0..topics).map(|i| enc(&[i as u8 + 1; 32])).collect();
        list(&[enc(&[7u8; 20][..]), list(&t), enc(data)])
    }

    #[test]
    fn rlp_zero_index_key_is_0x80() {
        assert_eq!(enc(&0u64), [0x80]);
    }

    #[test]
    fn receipt_types() {
        let body = receipt(alloc::vec![log(2, &[9; 64])]);
        assert_eq!(receipt_logs(&body).unwrap().len(), 1);
        for t in 1u8..=4 {
            let mut typed = alloc::vec![t];
            typed.extend(&body);
            assert_eq!(receipt_logs(&typed).unwrap()[0].topics.len(), 2);
        }
        for t in [0u8, 5, 0x7e, 0x80] {
            let mut typed = alloc::vec![t];
            typed.extend(&body);
            assert!(
                matches!(receipt_logs(&typed), Err(Error::UnknownReceiptType)),
                "{t}"
            );
        }
        let mut trailing = body.clone();
        trailing.push(0x80);
        assert!(matches!(
            receipt_logs(&trailing),
            Err(Error::InvalidReceipt)
        ));
        let five = list(&[
            enc(&1u8),
            enc(&21_000u64),
            enc(&[0u8; 256][..]),
            list(&[]),
            enc(&0u8),
        ]);
        assert!(matches!(receipt_logs(&five), Err(Error::InvalidReceipt)));
        let short_bloom = list(&[enc(&1u8), enc(&21_000u64), enc(&[0u8; 255][..]), list(&[])]);
        assert!(matches!(
            receipt_logs(&short_bloom),
            Err(Error::InvalidReceipt)
        ));
    }

    #[test]
    fn integer_rules() {
        let mut buf: &[u8] = &[0x82, 0x00, 0x01];
        let it = mpt::item(&mut buf).unwrap();
        assert_eq!(uint(&it).err(), Some(Error::InvalidInteger));
        let mut buf: &[u8] = &[0x82, 0x01, 0x02];
        let it = mpt::item(&mut buf).unwrap();
        assert_eq!(uint(&it).unwrap()[30..], [1, 2]);
    }

    #[test]
    fn comparisons_are_big_endian() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut big = [0u8; 32];
        big[0] = 1;
        assert!(compare(&one, Op::Lt, &big));
        assert!(compare(&big, Op::Ge, &one));
        assert!(compare(&one, Op::Ne, &big));
        assert!(!compare(&one, Op::Eq, &big));
    }
}
