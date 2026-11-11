//! Predicates, claims and verified statements (proposal sections 4.5 to 4.7),
//! checked against a [`FinalisedHeader`].
//!
//! Sources: Yellow Paper 4.1 (account state), 4.3 (header), 4.4.1
//! (receipts), App. B (RLP), App. D (trie); EIP-1186 (account and storage
//! proofs); EIP-2718 (typed receipts) with the receipt payloads of EIP-2930,
//! EIP-1559, EIP-4844 and EIP-7702.

use alloc::vec::Vec;

use alloy_rlp::Encodable;
use borsh::{BorshDeserialize, BorshSerialize};

use crate::crypto::{keccak256, sha256};
use crate::instance::{AccountId, FinalisedHeader};
use crate::mpt::{self, list_items, Item, EMPTY_TRIE_ROOT};
use crate::types::Root;
use crate::Error;

/// Section 4.5. `subject op rhs`. `rhs` is a uint, an int (two's
/// complement), an address or a bytes32, as a 32-byte word.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct Condition {
    pub subject: Subject,
    pub op: Op,
    pub rhs: [u8; 32],
}

/// A value of the fact a condition reads, as a 32-byte big-endian word.
/// A subject the fact doesn't carry is refused ([`Error::MalformedInput`]),
/// never read as zero.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Subject {
    AccountBalance,
    AccountNonce,
    AccountCodeHash,
    /// A packed field within the slot: `width` bytes, `offset` bytes from the
    /// low-order end, right-aligned.
    StorageValue {
        offset: u8,
        width: u8,
    },
    LogEmitter,
    LogTopic(u8),
    LogDataWord(u8),
    LogTopicCount,
    LogDataLength,
}

/// Comparison of two 32-byte words, unsigned big-endian. `AtLeast` is `>=`.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Equal,
    NotEqual,
    Less,
    AtMost,
    Greater,
    AtLeast,
}

/// Section 4.6. What the consumer asks: facts proven against one finalised
/// header, all of which must hold.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct Claim {
    /// The chain the consumer expects; refused on another (F.5).
    pub chain_id: u64,
    /// Each proven under the same header; all must hold.
    pub facts: Vec<Fact>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct Fact {
    /// What is proven.
    pub proof: Proof,
    /// What must hold of the values it establishes.
    pub conditions: Vec<Condition>,
}

/// An Ethereum account (Yellow Paper 4.1).
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct EthAccount {
    pub nonce: u64,
    pub balance: Root,
    pub storage_root: Root,
    pub code_hash: Root,
}

impl EthAccount {
    /// An absent account: nonce 0, balance 0, the empty storage root and
    /// `keccak256("")` as code hash.
    pub fn empty() -> Self {
        Self {
            nonce: 0,
            balance: [0; 32],
            storage_root: EMPTY_TRIE_ROOT,
            code_hash: keccak256(&[]),
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum Proof {
    /// Under `receipts_root`: `receipt` at `rlp(tx_index)`, and its log `log_index`.
    Log {
        tx_index: u64,
        receipt: Vec<u8>,
        proof: Vec<Vec<u8>>,
        log_index: u64,
    },
    /// Under `state_root`: `account` at `address`, and `value` at `slot` of its storage.
    Storage {
        address: [u8; 20],
        account: EthAccount,
        account_proof: Vec<Vec<u8>>,
        slot: Root,
        value: Root,
        storage_proof: Vec<Vec<u8>>,
    },
    /// Under `state_root`: `account` at `address`.
    Account {
        address: [u8; 20],
        account: EthAccount,
        account_proof: Vec<Vec<u8>>,
    },
}

/// Section 4.7. A claim that holds.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct Statement {
    /// `instance_id`: the instance whose header was used (F.15).
    pub instance: AccountId,
    /// The chain it is about (F.5).
    pub chain_id: u64,
    /// The block the facts were proven under.
    pub block_number: u64,
    /// One per fact, in the claim's order.
    pub facts: Vec<ProvenFact>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct ProvenFact {
    pub class: Class,
    pub id: Root,
    /// What was asserted of it.
    pub conditions: Vec<Condition>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// Logs: one ID per event, safe as a one-shot nullifier.
    Occurrence,
    /// Storage, account: same state, same ID at any block.
    State,
}

/// Domain tag of fact IDs.
pub const FACT_ID_TAG: &[u8] = b"eth_lc/statement/v1";

/// `SHA-256("eth_lc/statement/v1" ‖ chain_id ‖ kind ‖ fields)`. Integers are
/// big-endian: `chain_id`, `tx_index`, `log_index`, `nonce` and `len(data)`
/// as 8 bytes, `kind` and `n_topics` as 1 byte. Fields per kind:
///
/// - storage (0): `address ‖ slot ‖ value`
/// - log (1): `block_hash ‖ tx_index ‖ log_index ‖ emitter ‖ n_topics ‖ topics ‖ len(data) ‖ data`
/// - account (2): `address ‖ nonce ‖ balance ‖ code_hash`
fn fact_id(chain_id: u64, kind: u8, fields: &[&[u8]]) -> Root {
    let mut buf = Vec::new();
    buf.extend_from_slice(FACT_ID_TAG);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.push(kind);
    fields.iter().for_each(|f| buf.extend_from_slice(f));
    sha256(&buf)
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

/// The account at `address` under `state_root`. An absent account reads as
/// [`EthAccount::empty`].
fn account(state_root: &Root, address: &[u8; 20], proof: &[Vec<u8>]) -> Result<EthAccount, Error> {
    match mpt::get(state_root, &keccak256(address), proof)? {
        None => Ok(EthAccount::empty()),
        Some(rlp) => {
            let items = list_items(&rlp).map_err(|_| Error::InvalidAccount)?;
            let [n, b, s, c] = items.as_slice() else {
                return Err(Error::InvalidAccount);
            };
            let nonce = uint(n)?;
            if nonce[..24] != [0; 24] {
                return Err(Error::InvalidInteger);
            }
            let mut low = [0u8; 8];
            low.copy_from_slice(&nonce[24..]);
            Ok(EthAccount {
                nonce: u64::from_be_bytes(low),
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
/// `0x04`, each `rlp([status, cumulative_gas_used, logs_bloom, logs])`.
/// Returns whether the transaction succeeded (`status` 1) and its logs.
fn receipt(value: &[u8]) -> Result<(bool, Vec<Log>), Error> {
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
    let succeeded = status.payload == [1];
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
    Ok((succeeded, out))
}

fn compare(a: &Root, op: Op, b: &Root) -> bool {
    match op {
        Op::Equal => a == b,
        Op::NotEqual => a != b,
        Op::Less => a < b,
        Op::AtMost => a <= b,
        Op::Greater => a > b,
        Op::AtLeast => a >= b,
    }
}

fn word_of(n: u64) -> Root {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}

fn address_word(a: &[u8; 20]) -> Root {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(a);
    out
}

/// `width` bytes of `value`, `offset` bytes from the low-order end, right-aligned.
fn packed(value: &Root, offset: u8, width: u8) -> Result<Root, Error> {
    let (o, w) = (offset as usize, width as usize);
    if w == 0 || o + w > 32 {
        return Err(Error::MalformedInput);
    }
    let mut out = [0u8; 32];
    out[32 - w..].copy_from_slice(&value[32 - o - w..32 - o]);
    Ok(out)
}

fn account_subject(a: &EthAccount, s: Subject) -> Option<Root> {
    match s {
        Subject::AccountBalance => Some(a.balance),
        Subject::AccountNonce => Some(word_of(a.nonce)),
        Subject::AccountCodeHash => Some(a.code_hash),
        _ => None,
    }
}

fn log_subject(log: &Log, s: Subject) -> Option<Root> {
    match s {
        Subject::LogEmitter => Some(address_word(&log.address)),
        Subject::LogTopic(i) => log.topics.get(i as usize).copied(),
        Subject::LogDataWord(i) => {
            let start = i as usize * 32;
            let word = log.data.get(start..start + 32)?;
            let mut out = [0u8; 32];
            out.copy_from_slice(word);
            Some(out)
        }
        Subject::LogTopicCount => Some(word_of(log.topics.len() as u64)),
        Subject::LogDataLength => Some(word_of(log.data.len() as u64)),
        _ => None,
    }
}

/// Checks one fact under `header` and returns its class, ID and a reader of
/// its subjects.
fn prove(header: &FinalisedHeader, proof: &Proof) -> Result<(Class, Root, Reader), Error> {
    let chain_id = header.chain.chain_id;
    match proof {
        Proof::Account {
            address,
            account: claimed,
            account_proof,
        } => {
            if account(&header.state_root, address, account_proof)? != *claimed {
                return Err(Error::InvalidInclusionProof);
            }
            let id = fact_id(
                chain_id,
                2,
                &[
                    address,
                    &claimed.nonce.to_be_bytes(),
                    &claimed.balance,
                    &claimed.code_hash,
                ],
            );
            Ok((Class::State, id, Reader::Account(claimed.clone(), None)))
        }
        Proof::Storage {
            address,
            account: claimed,
            account_proof,
            slot,
            value,
            storage_proof,
        } => {
            if account(&header.state_root, address, account_proof)? != *claimed
                || storage_value(&claimed.storage_root, slot, storage_proof)? != *value
            {
                return Err(Error::InvalidInclusionProof);
            }
            let id = fact_id(chain_id, 0, &[address, slot, value]);
            Ok((
                Class::State,
                id,
                Reader::Account(claimed.clone(), Some(*value)),
            ))
        }
        Proof::Log {
            tx_index,
            receipt: claimed,
            proof,
            log_index,
        } => {
            let mut key = Vec::new();
            tx_index.encode(&mut key);
            let value =
                mpt::get(&header.receipts_root, &key, proof)?.ok_or(Error::ReceiptAbsent)?;
            if value != *claimed {
                return Err(Error::InvalidInclusionProof);
            }
            let (succeeded, mut logs) = receipt(&value)?;
            if !succeeded {
                return Err(Error::ConditionUnsatisfied);
            }
            let i = usize::try_from(*log_index).map_err(|_| Error::MalformedInput)?;
            if i >= logs.len() {
                return Err(Error::MalformedInput);
            }
            let log = logs.swap_remove(i);
            let topics: Vec<u8> = log.topics.iter().flatten().copied().collect();
            let id = fact_id(
                chain_id,
                1,
                &[
                    &header.block_hash,
                    &tx_index.to_be_bytes(),
                    &log_index.to_be_bytes(),
                    &log.address,
                    &[log.topics.len() as u8],
                    &topics,
                    &(log.data.len() as u64).to_be_bytes(),
                    &log.data,
                ],
            );
            Ok((Class::Occurrence, id, Reader::Log(log)))
        }
    }
}

/// The values one fact establishes.
enum Reader {
    /// An account, and the storage value when the fact is a storage fact.
    Account(EthAccount, Option<Root>),
    Log(Log),
}

impl Reader {
    fn read(&self, s: Subject) -> Result<Root, Error> {
        match (self, s) {
            (Reader::Account(_, Some(v)), Subject::StorageValue { offset, width }) => {
                packed(v, offset, width)
            }
            (Reader::Account(a, _), s) => account_subject(a, s).ok_or(Error::MalformedInput),
            (Reader::Log(l), s) => log_subject(l, s).ok_or(Error::MalformedInput),
        }
    }
}

/// Checks `claim` against `header` and returns the statement it proves.
///
/// Rules: chain ids match ([`Error::ChainIdMismatch`]); at least one fact
/// ([`Error::MalformedInput`]); each proof's claimed values equal what its
/// trie proof shows ([`Error::InvalidInclusionProof`]): the account at
/// `keccak256(address)` under the state root (absent reads as
/// [`EthAccount::empty`]), the storage value at `keccak256(slot)` under the
/// account's storage root (absent reads as zero), the receipt at
/// `rlp(tx_index)` under the receipts root (absent fails); a log of a
/// reverted transaction proves nothing ([`Error::ConditionUnsatisfied`]);
/// every condition reads a subject its fact carries and holds.
pub fn check_claim(header: &FinalisedHeader, claim: &Claim) -> Result<Statement, Error> {
    if claim.chain_id != header.chain.chain_id {
        return Err(Error::ChainIdMismatch);
    }
    if claim.facts.is_empty() {
        return Err(Error::MalformedInput);
    }
    let mut facts = Vec::with_capacity(claim.facts.len());
    for fact in &claim.facts {
        let (class, id, reader) = prove(header, &fact.proof)?;
        for c in &fact.conditions {
            if !compare(&reader.read(c.subject)?, c.op, &c.rhs) {
                return Err(Error::ConditionUnsatisfied);
            }
        }
        facts.push(ProvenFact {
            class,
            id,
            conditions: fact.conditions.clone(),
        });
    }
    Ok(Statement {
        instance: header.instance,
        chain_id: header.chain.chain_id,
        block_number: header.block_number,
        facts,
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

    fn receipt_rlp(logs: Vec<Vec<u8>>) -> Vec<u8> {
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
        let body = receipt_rlp(alloc::vec![log(2, &[9; 64])]);
        assert_eq!(receipt(&body).unwrap().1.len(), 1);
        for t in 1u8..=4 {
            let mut typed = alloc::vec![t];
            typed.extend(&body);
            assert_eq!(receipt(&typed).unwrap().1[0].topics.len(), 2);
        }
        for t in [0u8, 5, 0x7e, 0x80] {
            let mut typed = alloc::vec![t];
            typed.extend(&body);
            assert!(
                matches!(receipt(&typed), Err(Error::UnknownReceiptType)),
                "{t}"
            );
        }
        let mut trailing = body.clone();
        trailing.push(0x80);
        assert!(matches!(receipt(&trailing), Err(Error::InvalidReceipt)));
        let five = list(&[
            enc(&1u8),
            enc(&21_000u64),
            enc(&[0u8; 256][..]),
            list(&[]),
            enc(&0u8),
        ]);
        assert!(matches!(receipt(&five), Err(Error::InvalidReceipt)));
        let short_bloom = list(&[enc(&1u8), enc(&21_000u64), enc(&[0u8; 255][..]), list(&[])]);
        assert!(matches!(receipt(&short_bloom), Err(Error::InvalidReceipt)));
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
        assert!(compare(&one, Op::Less, &big));
        assert!(compare(&big, Op::AtLeast, &one));
        assert!(compare(&one, Op::NotEqual, &big));
        assert!(!compare(&one, Op::Equal, &big));
    }

    #[test]
    fn packed_fields() {
        let mut v = [0u8; 32];
        v[31] = 0xaa;
        v[30] = 0xbb;
        v[29] = 0xcc;
        assert_eq!(packed(&v, 0, 1).unwrap()[31], 0xaa);
        let two = packed(&v, 1, 2).unwrap();
        assert_eq!(two[30..], [0xcc, 0xbb]);
        assert_eq!(two[..30], [0; 30]);
        assert_eq!(packed(&v, 0, 32).unwrap(), v);
        assert_eq!(packed(&v, 1, 32), Err(Error::MalformedInput));
        assert_eq!(packed(&v, 0, 0), Err(Error::MalformedInput));
    }

    #[test]
    fn reverted_status_reads_as_failed() {
        let ok = receipt_rlp(alloc::vec![]);
        assert!(receipt(&ok).unwrap().0);
        let failed = list(&[enc(&0u8), enc(&21_000u64), enc(&[0u8; 256][..]), list(&[])]);
        assert!(!receipt(&failed).unwrap().0);
    }
}
