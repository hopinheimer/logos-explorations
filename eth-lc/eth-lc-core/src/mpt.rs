//! Merkle-Patricia trie proof walker (Yellow Paper App. D; proof format of
//! EIP-1186: the RLP nodes on the path from the root, in order).
//!
//! The walker proves inclusion (returns the value) and exclusion (returns
//! `None`) from an empty branch slot, a diverging leaf or a diverging
//! extension. An empty proof, or the single empty node `0x80`, proves
//! exclusion only under the empty-trie root.

use alloc::vec::Vec;

use alloy_rlp::Header;

use crate::crypto::keccak256;
use crate::types::Root;
use crate::Error;

/// `keccak256(rlp(""))`, the root of the empty trie.
pub const EMPTY_TRIE_ROOT: Root = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// One RLP item: list flag, payload and the full encoding.
#[derive(Clone, Copy)]
pub(crate) struct Item<'a> {
    pub list: bool,
    pub payload: &'a [u8],
    pub raw: &'a [u8],
}

/// Decodes one RLP item from the front of `buf`.
pub(crate) fn item<'a>(buf: &mut &'a [u8]) -> Result<Item<'a>, alloy_rlp::Error> {
    let start = *buf;
    let h = Header::decode(buf)?;
    if buf.len() < h.payload_length {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    let (payload, rest) = buf.split_at(h.payload_length);
    *buf = rest;
    Ok(Item {
        list: h.list,
        payload,
        raw: &start[..start.len() - rest.len()],
    })
}

/// Items of the RLP list that is exactly `data`.
pub(crate) fn list_items(data: &[u8]) -> Result<Vec<Item<'_>>, alloy_rlp::Error> {
    let mut buf = data;
    let outer = item(&mut buf)?;
    if !outer.list || !buf.is_empty() {
        return Err(alloy_rlp::Error::UnexpectedString);
    }
    let mut inner = outer.payload;
    let mut out = Vec::new();
    while !inner.is_empty() {
        out.push(item(&mut inner)?);
    }
    Ok(out)
}

/// Reference to a child node: by hash, or embedded (RLP shorter than 32 bytes).
enum Child<'a> {
    Hash(Root),
    Inline(&'a [u8]),
}

fn child<'a>(it: &Item<'a>) -> Result<Option<Child<'a>>, Error> {
    match (it.list, it.payload.len()) {
        (false, 0) => Ok(None),
        (false, 32) => {
            let mut h = [0u8; 32];
            h.copy_from_slice(it.payload);
            Ok(Some(Child::Hash(h)))
        }
        (true, _) if it.raw.len() < 32 => Ok(Some(Child::Inline(it.raw))),
        _ => Err(Error::InvalidProof),
    }
}

fn nibbles(key: &[u8]) -> Vec<u8> {
    key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

/// Hex-prefix decoding (Yellow Paper App. C): `(is_leaf, path nibbles)`.
fn hex_prefix(encoded: &[u8]) -> Result<(bool, Vec<u8>), Error> {
    let first = *encoded.first().ok_or(Error::InvalidProof)?;
    let flag = first >> 4;
    if flag > 3 {
        return Err(Error::InvalidProof);
    }
    let mut path = Vec::new();
    if flag & 1 == 1 {
        path.push(first & 0x0f);
    } else if first & 0x0f != 0 {
        return Err(Error::InvalidProof);
    }
    path.extend(nibbles(&encoded[1..]));
    Ok((flag >= 2, path))
}

/// Walks `proof` from `root` along `key`. Returns the stored value, or
/// `None` when the proof shows the key is absent. Every proof node must be
/// used, in order. Embedded nodes may appear as their own entries or only
/// inside their parent.
pub fn get(root: &Root, key: &[u8], proof: &[Vec<u8>]) -> Result<Option<Vec<u8>>, Error> {
    if proof.is_empty() {
        return if *root == EMPTY_TRIE_ROOT {
            Ok(None)
        } else {
            Err(Error::InvalidProof)
        };
    }
    let path = nibbles(key);
    let mut pos = 0usize;
    let mut nodes = proof.iter().peekable();
    let mut next = Child::Hash(*root);
    loop {
        let node: &[u8] = match next {
            Child::Hash(h) => {
                let n = nodes.next().ok_or(Error::InvalidProof)?;
                if keccak256(n) != h {
                    return Err(Error::InvalidProof);
                }
                n
            }
            Child::Inline(raw) => {
                // Some provers also list embedded nodes as proof entries; consume such a copy.
                if nodes.peek().is_some_and(|n| n.as_slice() == raw) {
                    nodes.next();
                }
                raw
            }
        };
        if node == [0x80] {
            // The empty node: only the empty trie hashes to it.
            return if nodes.next().is_none() {
                Ok(None)
            } else {
                Err(Error::InvalidProof)
            };
        }
        let items = list_items(node).map_err(|_| Error::InvalidProof)?;
        let outcome: Result<Option<Vec<u8>>, Child> = match items.len() {
            17 => {
                if pos == path.len() {
                    let v = &items[16];
                    if v.list {
                        return Err(Error::InvalidProof);
                    }
                    Ok((!v.payload.is_empty()).then(|| v.payload.to_vec()))
                } else {
                    let slot = &items[path[pos] as usize];
                    pos += 1;
                    match child(slot)? {
                        None => Ok(None),
                        Some(c) => Err(c),
                    }
                }
            }
            2 => {
                if items[0].list {
                    return Err(Error::InvalidProof);
                }
                let (leaf, segment) = hex_prefix(items[0].payload)?;
                let rest = &path[pos..];
                if leaf {
                    if items[1].list {
                        return Err(Error::InvalidProof);
                    }
                    Ok((rest == segment.as_slice()).then(|| items[1].payload.to_vec()))
                } else if segment.is_empty() {
                    return Err(Error::InvalidProof);
                } else if rest.starts_with(&segment) {
                    pos += segment.len();
                    match child(&items[1])? {
                        Some(c) => Err(c),
                        None => return Err(Error::InvalidProof),
                    }
                } else {
                    Ok(None)
                }
            }
            _ => return Err(Error::InvalidProof),
        };
        match outcome {
            Ok(value) => {
                // The walk ended: every proof node must have been used.
                return if nodes.next().is_none() {
                    Ok(value)
                } else {
                    Err(Error::InvalidProof)
                };
            }
            Err(c) => next = c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trie_root_is_keccak_of_empty_string() {
        assert_eq!(keccak256(&[0x80]), EMPTY_TRIE_ROOT);
    }

    #[test]
    fn empty_proof_rules() {
        assert_eq!(get(&EMPTY_TRIE_ROOT, &[1, 2], &[]), Ok(None));
        assert_eq!(get(&[1; 32], &[1, 2], &[]), Err(Error::InvalidProof));
    }

    /// RLP of a single-leaf trie node for `key` (full path) and `value`.
    fn leaf(key: &[u8], value: &[u8]) -> Vec<u8> {
        use alloy_rlp::Encodable;
        let mut path = alloc::vec![0x20u8];
        path.extend_from_slice(key);
        let mut payload = Vec::new();
        path.as_slice().encode(&mut payload);
        value.encode(&mut payload);
        let mut out = Vec::new();
        Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut out);
        out.extend(payload);
        out
    }

    #[test]
    fn single_leaf_inclusion_and_divergence() {
        let key = [0xabu8; 32];
        let node = leaf(&key, b"value-bytes-long-enough");
        let root = keccak256(&node);
        assert_eq!(
            get(&root, &key, &[node.clone()]),
            Ok(Some(b"value-bytes-long-enough".to_vec()))
        );
        // Diverging leaf: absence.
        assert_eq!(get(&root, &[0xac; 32], &[node.clone()]), Ok(None));
        // Altered node: hash mismatch.
        let mut bad = node.clone();
        bad[5] ^= 1;
        assert_eq!(get(&root, &key, &[bad]), Err(Error::InvalidProof));
        // Extra trailing node.
        assert_eq!(
            get(&root, &key, &[node.clone(), node]),
            Err(Error::InvalidProof)
        );
    }
}
