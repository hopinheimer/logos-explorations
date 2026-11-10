//! The execution block a light-client header anchors.
//!
//! Capella through Fulu: the payload header in the beacon block, verified by
//! the header's execution branch (`specs/capella/light-client/sync-protocol.md`).
//! Gloas variant: the block named by `execution_block_hash`, from its RLP
//! header (Yellow Paper 4.3, App. B) checked by Keccak-256. At a Gloas slot
//! that block is the bid's parent block; at an older slot it is the header's
//! own payload block (`specs/gloas/light-client/sync-protocol.md`, `fork.md`).

use alloy_rlp::{Decodable, Header};

use crate::crypto::keccak256;
use crate::types::{ExecutionAnchor, LightClientHeader, Root};
use crate::Error;

/// Minimum field count of an execution header: the 15 fields of the Yellow
/// Paper header (parent hash through nonce). Later forks append fields.
pub const MIN_HEADER_FIELDS: usize = 15;

/// The anchor of a header that already passed `is_valid_light_client_header`.
/// Gloas-variant headers need `execution_header_rlp`, at any slot; Capella and
/// Deneb variants take none.
pub fn execution_anchor(
    header: &LightClientHeader,
    execution_header_rlp: Option<&[u8]>,
) -> Result<ExecutionAnchor, Error> {
    match (header, execution_header_rlp) {
        (LightClientHeader::Capella { execution: e, .. }, None) => Ok(ExecutionAnchor {
            block_hash: e.block_hash,
            number: e.block_number,
            state_root: e.state_root,
            receipts_root: e.receipts_root,
        }),
        (LightClientHeader::Deneb { execution: e, .. }, None) => Ok(ExecutionAnchor {
            block_hash: e.block_hash,
            number: e.block_number,
            state_root: e.state_root,
            receipts_root: e.receipts_root,
        }),
        (
            LightClientHeader::Gloas {
                execution_block_hash,
                ..
            },
            Some(rlp),
        ) => {
            if keccak256(rlp) != *execution_block_hash {
                return Err(Error::ExecutionHashMismatch);
            }
            let (state_root, receipts_root, number) = header_fields(rlp)?;
            Ok(ExecutionAnchor {
                block_hash: *execution_block_hash,
                number,
                state_root,
                receipts_root,
            })
        }
        (LightClientHeader::Gloas { .. }, None) => Err(Error::MissingExecutionPreimage),
        (_, Some(_)) => Err(Error::UnexpectedExecutionPreimage),
    }
}

/// Reads `stateRoot` (item 3), `receiptsRoot` (item 5) and `number` (item 8)
/// from an RLP execution header: exactly one list spanning all bytes, at least
/// [`MIN_HEADER_FIELDS`] items.
pub fn header_fields(rlp: &[u8]) -> Result<(Root, Root, u64), Error> {
    let bad = |_| Error::InvalidExecutionHeader;
    let mut buf = rlp;
    let list = Header::decode(&mut buf).map_err(bad)?;
    if !list.list || list.payload_length != buf.len() {
        return Err(Error::InvalidExecutionHeader);
    }
    let (mut state_root, mut receipts_root, mut number) = (None, None, None);
    let mut count = 0usize;
    while !buf.is_empty() {
        let mut item = buf;
        match count {
            3 => state_root = Some(<[u8; 32]>::decode(&mut item).map_err(bad)?),
            5 => receipts_root = Some(<[u8; 32]>::decode(&mut item).map_err(bad)?),
            8 => number = Some(u64::decode(&mut item).map_err(bad)?),
            _ => {}
        }
        let h = Header::decode(&mut buf).map_err(bad)?;
        buf = buf
            .get(h.payload_length..)
            .ok_or(Error::InvalidExecutionHeader)?;
        if count == 3 || count == 5 || count == 8 {
            // The typed decode must consume exactly this item.
            if item.len() != buf.len() {
                return Err(Error::InvalidExecutionHeader);
            }
        }
        count += 1;
    }
    match (state_root, receipts_root, number) {
        (Some(s), Some(r), Some(n)) if count >= MIN_HEADER_FIELDS => Ok((s, r, n)),
        _ => Err(Error::InvalidExecutionHeader),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use alloy_rlp::Encodable;

    /// A header-shaped RLP list with `n` fields and distinctive values.
    pub(crate) fn header_rlp(n: usize) -> Vec<u8> {
        let mut items: Vec<Vec<u8>> = Vec::new();
        for i in 0..n {
            let mut out = Vec::new();
            match i {
                3 => [3u8; 32].encode(&mut out),
                5 => [5u8; 32].encode(&mut out),
                8 => 21_000_000u64.encode(&mut out),
                6 => [0u8; 256].encode(&mut out),
                _ => (i as u64).encode(&mut out),
            }
            items.push(out);
        }
        let payload: usize = items.iter().map(Vec::len).sum();
        let mut out = Vec::new();
        Header {
            list: true,
            payload_length: payload,
        }
        .encode(&mut out);
        for i in items {
            out.extend(i);
        }
        out
    }

    #[test]
    fn field_counts() {
        // 15 fields (pre-London shape), 21 (Cancun), 22 (Prague): all accepted.
        for n in [15, 16, 20, 21, 22] {
            assert_eq!(
                header_fields(&header_rlp(n)),
                Ok(([3; 32], [5; 32], 21_000_000)),
                "{n}"
            );
        }
        assert_eq!(
            header_fields(&header_rlp(14)),
            Err(Error::InvalidExecutionHeader)
        );
    }

    #[test]
    fn malformed_headers() {
        let mut trailing = header_rlp(21);
        trailing.push(0x80);
        assert_eq!(header_fields(&trailing), Err(Error::InvalidExecutionHeader));
        let truncated = &header_rlp(21)[..100];
        assert_eq!(header_fields(truncated), Err(Error::InvalidExecutionHeader));
        // A string instead of a list.
        let mut s = Vec::new();
        [1u8; 40].as_slice().encode(&mut s);
        assert_eq!(header_fields(&s), Err(Error::InvalidExecutionHeader));
    }

    #[test]
    fn gloas_anchor_checks_the_preimage() {
        let rlp = header_rlp(21);
        let h = LightClientHeader::Gloas {
            beacon: Default::default(),
            execution_block_hash: keccak256(&rlp),
            execution_branch: Vec::new(),
        };
        let a = execution_anchor(&h, Some(&rlp)).unwrap();
        assert_eq!(
            (a.number, a.state_root, a.receipts_root),
            (21_000_000, [3; 32], [5; 32])
        );
        let mut other = rlp.clone();
        other[10] ^= 1;
        assert_eq!(
            execution_anchor(&h, Some(&other)),
            Err(Error::ExecutionHashMismatch)
        );
        assert_eq!(
            execution_anchor(&h, None),
            Err(Error::MissingExecutionPreimage)
        );
    }
}
