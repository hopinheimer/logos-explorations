//! Hash functions. This module is the sole user of the `sha2` and
//! `tiny-keccak` forks, so the accelerated paths apply everywhere.

use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use crate::types::Root;

/// SHA-256 of `data` (the `hash` function of `ssz/simple-serialize.md`).
pub fn sha256(data: &[u8]) -> Root {
    Sha256::digest(data).into()
}

/// SHA-256 of `a || b`, the Merkle node function.
pub fn hash_pair(a: &Root, b: &Root) -> Root {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// Keccak-256 of `data` (Yellow Paper, `KEC`).
pub fn keccak256(data: &[u8]) -> Root {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digests() {
        // FIPS 180-2 example "abc".
        assert_eq!(sha256(b"abc")[..4], [0xba, 0x78, 0x16, 0xbf]);
        // keccak256("") is the empty code hash.
        assert_eq!(keccak256(b"")[..4], [0xc5, 0xd2, 0x46, 0x01]);
    }
}
