//! The pairing check's final exponentiation, replaced by a residue check
//! (Novakovic and Eagen, "On Proving Pairings", eprint 2024/640).
//!
//! The check holds iff the Miller loop output `f` satisfies `f^h = 1`, with
//! `h = (p^12 - 1) / r`: `f` is an `r`-th power in `Fp12*`. The prover
//! supplies `c` in `Fp12` and `s` in `Fp6` with `f * s = c^λ`, where
//! `λ = p - u = p + |u|` and `u = -0xd201000000010000` is the BLS12-381 seed.
//!
//! Soundness:
//! - `r` divides `λ`, since `p - u = r * (u - 1)^2 / 3`. So `c^λ` is an `r`-th
//!   power, and `(f * s)^h = 1`.
//! - `r` divides `p^6 + 1` (embedding degree 12), so `p^6 - 1` divides `h`,
//!   and `s^h = 1` for every nonzero `s` in `Fp6`. Hence `f^h = 1`.
//! - `s` must lie in `Fp6`. A scaling factor anywhere in `Fp12` would let any
//!   `f` pass; the encoding here only carries an `Fp6` element.
//! - `c` must be nonzero, or `f * 0 = 0^λ` would pass for any `f`.
//!
//! `c^λ = c^p * c^|u|`: one Frobenius map, then 63 squarings and 5
//! multiplications, in place of the final exponentiation.

use blst::{
    blst_bendian_from_fp, blst_fp, blst_fp12, blst_fp12_frobenius_map, blst_fp12_mul,
    blst_fp12_sqr, blst_fp6, blst_fp_from_bendian,
};

/// `|u|`, the absolute value of the BLS12-381 seed `u = -0xd201000000010000`.
pub const SEED_ABS: u64 = 0xd201_0000_0001_0000;

/// Bytes of an `Fp12` element: 12 big-endian `Fp` coordinates in blst's tower order.
pub const FP12_BYTES: usize = 576;
/// Bytes of an `Fp6` element: 6 big-endian `Fp` coordinates.
pub const FP6_BYTES: usize = 288;

/// An `Fp` coordinate, only if canonical (less than `p`).
fn fp(bytes: &[u8]) -> Option<blst_fp> {
    let mut out = blst_fp::default();
    let mut back = [0u8; 48];
    // SAFETY: `bytes` and `back` are 48 bytes, the size blst reads and writes.
    unsafe {
        blst_fp_from_bendian(&mut out, bytes.as_ptr());
        blst_bendian_from_fp(back.as_mut_ptr(), &out);
    }
    (back[..] == bytes[..48]).then_some(out)
}

fn fp6(bytes: &[u8]) -> Option<blst_fp6> {
    let mut out = blst_fp6::default();
    for (i, fp2) in out.fp2.iter_mut().enumerate() {
        for (j, x) in fp2.fp.iter_mut().enumerate() {
            let k = (2 * i + j) * 48;
            *x = fp(&bytes[k..k + 48])?;
        }
    }
    Some(out)
}

/// Decodes an `Fp12` element; `None` unless every coordinate is canonical.
pub fn fp12_from_bytes(bytes: &[u8; FP12_BYTES]) -> Option<blst_fp12> {
    Some(blst_fp12 {
        fp6: [fp6(&bytes[..FP6_BYTES])?, fp6(&bytes[FP6_BYTES..])?],
    })
}

/// Decodes an `Fp6` element as an `Fp12` element (its `w` coefficient zero).
pub fn fp6_from_bytes(bytes: &[u8; FP6_BYTES]) -> Option<blst_fp12> {
    Some(blst_fp12 {
        fp6: [fp6(bytes)?, blst_fp6::default()],
    })
}

fn fp6_bytes(x: &blst_fp6, out: &mut [u8]) {
    for (i, fp2) in x.fp2.iter().enumerate() {
        for (j, c) in fp2.fp.iter().enumerate() {
            let k = (2 * i + j) * 48;
            // SAFETY: the slice is 48 bytes, the size blst writes.
            unsafe { blst_bendian_from_fp(out[k..k + 48].as_mut_ptr(), c) };
        }
    }
}

/// Encodes an `Fp12` element.
pub fn fp12_to_bytes(x: &blst_fp12) -> [u8; FP12_BYTES] {
    let mut out = [0u8; FP12_BYTES];
    fp6_bytes(&x.fp6[0], &mut out[..FP6_BYTES]);
    fp6_bytes(&x.fp6[1], &mut out[FP6_BYTES..]);
    out
}

/// Encodes the `Fp6` part of an `Fp12` element whose `w` coefficient is zero.
pub fn fp6_to_bytes(x: &blst_fp12) -> Option<[u8; FP6_BYTES]> {
    if !is_zero(&blst_fp12 {
        fp6: [x.fp6[1], blst_fp6::default()],
    }) {
        return None;
    }
    let mut out = [0u8; FP6_BYTES];
    fp6_bytes(&x.fp6[0], &mut out);
    Some(out)
}

/// Field equality (blst's `PartialEq` for `blst_fp12`).
fn eq(a: &blst_fp12, b: &blst_fp12) -> bool {
    a == b
}

/// Zero in `Fp12`. Not `blst_fp12::default()`: blst's bindings define that
/// as one (`blst_fp6::default()` is zero).
fn zero() -> blst_fp12 {
    blst_fp12 {
        fp6: [blst_fp6::default(); 2],
    }
}

fn is_zero(x: &blst_fp12) -> bool {
    eq(x, &zero())
}

fn mul(a: &blst_fp12, b: &blst_fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: all pointers are to live `blst_fp12` values.
    unsafe { blst_fp12_mul(&mut out, a, b) };
    out
}

/// `c^λ = c^p * c^|u|`.
fn pow_lambda(c: &blst_fp12) -> blst_fp12 {
    // `|u|` has its top bit set: start from `c` and walk the remaining 63 bits.
    // In place: blst allows the output to alias an input, and copying a
    // 576-byte value per step cost about 100k cycles.
    let mut z = *c;
    let zp: *mut blst_fp12 = &mut z;
    for i in (0..63).rev() {
        // SAFETY: `zp` points to `z`, live for the loop; blst reads its inputs
        // before it writes the output.
        unsafe {
            blst_fp12_sqr(zp, zp);
            if (SEED_ABS >> i) & 1 == 1 {
                blst_fp12_mul(zp, zp, c);
            }
        }
    }
    let mut frob = blst_fp12::default();
    // SAFETY: both pointers are to live `blst_fp12` values.
    unsafe { blst_fp12_frobenius_map(&mut frob, c, 1) };
    mul(&frob, &z)
}

/// Whether the witness `(residue, scaling)` proves `f^h = 1`: `residue` is a
/// nonzero canonical `c` in `Fp12`, `scaling` a canonical `s` in `Fp6`, and
/// `f * s = c^λ`.
pub fn holds(f: &blst_fp12, residue: &[u8; FP12_BYTES], scaling: &[u8; FP6_BYTES]) -> bool {
    let (Some(c), Some(s)) = (fp12_from_bytes(residue), fp6_from_bytes(scaling)) else {
        return false;
    };
    if is_zero(&c) {
        return false;
    }
    eq(&mul(f, &s), &pow_lambda(&c))
}

/// The prover's side: the witness `(c, s)` for a Miller loop output `f` with
/// `f^h = 1`, after gnark's `finalExpWitness` for BLS12-381 (the paper's
/// algorithm). `None` when `f^h != 1`, so no witness exists.
#[cfg(feature = "std")]
pub fn witness(f: &blst_fp12) -> Option<([u8; FP12_BYTES], [u8; FP6_BYTES])> {
    use num_bigint::BigUint;

    // SAFETY: `blst_fp12_one` returns a pointer to a static value.
    let one_fp12 = unsafe { *blst::blst_fp12_one() };
    let pow = |x: &blst_fp12, e: &BigUint| -> blst_fp12 {
        let mut z = one_fp12;
        for byte in e.to_bytes_be() {
            for i in (0..8).rev() {
                let mut sq = blst_fp12::default();
                // SAFETY: both pointers are to live `blst_fp12` values.
                unsafe { blst_fp12_sqr(&mut sq, &z) };
                z = if (byte >> i) & 1 == 1 {
                    mul(&sq, x)
                } else {
                    sq
                };
            }
        }
        z
    };
    let is_one = |x: &blst_fp12| eq(x, &one_fp12);

    let c = Constants::get();
    // 1. Remove the order-`poly` part: `root^e1 = f^(-27 F e1')`.
    let root = pow(f, &(&c.fac * 27u32));
    let root_poly_inv = if is_one(&root) {
        one_fp12
    } else {
        let inv = (&c.fac * 27u32).modinv(&c.poly)?;
        pow(&root, &((&c.poly - inv) % &c.poly))
    };
    // 2. Remove the 3-part, a 27th root of unity.
    let root = pow(f, &(&c.poly * &c.fac));
    let root_27_inv = if is_one(&root) {
        one_fp12
    } else {
        let n27 = BigUint::from(27u32);
        let inv = (&c.poly * &c.fac).modinv(&n27)?;
        pow(&root, &((&n27 - inv) % &n27))
    };
    // 3. `s` shifts `f` into the subgroup of order `F`, where `λ` is invertible.
    let s = mul(&root_poly_inv, &root_27_inv);
    let shifted = mul(f, &s);
    let residue = pow(&shifted, &c.lambda.modinv(&c.fac)?);

    let (residue, scaling) = (fp12_to_bytes(&residue), fp6_to_bytes(&s)?);
    holds(f, &residue, &scaling).then_some((residue, scaling))
}

/// The big exponents the prover needs, from `p`, `r` and `u`.
#[cfg(feature = "std")]
struct Constants {
    /// `(1 - u) / 3`.
    poly: num_bigint::BigUint,
    /// `F = h / (27 * poly)`, with `h = (p^12 - 1) / r`.
    fac: num_bigint::BigUint,
    /// `λ = p - u`.
    lambda: num_bigint::BigUint,
}

#[cfg(feature = "std")]
impl Constants {
    fn get() -> &'static Constants {
        use num_bigint::BigUint;
        static C: std::sync::OnceLock<Constants> = std::sync::OnceLock::new();
        C.get_or_init(|| {
            let hex = |s: &str| BigUint::parse_bytes(s.as_bytes(), 16).expect("hex");
            let p = hex(P_HEX);
            let r = hex(R_HEX);
            let u = BigUint::from(SEED_ABS);
            let h = (p.pow(12) - 1u32) / &r;
            let poly = (&u + 1u32) / 3u32;
            let fac = &h / (&poly * 27u32);
            assert_eq!(&fac * &poly * 27u32, h, "27 * poly divides h");
            Constants {
                poly,
                fac,
                lambda: &p + &u,
            }
        })
    }
}

/// The BLS12-381 base field modulus `p`.
#[cfg(feature = "std")]
pub const P_HEX: &str = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
/// The BLS12-381 group order `r`.
#[cfg(feature = "std")]
pub const R_HEX: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn r_divides_lambda_and_p6_minus_1_divides_h() {
        let hex = |s: &str| BigUint::parse_bytes(s.as_bytes(), 16).unwrap();
        let (p, r, u) = (hex(P_HEX), hex(R_HEX), BigUint::from(SEED_ABS));
        // p - u = r (u - 1)^2 / 3, with u negative: p + |u| = r (|u| + 1)^2 / 3.
        let lambda = &p + &u;
        assert_eq!(&lambda % &r, BigUint::from(0u32));
        assert_eq!(lambda, &r * (&u + 1u32).pow(2) / 3u32);
        let h = (p.pow(12) - 1u32) / &r;
        assert_eq!(&h % (p.pow(6) - 1u32), BigUint::from(0u32));
    }

    #[test]
    fn encodings_round_trip_and_refuse_non_canonical() {
        let mut bytes = [0u8; FP12_BYTES];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = if i % 48 == 0 { 0 } else { i as u8 };
        }
        let x = fp12_from_bytes(&bytes).unwrap();
        assert_eq!(fp12_to_bytes(&x), bytes);
        // A coordinate equal to p is not canonical.
        let p = BigUint::parse_bytes(P_HEX.as_bytes(), 16)
            .unwrap()
            .to_bytes_be();
        bytes[48..96].copy_from_slice(&p);
        assert!(fp12_from_bytes(&bytes).is_none());
    }
}
