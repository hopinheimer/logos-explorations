# E1b: cutting the update's cycles in `eth-lc-core`

Three changes to `eth-lc-core` (0.1 to 0.2) take a real mainnet update from about 14.0M to
8.7M private cycles (−37.7%). Proving time falls by 30% and peak memory by 44%. The update
input falls from about 52 KB to about 3.3 KB.

## Where the cycles went

Upstream's guest:
- received the full signing committee, 512 keys, and hashed it to check the committee root;
- received the next committee's 512 keys on a handoff, and hashed those too;
- decompressed the sync aggregate signature, which takes a square root in Fp2;
- checked the signature with blst's `Signature::verify`, which runs the two pairings' Miller
  loops apart.

## What changed

1. **The committee comes as a witness, not 512 keys.** `KeyHints` carries:
   - the root of the committee's keys (`pubkeys_root`);
   - the aggregate key;
   - each non-signer's key, with its branch to that root.

   The guest checks:
   - that the aggregate key and `pubkeys_root` hash to the committee root the store selected;
   - that each non-signer's key lies on its branch.

   This replaces 512 key hashes with one hash for the root plus one per tree level per
   non-signer. `UpdateInput` no longer carries the committee.
2. **The next committee comes as its root.** `LightClientUpdate.next_sync_committee` is
   `Option<(Root, Vec<Root>)>`. The store only ever keeps the root, so the keys aren't needed
   until that committee signs.
3. **Points arrive uncompressed, and the pairing check runs one Miller loop.**
   - Keys arrive as 96 bytes and the signature as 192 (`KeyHints.signature`), so the guest
     takes no square roots. Only the plain uncompressed encoding is accepted, so a point has
     one encoding.
   - The signature hint must compress to the update's committed signature bytes and pass
     the subgroup check, so `SyncAggregate` keeps its spec shape.
   - The check e(−pk, H(m))·e(g1, sig) = 1 runs as one `blst_miller_loop_n` and one final
     exponentiation, in place of `sig.verify`.

Supporting changes:
- `KeyHints::new(committee, bits, signature)` builds the witness.
- `validate_light_client_update` drops its `committee` argument.
- `eth-lc-host`'s `ChainDir` keeps committee keys in `committees`, and `key_hints` and
  `to_core_update` follow the new types.
- The borsh layouts of `LightClientUpdate`, `KeyHints` and `UpdateInput` change, so the
  workspace version moves to 0.2.0, as `borsh_golden.rs` requires.

The trust model is unchanged. A hinted key is on the curve, and its compressed bytes are on
its branch to the keys root. That root, with the aggregate key, hashes to the committee root
the store selected, so the hinted key is the committed key. Committee roots chain by hash to
the trusted checkpoint.

## Results

Same harness (`just e1b`), the same four recorded mainnet steps (periods 1902 to 1905), and
the same machine: Apple M3 Max, 16 cores, 64 GB. LEZ `v0.4.0-rc1`, RISC Zero 3.0.5.

### Dev mode, all steps

| Step | Private cycles, 0.1 | Private cycles, 0.2 | Change | Input, 0.1 → 0.2 |
|---|---:|---:|---:|---|
| 0 | 13,990,140 | 8,714,317 | −37.7% | 52,101 → 3,101 B |
| 1 | 14,058,921 | 8,748,436 | −37.8% | 52,218 → 3,510 B |
| 2 | 13,997,291 | 8,716,828 | −37.7% | 52,138 → 3,138 B |
| 3 | 14,053,528 | 8,748,049 | −37.8% | 52,226 → 3,518 B |

- The public part (`Advance`) is unchanged, at 19,423 to 19,959 cycles.
- The update executed directly, as a sequencer would run it on the public path, takes 181 to
  186 ms, down from 238 to 243 ms.

### Real proof, step 1 (`just e1b-prove 1`)

| | 0.1 | 0.2 | Change |
|---|---:|---:|---:|
| Proving time | 1,107 s | **774 s** | −30.1% |
| Peak memory | 13.1 GB | **7.4 GB** | −44% |
| CPU time (user) | 16,033 s | 8,451 s | −47% |
| Transaction | 228,355 B | 228,355 B | — |

Proving splits into a fixed part, about 233 s for any private transaction, and the update's
own proof. The update's proof fell from about 874 s to about 541 s. The transaction size is
the proof, whose size is fixed.

## Verification

- `just test` (eth-lc): 73 tests pass, the same set as before.
- New mutation cases:
  - a tampered or short non-signer branch;
  - a wrong keys root;
  - a flagged key;
  - another committee's witness;
  - a signature hint off the curve or flagged;
  - another message.
- `just spec-tests` (consensus-specs `v1.7.0-beta.4` light-client vectors, minimal preset):
  - capella, deneb, electra, fulu and gloas all pass;
  - the strict store passes 33 cases;
  - case and step counts are identical to 0.1's.
- `borsh_golden.rs`: only the three intended layouts changed.
- E1: `e1b` steps 0 to 3, `e1b-window` and `e1b-instances` pass, as does eth-lc's
  `consumer-check`.

## Reproduce

```console
cd rfp-021/e1
just e1b 1          # dev mode; steps 0 to 3
just e1b-prove 1    # real proof, about 13 min on the machine above
cd ../../eth-lc
just test
just spec-tests     # downloads the consensus-specs vectors into spec-data/ (16 MB)
```

Logs: `../results/e1b-dev-step{0,1,2,3}.log` and `../results/e1b-prove-step1.log`.

## Files

| Path | Change |
|---|---|
| `eth-lc/eth-lc-core/src/types.rs` | `KeyHints` witness and signature; `UpdateInput` without the committee; next committee as a root |
| `eth-lc/eth-lc-core/src/bls.rs` | `KeyHints::new`; witness check; uncompressed signature; one Miller loop |
| `eth-lc/eth-lc-core/src/sync.rs` | `validate` and `validate_light_client_update` on the witness; next-committee root |
| `eth-lc/eth-lc-core/tests/borsh_golden.rs` | new golden digests for the three layouts |
| `eth-lc/eth-lc-host/src/{chain_dir,forks,hints,synthetic}.rs` | committee keys kept by the host; inputs built with `KeyHints::new` |
| `eth-lc/eth-lc-host/tests/{mainnet,synthetic,spec_sync}.rs` | tests on the new types; new mutation cases |
| `eth-lc/Cargo.toml` | version 0.2.0 |
| `eth-lc/README.md`, `eth-lc/eth-lc-core/README.md` | input and trust-model notes |

## Step 4 (branch `eth-lc-core-residue`): residue check in place of the final exponentiation

The final exponentiation was the largest remaining cost: 3.7M of the 8.7M cycles. It is replaced
by the residue check from Novakovic and Eagen, "On Proving Pairings" (eprint 2024/640):

- **What the guest checks:**
  - the submitter supplies `c` in `Fp12` and `s` in `Fp6` (`KeyHints.residue`,
    `KeyHints.scaling`);
  - the guest checks `f * s = c^λ`, where `f` is the Miller loop output and `λ = p - u`, `u`
    being the BLS12-381 seed;
  - `c^λ = c^p * c^|u|` is one Frobenius map, 63 squarings and 5 multiplications.
- **Why this is sound:**
  - `r` divides `λ` (`p - u = r (u - 1)^2 / 3`), so `c^λ` is an `r`-th power;
  - `p^6 - 1` divides the final exponent, so `s` raised to the final exponent is 1 for any
    nonzero `s` in `Fp6`;
  - together, these give `f^h = 1`, the pairing check.
- **What the guest also requires,** covering the OpenVM CVE-2026-46669 class of bugs:
  - `s` is encoded as an `Fp6` element, so it cannot lie elsewhere in `Fp12`;
  - `c` is nonzero, which rules out the all-zero witness `0 = 0`;
  - every coordinate is canonical.
- **The prover's side** (`residue::witness`, host only, `num-bigint`) follows gnark's
  `finalExpWitness` for BLS12-381. It returns no witness when the pairing check fails.
- **A trap found on the way:** blst's Rust bindings define `blst_fp12::default()` as **one**,
  not zero. A non-zero check written against it accepted the all-zero witness. The forgery test
  caught it, and `residue.rs` uses an explicit zero.

| Step | 0.2 | 0.3 (residue check) | Change | vs 0.1 |
|---|---:|---:|---:|---:|
| 0 | 8,714,317 | 6,201,492 | −28.8% | −55.7% |
| 1 | 8,748,436 | 6,236,056 | −28.7% | −55.6% |
| 2 | 8,716,828 | 6,204,470 | −28.8% | −55.7% |
| 3 | 8,748,049 | 6,235,669 | −28.7% | −55.6% |

Dev mode, same harness. The input grows by 864 B (the witness), to 3,965–4,382 B. The update
executed directly takes 131 to 134 ms.

**Checks:**
- `just test`: 77 tests pass. New cases: a tampered residue or scaling factor, the all-zero
  witness, the trivial `(1, 1)` witness, a non-canonical coordinate, another message's witness,
  and no witness for a failing pairing.
- `just spec-tests`: same case and step counts as before.
- `e1b` steps 0 to 3, `e1b-window`, `e1b-instances` and `consumer-check` pass.
- The borsh layouts of `KeyHints` and `UpdateInput` change, so the version moves to 0.3.0.

**Not done:**
- the machine-checked soundness proof;
- a real proof run on 0.3.
