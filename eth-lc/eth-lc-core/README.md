# eth-lc-core

Ethereum light-client core for RISC Zero guests. It implements the
consensus-specs light-client sync protocol at tag `v1.7.0-beta.4` for
Capella through Gloas, anchors one execution block per finalized header, and
checks claims about accounts, storage slots and receipt logs against that
anchor.

The crate is `no_std` + `alloc` with `default-features = false`. Guests use
that form.

## API overview

| Item | Use |
|---|---|
| `ChainConfig`, `profile::mainnet()`, `check_profile` | Chain parameters. Only pinned profiles pass. |
| `initialize_store(cfg, &BootstrapInput)` | `initialize_light_client_store` plus the profile check and the execution anchor. The only way to anchor a store. |
| `apply_update(cfg, &store, &UpdateInput)` | Guest entry: one strict store transition. |
| `validate_light_client_update(..., current_slot)` | The full spec check, read-only. For parity tests and off-chain callers. |
| `stale_after_ms(cfg, &store)` | Liveness bound: the time at which the store stalls. |
| `claim::check_claim(&record, &claim)` | Checks account, storage and receipt-log claims against a `HeaderRecord`. |
| `claim::HeaderRecord::from_store(cfg, &store)` | The record of the store's finalized header. |

Inputs carry the full signing committee and `KeyHints` (uncompressed keys of
the committee aggregate and of each non-signer). `eth-lc-host` builds them.

## Trust model

- Safety rests on two inputs: the trusted checkpoint behind `initialize_store`,
  and an honest supermajority of each sync committee the store accepts as
  signer. `initialize_store` and `apply_update` also check the config against a
  pinned profile.
- The LEZ sequencer timestamp is a liveness input only. Safety holds for any timestamp.
- The store accepts an update signed by the next committee only when its
  finalized header is also in the next period. That update rotates the
  committees. This is a stronger assumption than the spec, and it adds a short
  finality gap at each period boundary (about two epochs).
- `apply_update` stores only finalized headers from updates with at least two
  thirds participation and a finality proof.
- A stall is fatal for an instance. Each instance keeps its first anchor for
  life. Recovery is a new instance with a fresh `Init` (see "Stalls and
  migration" in the workspace README).
- Hinted keys skip the per-key subgroup check. A hinted key is on the curve and
  compresses to the committed bytes, so it is the committed key. The committed
  bytes chain by hash to the trusted checkpoint. The participant key must
  differ from the identity point.

## Guest example (LEZ v0.4 actor)

`Init` anchors an empty instance. `Update` runs on a private actor of the
program and sends `Advance` to the public instance. `Attest` checks a claim
against the instance record and emits the attestation.

```rust
use borsh::{BorshDeserialize, BorshSerialize};
use eth_lc_core::claim::{check_claim, Claim, HeaderRecord};
use eth_lc_core::{apply_update, initialize_store, stale_after_ms, BootstrapInput, ChainConfig, Store, UpdateInput};
use lee_core::account::Actor;
use lee_core::program::{ProgramEvent, ReceiveInput, Response};

#[derive(BorshSerialize, BorshDeserialize)]
pub enum LcMsg {
    /// Instance actor: anchors an empty instance. The instance must authorize it.
    Init { cfg: ChainConfig, input: BootstrapInput },
    /// Private actor: `input` is the instance state followed by `borsh(UpdateInput)`.
    Update { instance: Actor, input: Vec<u8> },
    /// Instance actor: replaces its state, only from this program and only on top of `prev`.
    Advance { prev: Vec<u8>, next: Vec<u8> },
    /// Instance actor: checks `claim` against the finalized record and emits the attestation.
    Attest { claim: Claim },
}

/// Event selector: the first 8 bytes of `sha256("eth-lc::Attestation")`.
pub const ATTESTATION: [u8; 8] = [0xa2, 0xbb, 0xb2, 0xad, 0xb0, 0x67, 0xee, 0xcc];

// A panic aborts the guest, which refuses the message: the `expect` calls are the refusal paths.
fn handle(input: &ReceiveInput) -> Response {
    match borsh::from_slice::<LcMsg>(&input.message).expect("lc message") {
        LcMsg::Init { cfg, input: bootstrap } => {
            assert!(input.is_authorized, "init must be authorized");
            assert!(input.pre_state.as_ref().is_empty(), "instance already anchored");
            let store = initialize_store(&cfg, &bootstrap).expect("bootstrap verifies");
            Response::set_state(borsh::to_vec(&(cfg, store)).expect("state encodes"))
        }
        LcMsg::Update { instance, input } => {
            let mut rest = input.as_slice();
            let (cfg, store) = <(ChainConfig, Store)>::deserialize(&mut rest).expect("instance state");
            let prev = input[..input.len() - rest.len()].to_vec();
            let update: UpdateInput = borsh::from_slice(rest).expect("update input");
            let next_store = apply_update(&cfg, &store, &update).expect("the update verifies");
            let next = borsh::to_vec(&(&cfg, &next_store)).expect("state encodes");
            Response::keep_state()
                .send_sync(instance, &LcMsg::Advance { prev, next })
                .timestamp_window(..stale_after_ms(&cfg, &store))
        }
        LcMsg::Advance { prev, next } => {
            assert!(input.from_own_program(), "advance must come from this program");
            assert_eq!(input.pre_state.as_ref(), prev.as_slice(), "stale store");
            Response::set_state(next)
        }
        LcMsg::Attest { claim } => {
            let (cfg, store): (ChainConfig, Store) = borsh::from_slice(input.pre_state.as_ref()).expect("instance state");
            let attestation = check_claim(&HeaderRecord::from_store(&cfg, &store), &claim).expect("claim holds");
            Response::keep_state()
                .event(ProgramEvent { selector: ATTESTATION, data: borsh::to_vec(&attestation).expect("attestation encodes") })
        }
    }
}

lee_core::actor_entrypoint!(raw handle);
```

Notes:

- The `Update` response sets an upper timestamp bound at `stale_after_ms`. LEZ
  then refuses updates on a stale instance. `Attest` leaves its window unbounded, so a
  stalled instance keeps serving claims against the headers it recorded.
- Execution block numbers can repeat at Gloas (two beacon slots can name the
  same parent block). Key header records by beacon slot.

## Claims

- State trie key `keccak256(address)`; storage key `keccak256(key)`; receipt key `rlp(tx_index)`.
- Absent accounts read as nonce 0, balance 0, the empty storage root and
  `keccak256("")`. Absent slots read as 0. An absent receipt fails the claim.
- Receipt types: legacy, `0x01`, `0x02`, `0x03`, `0x04`. Other type bytes fail
  with `Error::UnknownReceiptType`. A later receipt type gets support after its
  EIP text is checked.
- `Attestation` is plain data. It is a result for the program that ran
  `check_claim`. A consumer that needs authentication re-checks the claim
  against a store or record it holds itself.

## Stalls and migration

See the workspace README: a stalled instance stays readable, and recovery is a
new instance anchored at a checkpoint that `eth_lc_host::checkpoint::verify_new_checkpoint` accepts.

## Features

| Feature | Use |
|---|---|
| `std` (default) | `std::error::Error` for `Error`. Guests turn it off. |
| `minimal-profile` | The minimal-preset profile for conformance tests. |
| `spec-oracle` | Exposes the spec transition (`oracle::apply_light_client_update`) to host tests. |

The crate refuses `minimal-profile` and `spec-oracle` on `target_os = "zkvm"`.
