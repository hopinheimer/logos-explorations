//! E1b: the light-client update as a LEZ actor. `Update` runs on a private
//! actor of this program (proven by the submitter); `Advance` runs on the
//! public instance actor and accepts only its own program, on top of the
//! state it holds.
//!
//! Instance state: `borsh((ChainConfig, Store))`. `Update.input` is that
//! state followed by `borsh(UpdateInput)`.
//!
//! A panic aborts the guest, which refuses the message; the `expect` calls
//! below are the refusal paths.

use borsh::{BorshDeserialize, BorshSerialize};
use eth_lc_core::{apply_update, stale_after_ms, ChainConfig, Store, UpdateInput};
use lee_core::{
    account::Actor,
    program::{ReceiveInput, Response},
};

#[derive(BorshSerialize, BorshDeserialize)]
pub enum LcMsg {
    Update { instance: Actor, input: Vec<u8> },
    Advance { prev: Vec<u8>, next: Vec<u8> },
}

fn handle(input: &ReceiveInput) -> Response {
    match borsh::from_slice::<LcMsg>(&input.message).expect("lc message") {
        LcMsg::Update { instance, input } => {
            let mut rest = input.as_slice();
            let (cfg, store) =
                <(ChainConfig, Store)>::deserialize(&mut rest).expect("instance state");
            let prev = input[..input.len() - rest.len()].to_vec();
            let update: UpdateInput = borsh::from_slice(rest).expect("update input");
            let next_store = apply_update(&cfg, &store, &update).expect("the update verifies");
            let next = borsh::to_vec(&(&cfg, &next_store)).expect("state encodes");
            let cfg_len = borsh::to_vec(&cfg).expect("config encodes").len();
            assert_eq!(next[..cfg_len], prev[..cfg_len], "config changed");
            Response::keep_state()
                .send_sync(instance, &LcMsg::Advance { prev, next })
                .timestamp_window(..stale_after_ms(&cfg, &store))
        }
        LcMsg::Advance { prev, next } => {
            assert!(
                input.from_own_program(),
                "advance must come from this program"
            );
            assert_eq!(input.pre_state.as_ref(), prev.as_slice(), "stale store");
            Response::set_state(next)
        }
    }
}

lee_core::actor_entrypoint!(raw handle);
