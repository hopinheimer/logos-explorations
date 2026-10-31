//! E1b: the light-client update as a LEZ actor. `Update` runs on a private
//! actor of this program (proven by the submitter); `Advance` runs on the
//! public instance actor and accepts only its own program, on top of the
//! store it holds.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::Actor,
    program::{ReceiveInput, Response},
};
use sextant_core::{lc, ChainConfig, KeyWitness, Store, SyncCommittee, Update};

#[derive(BorshSerialize, BorshDeserialize)]
pub enum LcMsg {
    Update { instance: Actor, input: Vec<u8> },
    Advance { prev: Vec<u8>, next: Vec<u8> },
}

type Input = (ChainConfig, Store, Update, SyncCommittee, KeyWitness);

fn handle(input: &ReceiveInput) -> Response {
    match borsh::from_slice::<LcMsg>(&input.message).expect("lc message") {
        LcMsg::Update { instance, input } => {
            let (cfg, store, update, committee, witness): Input =
                borsh::from_slice(&input).expect("update input");
            let next = lc::apply_update(&cfg, &store, &update, &committee, &witness, lc::FAST, &mut |_| {})
                .expect("the update verifies");
            Response::keep_state().send_sync(
                instance,
                &LcMsg::Advance {
                    prev: borsh::to_vec(&store).unwrap(),
                    next: borsh::to_vec(&next).unwrap(),
                },
            )
        }
        LcMsg::Advance { prev, next } => {
            assert!(input.from_own_program(), "advance must come from this program");
            assert_eq!(input.pre_state.as_ref(), prev.as_slice(), "stale store");
            Response::set_state(next)
        }
    }
}

lee_core::actor_entrypoint!(raw handle);
