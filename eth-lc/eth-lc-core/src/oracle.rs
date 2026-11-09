//! Spec transition for host conformance tests (feature `spec-oracle`).
//!
//! The test-only spec store in `eth-lc-host/tests/spec_sync.rs` drives this
//! transition after `validate_light_client_update`, as
//! `process_light_client_update` does. The crate refuses this feature on
//! `target_os = "zkvm"`.

use crate::config::ChainConfig;
use crate::types::{LightClientUpdate, Store};
use crate::Error;

/// `apply_light_client_update` (`specs/altair/light-client/sync-protocol.md`).
/// Writes the store as given; `store.execution` keeps its value.
pub fn apply_light_client_update(
    cfg: &ChainConfig,
    store: &mut Store,
    update: &LightClientUpdate,
) -> Result<(), Error> {
    crate::sync::apply_light_client_update(cfg, store, update)
}
