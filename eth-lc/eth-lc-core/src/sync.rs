//! The light-client sync protocol (`specs/altair/light-client/sync-protocol.md`
//! with the Capella, Deneb, Electra and Gloas modifications) and the strict
//! guest entry [`apply_update`].

use crate::bls::{participation, verify_sync_aggregate};
use crate::config::{compute_domain, compute_signing_root, ChainConfig, DOMAIN_SYNC_COMMITTEE};
use crate::execution::execution_anchor;
use crate::fork::{
    current_sync_committee_gindex, execution_gindex, finalized_root_gindex,
    next_sync_committee_gindex, ForkName,
};
use crate::profile::check_profile;
use crate::ssz::is_valid_normalized_merkle_branch;
use crate::types::{
    BootstrapInput, KeyHints, LightClientHeader, LightClientUpdate, Root, Store, SyncCommittee,
    UpdateInput,
};
use crate::Error;

/// `GENESIS_SLOT` (`specs/phase0/beacon-chain.md`).
pub const GENESIS_SLOT: u64 = 0;
/// `MIN_SYNC_COMMITTEE_PARTICIPANTS` (`specs/altair/light-client/sync-protocol.md`).
pub const MIN_SYNC_COMMITTEE_PARTICIPANTS: u32 = 1;

/// `is_valid_light_client_header` (`specs/gloas/light-client/sync-protocol.md`
/// and earlier), with the variant bound to the fork at the header's slot.
fn check_header(cfg: &ChainConfig, header: &LightClientHeader) -> Result<(), Error> {
    let beacon = header.beacon();
    let fork = cfg.fork_at_slot(beacon.slot);
    let gindex = execution_gindex(fork).ok_or(Error::UnsupportedFork)?;
    let leaf = match (fork, header) {
        (ForkName::Capella, LightClientHeader::Capella { execution, .. }) => {
            execution.hash_tree_root()
        }
        (
            ForkName::Deneb | ForkName::Electra | ForkName::Fulu,
            LightClientHeader::Deneb { execution, .. },
        ) => execution.hash_tree_root(),
        (
            ForkName::Gloas,
            LightClientHeader::Gloas {
                execution_block_hash,
                ..
            },
        ) => Some(*execution_block_hash),
        _ => return Err(Error::HeaderVariant),
    }
    .ok_or(Error::InvalidHeader)?;
    if is_valid_normalized_merkle_branch(
        &leaf,
        header.execution_branch(),
        gindex,
        &beacon.body_root,
    ) {
        Ok(())
    } else {
        Err(Error::InvalidHeader)
    }
}

/// `is_valid_light_client_header` (`specs/gloas/light-client/sync-protocol.md`,
/// `specs/deneb/light-client/sync-protocol.md`, `specs/capella/light-client/sync-protocol.md`).
/// Headers before Capella are unsupported and count as invalid.
pub fn is_valid_light_client_header(cfg: &ChainConfig, header: &LightClientHeader) -> bool {
    check_header(cfg, header).is_ok()
}

/// `get_lc_execution_root` (`specs/gloas/light-client/sync-protocol.md`,
/// `specs/deneb/light-client/sync-protocol.md`): the payload-header root
/// (Capella and Deneb layouts) or `execution_block_hash` (Gloas).
pub fn get_lc_execution_root(header: &LightClientHeader) -> Root {
    match header {
        LightClientHeader::Capella { execution, .. } => execution.hash_tree_root(),
        LightClientHeader::Deneb { execution, .. } => execution.hash_tree_root(),
        LightClientHeader::Gloas {
            execution_block_hash,
            ..
        } => Some(*execution_block_hash),
    }
    .unwrap_or_default()
}

/// `initialize_light_client_store` (`specs/altair/light-client/sync-protocol.md`)
/// plus the profile check and the execution anchor of the bootstrap header.
/// This is the only way to anchor a store.
pub fn initialize_store(cfg: &ChainConfig, input: &BootstrapInput) -> Result<Store, Error> {
    check_profile(cfg)?;
    let b = &input.bootstrap;
    check_header(cfg, &b.header)?;
    let beacon = b.header.beacon();
    if beacon.hash_tree_root() != input.trusted_block_root {
        return Err(Error::TrustedRootMismatch);
    }
    check_committee_size(cfg, &b.current_sync_committee)?;
    let committee_root = b.current_sync_committee.hash_tree_root();
    let gindex = current_sync_committee_gindex(cfg.fork_at_slot(beacon.slot));
    if !is_valid_normalized_merkle_branch(
        &committee_root,
        &b.current_sync_committee_branch,
        gindex,
        &beacon.state_root,
    ) {
        return Err(Error::InvalidCurrentCommitteeBranch);
    }
    let execution = execution_anchor(&b.header, input.execution_header_rlp.as_deref())?;
    Ok(Store {
        finalized: beacon.clone(),
        execution,
        current_committee_root: committee_root,
        next_committee_root: None,
    })
}

fn check_committee_size(cfg: &ChainConfig, committee: &SyncCommittee) -> Result<(), Error> {
    if committee.pubkeys.len() == cfg.sync_committee_size as usize {
        Ok(())
    } else {
        Err(Error::CommitteeSize)
    }
}

/// Facts `validate_light_client_update` derives, reused by the callers.
struct Validated {
    participants: u32,
    store_period: u64,
    signature_period: u64,
}

/// `validate_light_client_update` (`specs/altair/light-client/sync-protocol.md`)
/// minus the `current_slot` bound. `committee` must hash to the store root
/// the signature period selects; `hints` bind the signer keys.
fn validate(
    cfg: &ChainConfig,
    store: &Store,
    update: &LightClientUpdate,
    committee: &SyncCommittee,
    hints: &KeyHints,
) -> Result<Validated, Error> {
    // Verify sync committee has sufficient participants.
    let participants = participation(cfg, &update.sync_aggregate.bits)?;
    if participants < MIN_SYNC_COMMITTEE_PARTICIPANTS {
        return Err(Error::TooFewParticipants);
    }

    // Verify update does not skip a sync committee period.
    check_header(cfg, &update.attested_header)?;
    let attested = update.attested_header.beacon();
    let attested_slot = attested.slot;
    let finalized_slot = update.finalized_slot();
    if !(update.signature_slot > attested_slot && attested_slot >= finalized_slot) {
        return Err(Error::SlotOrder);
    }
    let store_period = cfg.period_at_slot(store.finalized.slot);
    let signature_period = cfg.period_at_slot(update.signature_slot);
    let next_known = store.next_committee_root.is_some();
    let period_ok = if next_known {
        signature_period == store_period || signature_period == store_period.saturating_add(1)
    } else {
        signature_period == store_period
    };
    if !period_ok {
        return Err(Error::SignaturePeriod);
    }

    // Verify update is relevant.
    let attested_period = cfg.period_at_slot(attested_slot);
    let has_next =
        !next_known && update.next_sync_committee.is_some() && attested_period == store_period;
    if !(attested_slot > store.finalized.slot || has_next) {
        return Err(Error::NotRelevant);
    }

    // Verify the finality branch against the attested state.
    let attested_fork = cfg.fork_at_slot(attested_slot);
    if let Some((finalized, branch)) = &update.finality {
        let leaf = if finalized_slot == GENESIS_SLOT {
            if !finalized.is_empty() {
                return Err(Error::GenesisHeaderNotEmpty);
            }
            [0u8; 32]
        } else {
            check_header(cfg, finalized)?;
            finalized.beacon().hash_tree_root()
        };
        if !is_valid_normalized_merkle_branch(
            &leaf,
            branch,
            finalized_root_gindex(attested_fork),
            &attested.state_root,
        ) {
            return Err(Error::InvalidFinalityBranch);
        }
    }

    // Verify the next sync committee against the attested state.
    if let Some((next, branch)) = &update.next_sync_committee {
        check_committee_size(cfg, next)?;
        let next_root = next.hash_tree_root();
        if attested_period == store_period {
            if let Some(stored) = store.next_committee_root {
                if stored != next_root {
                    return Err(Error::NextCommitteeMismatch);
                }
            }
        }
        if !is_valid_normalized_merkle_branch(
            &next_root,
            branch,
            next_sync_committee_gindex(attested_fork),
            &attested.state_root,
        ) {
            return Err(Error::InvalidNextCommitteeBranch);
        }
    }

    // Verify the sync committee aggregate signature.
    let selected = if signature_period == store_period {
        Some(store.current_committee_root)
    } else {
        store.next_committee_root
    };
    check_committee_size(cfg, committee)?;
    if selected != Some(committee.hash_tree_root()) {
        return Err(Error::CommitteeMismatch);
    }
    let fork_version_slot = update.signature_slot.saturating_sub(1);
    let fork_version = cfg.fork_version_at_epoch(cfg.compute_epoch_at_slot(fork_version_slot));
    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE,
        fork_version,
        &cfg.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&attested.hash_tree_root(), &domain);
    verify_sync_aggregate(committee, hints, &update.sync_aggregate, &signing_root)?;

    Ok(Validated {
        participants,
        store_period,
        signature_period,
    })
}

/// `validate_light_client_update` (`specs/altair/light-client/sync-protocol.md`),
/// read-only, with the `current_slot` bound. For spec parity tests and
/// off-chain callers.
pub fn validate_light_client_update(
    cfg: &ChainConfig,
    store: &Store,
    update: &LightClientUpdate,
    committee: &SyncCommittee,
    hints: &KeyHints,
    current_slot: u64,
) -> Result<(), Error> {
    if current_slot < update.signature_slot {
        return Err(Error::SlotOrder);
    }
    validate(cfg, store, update, committee, hints).map(|_| ())
}

/// `apply_light_client_update` (`specs/altair/light-client/sync-protocol.md`),
/// on committee roots. The caller must have validated `update`; this
/// function writes the store directly. It leaves
/// `store.execution` to the caller.
pub(crate) fn apply_light_client_update(
    cfg: &ChainConfig,
    store: &mut Store,
    update: &LightClientUpdate,
) -> Result<(), Error> {
    let store_period = cfg.period_at_slot(store.finalized.slot);
    let finalized_period = cfg.period_at_slot(update.finalized_slot());
    let next_root = update
        .next_sync_committee
        .as_ref()
        .map(|(c, _)| c.hash_tree_root());
    match store.next_committee_root {
        None => {
            if finalized_period != store_period {
                return Err(Error::PeriodSkip);
            }
            store.next_committee_root = next_root;
        }
        Some(next) if finalized_period == store_period.saturating_add(1) => {
            store.current_committee_root = next;
            store.next_committee_root = next_root;
        }
        Some(_) => {}
    }
    if let Some((finalized, _)) = &update.finality {
        if finalized.beacon().slot > store.finalized.slot {
            store.finalized = finalized.beacon().clone();
        }
    }
    Ok(())
}

/// The guest entry: a store transition under the strict policy.
///
/// Order: profile check; every check of `validate_light_client_update`
/// except the `current_slot` bound; participation of at least two thirds;
/// finality present; accept rule (a next-committee signature needs a
/// next-period finalized header); progress (a greater finalized slot or
/// `update_has_finalized_next_sync_committee`); the spec transition; the
/// execution anchor when the finalized header changed.
pub fn apply_update(cfg: &ChainConfig, store: &Store, input: &UpdateInput) -> Result<Store, Error> {
    check_profile(cfg)?;
    let update = &input.update;
    let v = validate(cfg, store, update, &input.committee, &input.hints)?;
    if (v.participants as u64) * 3 < (cfg.sync_committee_size as u64) * 2 {
        return Err(Error::NoSupermajority);
    }
    let Some((finalized, _)) = &update.finality else {
        return Err(Error::MissingFinality);
    };
    let finalized_slot = finalized.beacon().slot;
    let finalized_period = cfg.period_at_slot(finalized_slot);
    if v.signature_period != v.store_period && finalized_period != v.store_period.saturating_add(1)
    {
        return Err(Error::AcceptRule);
    }
    let has_finalized_next = store.next_committee_root.is_none()
        && update.next_sync_committee.is_some()
        && finalized_period == cfg.period_at_slot(update.attested_header.beacon().slot);
    let advances = finalized_slot > store.finalized.slot;
    if !(advances || has_finalized_next) {
        return Err(Error::NoProgress);
    }
    let mut next = store.clone();
    apply_light_client_update(cfg, &mut next, update)?;
    if advances {
        next.execution = execution_anchor(finalized, input.execution_header_rlp.as_deref())?;
    } else if input.execution_header_rlp.is_some() {
        return Err(Error::UnexpectedExecutionPreimage);
    }
    Ok(next)
}

/// Liveness bound: the start (Unix ms) of the period two after the store's
/// finalized period. At that time the last period with honest updates for
/// this store has ended and the instance is stalled. Safety is independent of
/// this bound.
pub fn stale_after_ms(cfg: &ChainConfig, store: &Store) -> u64 {
    let period = cfg.period_at_slot(store.finalized.slot);
    cfg.slot_start_ms(cfg.period_start_slot(period.saturating_add(2)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::mainnet;

    #[test]
    fn stale_after_at_period_boundaries() {
        let cfg = mainnet();
        let store = |slot| Store {
            finalized: crate::types::BeaconBlockHeader {
                slot,
                ..Default::default()
            },
            execution: Default::default(),
            current_committee_root: [0; 32],
            next_committee_root: None,
        };
        let period_ms = 8192 * 12 * 1000;
        let genesis_ms = 1_606_824_023_000u64;
        // First and last slot of period 1: stale at the start of period 3.
        assert_eq!(
            stale_after_ms(&cfg, &store(8192)),
            genesis_ms + 3 * period_ms
        );
        assert_eq!(
            stale_after_ms(&cfg, &store(16383)),
            genesis_ms + 3 * period_ms
        );
        // First slot of period 2: stale at the start of period 4.
        assert_eq!(
            stale_after_ms(&cfg, &store(16384)),
            genesis_ms + 4 * period_ms
        );
        assert_eq!(stale_after_ms(&cfg, &store(u64::MAX)), u64::MAX);
    }
}
