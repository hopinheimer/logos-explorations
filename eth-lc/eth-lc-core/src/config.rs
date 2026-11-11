//! Chain configuration and the phase0 / altair helper functions that read it.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::crypto::hash_pair;
use crate::types::Root;

/// `DOMAIN_SYNC_COMMITTEE` (`specs/altair/beacon-chain.md`).
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

/// One entry of the fork schedule: its version and activation epoch.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct Fork {
    pub version: [u8; 4],
    pub epoch: u64,
}

/// The parameters the light client reads: an instance's
/// [`crate::instance::InstanceConfig`] (less its checkpoint) with the pinned
/// preset. Built from that config, never stored. `forks` lists the schedule
/// from genesis (phase0) through Gloas, in order. [`crate::check_profile`]
/// checks it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_validators_root: Root,
    pub genesis_time: u64,
    pub seconds_per_slot: u64,
    pub slots_per_epoch: u64,
    pub epochs_per_sync_committee_period: u64,
    pub sync_committee_size: u32,
    pub forks: Vec<Fork>,
    /// Signers an update needs, of `sync_committee_size`.
    pub min_participants: u16,
    /// Seconds after the store's finalized slot at which updates stop.
    pub weak_subjectivity_period: u64,
}

impl ChainConfig {
    /// `compute_epoch_at_slot` (`specs/phase0/beacon-chain.md`).
    pub fn compute_epoch_at_slot(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    /// `compute_start_slot_at_epoch` (`specs/phase0/beacon-chain.md`), saturating.
    pub fn compute_start_slot_at_epoch(&self, epoch: u64) -> u64 {
        epoch.saturating_mul(self.slots_per_epoch)
    }

    /// `compute_sync_committee_period_at_slot`
    /// (`specs/altair/light-client/sync-protocol.md`).
    pub fn period_at_slot(&self, slot: u64) -> u64 {
        self.compute_epoch_at_slot(slot) / self.epochs_per_sync_committee_period
    }

    /// First slot of sync committee period `period`, saturating.
    pub fn period_start_slot(&self, period: u64) -> u64 {
        self.compute_start_slot_at_epoch(
            period.saturating_mul(self.epochs_per_sync_committee_period),
        )
    }

    /// Index into `forks` of the fork active at `epoch`: the highest entry
    /// with `epoch <= epoch`. Returns 0 for an empty schedule.
    pub fn fork_index_at_epoch(&self, epoch: u64) -> usize {
        self.forks
            .iter()
            .rposition(|f| f.epoch <= epoch)
            .unwrap_or(0)
    }

    /// `compute_fork_version` (`specs/*/fork.md`): the version of the fork
    /// active at `epoch`. An empty schedule yields the zero version.
    pub fn fork_version_at_epoch(&self, epoch: u64) -> [u8; 4] {
        self.forks
            .get(self.fork_index_at_epoch(epoch))
            .map(|f| f.version)
            .unwrap_or_default()
    }

    /// Unix time in milliseconds at the start of `slot`, saturating.
    pub fn slot_start_ms(&self, slot: u64) -> u64 {
        self.genesis_time
            .saturating_add(slot.saturating_mul(self.seconds_per_slot))
            .saturating_mul(1000)
    }
}

/// `compute_fork_data_root` (`specs/phase0/beacon-chain.md`).
pub fn compute_fork_data_root(current_version: [u8; 4], genesis_validators_root: &Root) -> Root {
    let mut version = [0u8; 32];
    version[..4].copy_from_slice(&current_version);
    hash_pair(&version, genesis_validators_root)
}

/// `compute_domain` (`specs/phase0/beacon-chain.md`).
pub fn compute_domain(
    domain_type: [u8; 4],
    fork_version: [u8; 4],
    genesis_validators_root: &Root,
) -> Root {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}

/// `compute_signing_root` (`specs/phase0/beacon-chain.md`): the root of
/// `SigningData { object_root, domain }`.
pub fn compute_signing_root(object_root: &Root, domain: &Root) -> Root {
    hash_pair(object_root, domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ChainConfig;
    fn mainnet() -> ChainConfig {
        ChainConfig::mainnet()
    }

    #[test]
    fn slot_period_math() {
        let cfg = mainnet();
        assert_eq!(cfg.compute_epoch_at_slot(8191), 255);
        assert_eq!(cfg.period_at_slot(8191), 0);
        assert_eq!(cfg.period_at_slot(8192), 1);
        assert_eq!(cfg.period_start_slot(2), 16384);
        assert_eq!(cfg.slot_start_ms(0), 1_606_824_023_000);
        assert_eq!(cfg.slot_start_ms(1), 1_606_824_035_000);
        assert_eq!(cfg.slot_start_ms(u64::MAX), u64::MAX);
    }

    #[test]
    fn fork_versions_at_boundaries() {
        let cfg = mainnet();
        assert_eq!(cfg.fork_version_at_epoch(0), [0, 0, 0, 0]);
        assert_eq!(cfg.fork_version_at_epoch(74_239), [0, 0, 0, 0]);
        assert_eq!(cfg.fork_version_at_epoch(74_240), [1, 0, 0, 0]);
        assert_eq!(cfg.fork_version_at_epoch(411_391), [5, 0, 0, 0]);
        assert_eq!(cfg.fork_version_at_epoch(411_392), [6, 0, 0, 0]);
        assert_eq!(cfg.fork_version_at_epoch(u64::MAX - 1), [6, 0, 0, 0]);
        assert_eq!(cfg.fork_version_at_epoch(u64::MAX), [7, 0, 0, 0]);
    }

    #[test]
    fn domain_layout() {
        let gvr = [7u8; 32];
        let d = compute_domain(DOMAIN_SYNC_COMMITTEE, [6, 0, 0, 0], &gvr);
        assert_eq!(d[..4], DOMAIN_SYNC_COMMITTEE);
        assert_eq!(d[4..], compute_fork_data_root([6, 0, 0, 0], &gvr)[..28]);
    }
}
