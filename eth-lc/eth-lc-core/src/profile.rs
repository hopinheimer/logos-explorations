//! Pinned chain profiles. A config passes [`check_profile`] only when it
//! equals one of them, so state bytes carry a known chain.
//!
//! Values come from `configs/mainnet.yaml`, `configs/minimal.yaml` and the
//! presets at consensus-specs tag `v1.7.0-beta.4`, and from the mainnet
//! Beacon API (`/eth/v1/beacon/genesis`).

use alloc::vec::Vec;

use crate::config::{ChainConfig, Fork};
use crate::types::Root;
use crate::Error;

/// Number of fork entries in every profile: phase0 through Gloas.
pub const FORK_COUNT: usize = 8;

const MAINNET_SYNC_COMMITTEE_SIZE: u32 = 512;
const _: () = assert!(MAINNET_SYNC_COMMITTEE_SIZE % 8 == 0);

/// Mainnet `genesis_validators_root`.
pub const MAINNET_GENESIS_VALIDATORS_ROOT: Root = [
    0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd, 0x4e,
    0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b, 0xfe, 0x95,
];

/// Mainnet fork epochs, phase0 through Gloas.
pub const MAINNET_FORK_EPOCHS: [u64; FORK_COUNT] = [
    0,
    74_240,
    144_896,
    194_048,
    269_568,
    364_032,
    411_392,
    u64::MAX,
];

/// The pinned mainnet profile.
pub fn mainnet() -> ChainConfig {
    ChainConfig {
        chain_id: 1,
        genesis_validators_root: MAINNET_GENESIS_VALIDATORS_ROOT,
        genesis_time: 1_606_824_023,
        seconds_per_slot: 12,
        slots_per_epoch: 32,
        epochs_per_sync_committee_period: 256,
        sync_committee_size: MAINNET_SYNC_COMMITTEE_SIZE,
        forks: schedule(0x00, &MAINNET_FORK_EPOCHS),
    }
}

fn schedule(network_byte: u8, epochs: &[u64; FORK_COUNT]) -> Vec<Fork> {
    epochs
        .iter()
        .zip(0u8..)
        .map(|(&epoch, i)| Fork {
            version: [i, 0x00, 0x00, network_byte],
            epoch,
        })
        .collect()
}

#[cfg(feature = "minimal-profile")]
const MINIMAL_SYNC_COMMITTEE_SIZE: u32 = 32;
#[cfg(feature = "minimal-profile")]
const _: () = assert!(MINIMAL_SYNC_COMMITTEE_SIZE % 8 == 0);

/// The minimal-preset profile for conformance tests. Test cases supply the
/// genesis validators root and the fork epochs; everything else is pinned.
#[cfg(feature = "minimal-profile")]
pub fn minimal(genesis_validators_root: Root, fork_epochs: [u64; FORK_COUNT]) -> ChainConfig {
    ChainConfig {
        chain_id: 5,
        genesis_validators_root,
        genesis_time: 1_578_009_600,
        seconds_per_slot: 6,
        slots_per_epoch: 8,
        epochs_per_sync_committee_period: 8,
        sync_committee_size: MINIMAL_SYNC_COMMITTEE_SIZE,
        forks: schedule(0x01, &fork_epochs),
    }
}

/// Checks that `cfg` equals a pinned profile: mainnet, or (feature
/// `minimal-profile`) the minimal profile with a genesis-first,
/// non-decreasing fork schedule.
pub fn check_profile(cfg: &ChainConfig) -> Result<(), Error> {
    if *cfg == mainnet() {
        return Ok(());
    }
    #[cfg(feature = "minimal-profile")]
    if let Some(epochs) = fork_epochs(cfg) {
        if *cfg == minimal(cfg.genesis_validators_root, epochs) {
            return Ok(());
        }
    }
    Err(Error::ProfileMismatch)
}

#[cfg(feature = "minimal-profile")]
fn fork_epochs(cfg: &ChainConfig) -> Option<[u64; FORK_COUNT]> {
    let epochs: [u64; FORK_COUNT] =
        core::array::from_fn(|i| cfg.forks.get(i).map_or(u64::MAX, |f| f.epoch));
    let ordered = epochs[0] == 0 && epochs.windows(2).all(|w| w[0] <= w[1]);
    (cfg.forks.len() == FORK_COUNT && ordered).then_some(epochs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads `"KEY":"value"` from the recorded Beacon API JSON.
    fn api_value<'a>(json: &'a str, key: &str) -> &'a str {
        let pat = alloc::format!("\"{key}\":\"");
        let start = json
            .find(&pat)
            .map(|i| i + pat.len())
            .unwrap_or_else(|| panic!("{key} missing"));
        let end = json[start..].find('"').unwrap() + start;
        &json[start..end]
    }

    fn hex(bytes: &[u8]) -> alloc::string::String {
        let mut s = alloc::string::String::from("0x");
        for b in bytes {
            s.push_str(&alloc::format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn mainnet_matches_recorded_beacon_api() {
        let spec = include_str!("../../vectors/mainnet/config-spec.json");
        let genesis = include_str!("../../vectors/mainnet/genesis.json");
        let cfg = mainnet();
        assert_eq!(
            api_value(genesis, "genesis_validators_root"),
            hex(&cfg.genesis_validators_root)
        );
        assert_eq!(
            api_value(genesis, "genesis_time"),
            alloc::format!("{}", cfg.genesis_time)
        );
        assert_eq!(
            api_value(spec, "DEPOSIT_CHAIN_ID"),
            alloc::format!("{}", cfg.chain_id)
        );
        assert_eq!(
            api_value(spec, "SECONDS_PER_SLOT"),
            alloc::format!("{}", cfg.seconds_per_slot)
        );
        assert_eq!(
            api_value(spec, "SLOTS_PER_EPOCH"),
            alloc::format!("{}", cfg.slots_per_epoch)
        );
        assert_eq!(
            api_value(spec, "EPOCHS_PER_SYNC_COMMITTEE_PERIOD"),
            alloc::format!("{}", cfg.epochs_per_sync_committee_period)
        );
        assert_eq!(
            api_value(spec, "SYNC_COMMITTEE_SIZE"),
            alloc::format!("{}", cfg.sync_committee_size)
        );
        let names = [
            "GENESIS",
            "ALTAIR",
            "BELLATRIX",
            "CAPELLA",
            "DENEB",
            "ELECTRA",
            "FULU",
            "GLOAS",
        ];
        for (name, fork) in names.iter().zip(&cfg.forks) {
            assert_eq!(
                api_value(spec, &alloc::format!("{name}_FORK_VERSION")),
                hex(&fork.version)
            );
            if *name != "GENESIS" {
                assert_eq!(
                    api_value(spec, &alloc::format!("{name}_FORK_EPOCH")),
                    alloc::format!("{}", fork.epoch)
                );
            }
        }
    }

    #[test]
    fn mainnet_passes() {
        assert_eq!(check_profile(&mainnet()), Ok(()));
    }

    #[test]
    fn each_altered_field_is_refused() {
        let alter: [fn(&mut ChainConfig); 12] = [
            |c| c.chain_id += 1,
            |c| c.genesis_validators_root[0] ^= 1,
            |c| c.genesis_time += 1,
            |c| c.seconds_per_slot += 1,
            |c| c.slots_per_epoch += 1,
            |c| c.epochs_per_sync_committee_period += 1,
            |c| c.sync_committee_size += 8,
            |c| c.forks[6].epoch += 1,
            |c| c.forks[7].epoch = 500_000,
            |c| c.forks[3].version[0] ^= 1,
            |c| {
                c.forks.pop();
            },
            |c| {
                c.forks.push(Fork {
                    version: [8, 0, 0, 0],
                    epoch: u64::MAX,
                })
            },
        ];
        for (i, f) in alter.iter().enumerate() {
            let mut cfg = mainnet();
            f(&mut cfg);
            assert_eq!(
                check_profile(&cfg),
                Err(Error::ProfileMismatch),
                "alteration {i}"
            );
        }
    }

    #[cfg(feature = "minimal-profile")]
    #[test]
    fn minimal_profile_rules() {
        let epochs = [0, 0, 0, 0, 0, 0, 0, 3];
        assert_eq!(check_profile(&minimal([1; 32], epochs)), Ok(()));
        let mut bad = minimal([1; 32], epochs);
        bad.sync_committee_size = 512;
        assert_eq!(check_profile(&bad), Err(Error::ProfileMismatch));
        assert_eq!(
            check_profile(&minimal([1; 32], [0, 0, 0, 5, 4, 6, 7, 8])),
            Err(Error::ProfileMismatch)
        );
        assert_eq!(
            check_profile(&minimal([1; 32], [1, 1, 1, 1, 1, 1, 1, 1])),
            Err(Error::ProfileMismatch)
        );
    }
}
