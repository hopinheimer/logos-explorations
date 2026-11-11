//! Pinned preset and chain identity checks.
//!
//! [`check_profile`] pins the preset exactly: the mainnet preset, or (feature
//! `minimal-profile`) the minimal preset for conformance tests. The chain
//! identity (chain id, genesis, fork schedule) comes from the instance `Init`
//! and passes structural checks only. One program therefore serves any
//! Ethereum-consensus chain of the pinned preset. The operator verifies the
//! identity fields against the chain with
//! `eth_lc_host::checkpoint::verify_instance_config`.
//!
//! Preset values come from `presets/mainnet` and `presets/minimal` at
//! consensus-specs tag `v1.7.0-beta.4`. The constructors
//! [`ChainConfig::mainnet`], [`ChainConfig::sepolia`] and
//! [`ChainConfig::hoodi`] carry values from each chain's Beacon API
//! (`/eth/v1/config/spec`, `/eth/v1/beacon/genesis`); tests cross-check them
//! against the recorded responses in `vectors/<chain>/`.

use alloc::vec::Vec;

use crate::config::{ChainConfig, Fork};
use crate::fork::ForkName;
use crate::types::Root;
use crate::Error;

/// Number of fork entries in every config: phase0 through Gloas.
pub const FORK_COUNT: usize = 8;

/// The preset fields of a [`ChainConfig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preset {
    pub seconds_per_slot: u64,
    pub slots_per_epoch: u64,
    pub epochs_per_sync_committee_period: u64,
    pub sync_committee_size: u32,
}

/// The mainnet preset (`presets/mainnet`, `SECONDS_PER_SLOT` from `configs/mainnet.yaml`).
pub const MAINNET_PRESET: Preset = Preset {
    seconds_per_slot: 12,
    slots_per_epoch: 32,
    epochs_per_sync_committee_period: 256,
    sync_committee_size: 512,
};
const _: () = assert!(MAINNET_PRESET.sync_committee_size % 8 == 0);

/// The minimal preset (`presets/minimal`, `SECONDS_PER_SLOT` from `configs/minimal.yaml`).
#[cfg(feature = "minimal-profile")]
pub const MINIMAL_PRESET: Preset = Preset {
    seconds_per_slot: 6,
    slots_per_epoch: 8,
    epochs_per_sync_committee_period: 8,
    sync_committee_size: 32,
};
#[cfg(feature = "minimal-profile")]
const _: () = assert!(MINIMAL_PRESET.sync_committee_size % 8 == 0);

impl ChainConfig {
    /// The preset fields of this config.
    pub fn preset(&self) -> Preset {
        Preset {
            seconds_per_slot: self.seconds_per_slot,
            slots_per_epoch: self.slots_per_epoch,
            epochs_per_sync_committee_period: self.epochs_per_sync_committee_period,
            sync_committee_size: self.sync_committee_size,
        }
    }

    /// Default `min_participants` of `preset`: two thirds of the committee,
    /// rounded up (342 of 512).
    pub fn default_min_participants(preset: Preset) -> u16 {
        ((2 * preset.sync_committee_size).div_ceil(3)) as u16
    }

    /// Default `weak_subjectivity_period` of `preset`, in seconds: 256 epochs
    /// on mainnet, `MIN_VALIDATOR_WITHDRAWABILITY_DELAY`, the floor of
    /// `compute_weak_subjectivity_period` (`specs/phase0/weak-subjectivity.md`).
    /// The minimal preset takes one sync committee period.
    pub fn default_weak_subjectivity_period(preset: Preset) -> u64 {
        preset.epochs_per_sync_committee_period * preset.slots_per_epoch * preset.seconds_per_slot
    }

    pub(crate) fn with_preset(
        preset: Preset,
        chain_id: u64,
        genesis_validators_root: Root,
        genesis_time: u64,
        forks: Vec<Fork>,
    ) -> Self {
        ChainConfig {
            chain_id,
            genesis_validators_root,
            genesis_time,
            seconds_per_slot: preset.seconds_per_slot,
            slots_per_epoch: preset.slots_per_epoch,
            epochs_per_sync_committee_period: preset.epochs_per_sync_committee_period,
            sync_committee_size: preset.sync_committee_size,
            forks,
            min_participants: Self::default_min_participants(preset),
            weak_subjectivity_period: Self::default_weak_subjectivity_period(preset),
        }
    }

    /// Ethereum mainnet.
    pub fn mainnet() -> Self {
        Self::with_preset(
            MAINNET_PRESET,
            1,
            hex32("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"),
            1_606_824_023,
            schedule(
                [
                    0x00000000, 0x01000000, 0x02000000, 0x03000000, 0x04000000, 0x05000000,
                    0x06000000, 0x07000000,
                ],
                [
                    0,
                    74_240,
                    144_896,
                    194_048,
                    269_568,
                    364_032,
                    411_392,
                    u64::MAX,
                ],
            ),
        )
    }

    /// Sepolia. Gloas is active from epoch 353,024.
    pub fn sepolia() -> Self {
        Self::with_preset(
            MAINNET_PRESET,
            11_155_111,
            hex32("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"),
            1_655_733_600,
            schedule(
                [
                    0x90000069, 0x90000070, 0x90000071, 0x90000072, 0x90000073, 0x90000074,
                    0x90000075, 0x90000076,
                ],
                [0, 50, 100, 56_832, 132_608, 222_464, 272_640, 353_024],
            ),
        )
    }

    /// Hoodi. Gloas is unscheduled.
    pub fn hoodi() -> Self {
        Self::with_preset(
            MAINNET_PRESET,
            560_048,
            hex32("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"),
            1_742_213_400,
            schedule(
                [
                    0x10000910, 0x20000910, 0x30000910, 0x40000910, 0x50000910, 0x60000910,
                    0x70000910, 0x80000910,
                ],
                [0, 0, 0, 0, 0, 2_048, 50_688, u64::MAX],
            ),
        )
    }

    /// A minimal-preset config for conformance tests, with the test case's
    /// genesis validators root and fork epochs. Fork versions follow
    /// `configs/minimal.yaml`.
    #[cfg(feature = "minimal-profile")]
    pub fn minimal(genesis_validators_root: Root, fork_epochs: [u64; FORK_COUNT]) -> Self {
        let versions = core::array::from_fn(|i| u32::from_be_bytes([i as u8, 0, 0, 1]));
        Self::with_preset(
            MINIMAL_PRESET,
            5,
            genesis_validators_root,
            1_578_009_600,
            schedule(versions, fork_epochs),
        )
    }
}

fn hex32(s: &str) -> Root {
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        let byte = &s.as_bytes()[2 * i..2 * i + 2];
        let nib = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            _ => c - b'a' + 10,
        };
        *o = nib(byte[0]) << 4 | nib(byte[1]);
    }
    out
}

fn schedule(versions: [u32; FORK_COUNT], epochs: [u64; FORK_COUNT]) -> Vec<Fork> {
    versions
        .iter()
        .zip(epochs)
        .map(|(v, epoch)| Fork {
            version: v.to_be_bytes(),
            epoch,
        })
        .collect()
}

/// Checks `cfg` before any store transition:
///
/// - Preset: equal to the mainnet preset, or (feature `minimal-profile`) the
///   minimal preset. Otherwise [`Error::PresetMismatch`].
/// - Chain identity, structural only. Otherwise [`Error::InvalidChainIdentity`]:
///   nonzero `chain_id` and `genesis_validators_root`; exactly one fork entry
///   for each fork from phase0 through Gloas; phase0 at epoch 0; epochs
///   non-decreasing; Capella scheduled (its epoch below `u64::MAX`); fork
///   versions pairwise distinct. An unscheduled fork has epoch `u64::MAX`.
/// - Finality parameters, structural only. Otherwise
///   [`Error::InvalidChainIdentity`]: `min_participants` from 1 to
///   `sync_committee_size`; `weak_subjectivity_period` nonzero.
pub fn check_profile(cfg: &ChainConfig) -> Result<(), Error> {
    let preset = cfg.preset();
    #[cfg(feature = "minimal-profile")]
    let preset_ok = preset == MAINNET_PRESET || preset == MINIMAL_PRESET;
    #[cfg(not(feature = "minimal-profile"))]
    let preset_ok = preset == MAINNET_PRESET;
    if !preset_ok {
        return Err(Error::PresetMismatch);
    }
    let f = &cfg.forks;
    let structural = cfg.chain_id != 0
        && cfg.genesis_validators_root != [0; 32]
        && f.len() == FORK_COUNT
        && f[0].epoch == 0
        && f.windows(2).all(|w| w[0].epoch <= w[1].epoch)
        && f[ForkName::Capella as usize].epoch != u64::MAX
        && f.iter()
            .enumerate()
            .all(|(i, a)| f[i + 1..].iter().all(|b| a.version != b.version))
        && cfg.min_participants >= 1
        && u32::from(cfg.min_participants) <= cfg.sync_committee_size
        && cfg.weak_subjectivity_period > 0;
    if structural {
        Ok(())
    } else {
        Err(Error::InvalidChainIdentity)
    }
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

    fn matches_recorded(cfg: &ChainConfig, spec: &str, genesis: &str) {
        assert_eq!(
            api_value(genesis, "genesis_validators_root"),
            hex(&cfg.genesis_validators_root)
        );
        assert_eq!(
            api_value(genesis, "genesis_time"),
            alloc::format!("{}", cfg.genesis_time)
        );
        let fields = [
            ("DEPOSIT_CHAIN_ID", cfg.chain_id),
            ("SECONDS_PER_SLOT", cfg.seconds_per_slot),
            ("SLOTS_PER_EPOCH", cfg.slots_per_epoch),
            (
                "EPOCHS_PER_SYNC_COMMITTEE_PERIOD",
                cfg.epochs_per_sync_committee_period,
            ),
            ("SYNC_COMMITTEE_SIZE", cfg.sync_committee_size as u64),
        ];
        for (key, value) in fields {
            assert_eq!(api_value(spec, key), alloc::format!("{value}"), "{key}");
        }
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
                hex(&fork.version),
                "{name}"
            );
            if *name != "GENESIS" {
                assert_eq!(
                    api_value(spec, &alloc::format!("{name}_FORK_EPOCH")),
                    alloc::format!("{}", fork.epoch),
                    "{name}"
                );
            }
        }
        assert_eq!(check_profile(cfg), Ok(()));
    }

    #[test]
    fn constructors_match_recorded_beacon_api() {
        matches_recorded(
            &ChainConfig::mainnet(),
            include_str!("../../vectors/mainnet/config-spec.json"),
            include_str!("../../vectors/mainnet/genesis.json"),
        );
        matches_recorded(
            &ChainConfig::sepolia(),
            include_str!("../../vectors/sepolia/config-spec.json"),
            include_str!("../../vectors/sepolia/genesis.json"),
        );
        matches_recorded(
            &ChainConfig::hoodi(),
            include_str!("../../vectors/hoodi/config-spec.json"),
            include_str!("../../vectors/hoodi/genesis.json"),
        );
    }

    #[test]
    fn each_preset_deviation_is_refused() {
        let alter: [fn(&mut ChainConfig); 4] = [
            |c| c.seconds_per_slot += 1,
            |c| c.slots_per_epoch += 1,
            |c| c.epochs_per_sync_committee_period += 1,
            |c| c.sync_committee_size += 8,
        ];
        for (i, f) in alter.iter().enumerate() {
            for base in [ChainConfig::mainnet(), ChainConfig::sepolia()] {
                let mut cfg = base;
                f(&mut cfg);
                assert_eq!(check_profile(&cfg), Err(Error::PresetMismatch), "{i}");
            }
        }
    }

    #[test]
    fn identity_is_free_within_the_structure() {
        // Another chain of the same preset passes: identity comes from Init.
        let mut cfg = ChainConfig::sepolia();
        cfg.chain_id = 7;
        cfg.genesis_validators_root = [9; 32];
        cfg.genesis_time = 0;
        cfg.forks[7].epoch = u64::MAX;
        cfg.forks[6].epoch = 400_000;
        cfg.forks[3].version = [0xaa; 4];
        assert_eq!(check_profile(&cfg), Ok(()));
    }

    #[test]
    fn structural_violations_are_refused() {
        let alter: [fn(&mut ChainConfig); 8] = [
            |c| c.chain_id = 0,
            |c| c.genesis_validators_root = [0; 32],
            |c| c.forks[0].epoch = 1,
            |c| c.forks[5].epoch = c.forks[4].epoch - 1,
            |c| c.forks[4].version = c.forks[3].version,
            |c| c.forks[7].version = c.forks[0].version,
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
            let mut cfg = ChainConfig::mainnet();
            f(&mut cfg);
            assert_eq!(
                check_profile(&cfg),
                Err(Error::InvalidChainIdentity),
                "alteration {i}"
            );
        }
        let mut unscheduled = ChainConfig::mainnet();
        unscheduled
            .forks
            .iter_mut()
            .skip(3)
            .for_each(|f| f.epoch = u64::MAX);
        assert_eq!(
            check_profile(&unscheduled),
            Err(Error::InvalidChainIdentity)
        );
    }

    #[cfg(feature = "minimal-profile")]
    #[test]
    fn minimal_preset_rules() {
        let epochs = [0, 0, 0, 0, 0, 0, 0, 3];
        assert_eq!(
            check_profile(&ChainConfig::minimal([1; 32], epochs)),
            Ok(())
        );
        let mut bad = ChainConfig::minimal([1; 32], epochs);
        bad.sync_committee_size = 512;
        assert_eq!(check_profile(&bad), Err(Error::PresetMismatch));
        assert_eq!(
            check_profile(&ChainConfig::minimal([1; 32], [0, 0, 0, 5, 4, 6, 7, 8])),
            Err(Error::InvalidChainIdentity)
        );
        assert_eq!(
            check_profile(&ChainConfig::minimal([1; 32], [1, 1, 1, 1, 1, 1, 1, 1])),
            Err(Error::InvalidChainIdentity)
        );
    }
}
