//! Fork by epoch and the generalized-index tables of the light-client specs.

use crate::config::ChainConfig;

/// Forks in schedule order. The index equals the position in `ChainConfig::forks`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ForkName {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
    Gloas,
}

impl ForkName {
    /// Forks in schedule order.
    pub const ALL: [ForkName; 8] = [
        ForkName::Phase0,
        ForkName::Altair,
        ForkName::Bellatrix,
        ForkName::Capella,
        ForkName::Deneb,
        ForkName::Electra,
        ForkName::Fulu,
        ForkName::Gloas,
    ];
}

impl ChainConfig {
    /// The fork active at `epoch`. Schedule entries past Gloas count as Gloas.
    pub fn fork_at_epoch(&self, epoch: u64) -> ForkName {
        let i = self.fork_index_at_epoch(epoch).min(ForkName::ALL.len() - 1);
        ForkName::ALL[i]
    }

    /// The fork active at `slot`.
    pub fn fork_at_slot(&self, slot: u64) -> ForkName {
        self.fork_at_epoch(self.compute_epoch_at_slot(slot))
    }
}

/// `finalized_root_gindex_at_slot`, by the fork of that slot
/// (`specs/gloas/light-client/sync-protocol.md`).
pub fn finalized_root_gindex(fork: ForkName) -> u64 {
    match fork {
        ForkName::Gloas => 735,
        ForkName::Electra | ForkName::Fulu => 169,
        _ => 105,
    }
}

/// `current_sync_committee_gindex_at_slot`, by the fork of that slot
/// (`specs/gloas/light-client/sync-protocol.md`).
pub fn current_sync_committee_gindex(fork: ForkName) -> u64 {
    match fork {
        ForkName::Gloas => 2945,
        ForkName::Electra | ForkName::Fulu => 86,
        _ => 54,
    }
}

/// `next_sync_committee_gindex_at_slot`, by the fork of that slot
/// (`specs/gloas/light-client/sync-protocol.md`).
pub fn next_sync_committee_gindex(fork: ForkName) -> u64 {
    match fork {
        ForkName::Gloas => 2946,
        ForkName::Electra | ForkName::Fulu => 87,
        _ => 55,
    }
}

/// `EXECUTION_PAYLOAD_GINDEX` (`specs/capella/light-client/sync-protocol.md`).
pub const EXECUTION_PAYLOAD_GINDEX: u64 = 25;
/// `EXECUTION_BLOCK_HASH_GINDEX_GLOAS` (`specs/gloas/light-client/sync-protocol.md`).
pub const EXECUTION_BLOCK_HASH_GINDEX_GLOAS: u64 = 2856;

/// Gindex of the execution leaf in `BeaconBlockBody` for headers of `fork`:
/// the payload header (Capella through Fulu) or the bid's parent block hash
/// (Gloas). `None` before Capella.
pub fn execution_gindex(fork: ForkName) -> Option<u64> {
    match fork {
        ForkName::Phase0 | ForkName::Altair | ForkName::Bellatrix => None,
        ForkName::Gloas => Some(EXECUTION_BLOCK_HASH_GINDEX_GLOAS),
        _ => Some(EXECUTION_PAYLOAD_GINDEX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::mainnet;

    #[test]
    fn gindex_tables() {
        use ForkName::*;
        let expect = [
            (Capella, 105, 54, 55, Some(25)),
            (Deneb, 105, 54, 55, Some(25)),
            (Electra, 169, 86, 87, Some(25)),
            (Fulu, 169, 86, 87, Some(25)),
            (Gloas, 735, 2945, 2946, Some(2856)),
            (Bellatrix, 105, 54, 55, None),
        ];
        for (f, fin, cur, next, exe) in expect {
            assert_eq!(finalized_root_gindex(f), fin, "{f:?}");
            assert_eq!(current_sync_committee_gindex(f), cur, "{f:?}");
            assert_eq!(next_sync_committee_gindex(f), next, "{f:?}");
            assert_eq!(execution_gindex(f), exe, "{f:?}");
        }
    }

    #[test]
    fn fork_boundary_slots() {
        let cfg = mainnet();
        let s = |e: u64| e * 32;
        assert_eq!(cfg.fork_at_slot(s(194_048) - 1), ForkName::Bellatrix);
        assert_eq!(cfg.fork_at_slot(s(194_048)), ForkName::Capella);
        assert_eq!(cfg.fork_at_slot(s(269_568) - 1), ForkName::Capella);
        assert_eq!(cfg.fork_at_slot(s(269_568)), ForkName::Deneb);
        assert_eq!(cfg.fork_at_slot(s(364_032)), ForkName::Electra);
        assert_eq!(cfg.fork_at_slot(s(411_392) - 1), ForkName::Electra);
        assert_eq!(cfg.fork_at_slot(s(411_392)), ForkName::Fulu);
        assert_eq!(cfg.fork_at_slot(u64::MAX), ForkName::Fulu);
        assert_eq!(cfg.fork_at_epoch(u64::MAX), ForkName::Gloas);
    }
}
