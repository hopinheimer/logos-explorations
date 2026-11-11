//! The program's accounts and events (proposal section 4), and the two
//! transitions that write them: [`init`] and [`advance`].
//!
//! Each account object is Borsh-encoded and stores the values its address is
//! derived from. Addresses are LEZ PDAs of the program. This crate has no LEZ
//! dependency: it returns the seed of each address (`*_seed`), and the program
//! passes a `pda` function that maps a seed to the account id.
//!
//! Every account is written once. A second write to the same address is
//! refused by the program, so an update that reaches a block already written
//! is refused (R.8).

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::bls::participation;
use crate::claim::Statement;
use crate::config::{ChainConfig, Fork};
use crate::crypto::sha256;
use crate::profile::{Preset, MAINNET_PRESET};
use crate::sync::{apply_update, initialize_store, stale_after_ms};
use crate::types::{BeaconBlockHeader, BootstrapInput, ExecutionAnchor, Root, Store, UpdateInput};
use crate::Error;

/// A LEZ account id (32 bytes; the same Borsh encoding as LEZ's `AccountId`).
pub type AccountId = [u8; 32];

/// Section 4.1. At `instance_id = PDA(program, H(checkpoint ‖ chain ‖ finality))`,
/// written once, at `Init`.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct InstanceConfig {
    /// The beacon block root the instance starts from.
    pub checkpoint: Root,
    pub chain: ChainBinding,
    pub finality: FinalityParams,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct ChainBinding {
    /// Execution chain.
    pub chain_id: u64,
    /// Consensus network.
    pub genesis_validators_root: Root,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct FinalityParams {
    pub genesis_time: u64,
    /// (activation epoch, fork version), oldest first.
    pub forks: Vec<(u64, [u8; 4])>,
    /// 342 of 512.
    pub min_participants: u16,
    /// Seconds; past it the instance is replaced (F.10).
    pub weak_subjectivity_period: u64,
}

/// Section 4.2. At `PDA(program, H("state" ‖ instance ‖ block_number))`.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct ConsensusState {
    /// `instance_id`.
    pub instance: AccountId,
    /// The finalised execution block this state reached.
    pub block_number: u64,
    /// `block_number` of the state the update was built on.
    pub parent: u64,
    /// Its sync-committee period.
    pub period: u64,
    pub current_committee: Root,
    /// Once handed off.
    pub next_committee: Option<Root>,
    /// Its `FinalisedHeader` account.
    pub finalised_header: AccountId,
}

/// Section 4.3. At `PDA(program, H("committee" ‖ instance ‖ period))`.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct Committee {
    /// `instance_id`.
    pub instance: AccountId,
    pub period: u64,
    /// SSZ root of the 512 keys and their aggregate.
    pub root: Root,
    /// The attested header that carried it.
    pub handoff_slot: u64,
}

/// Section 4.4. At `PDA(program, H("header" ‖ instance ‖ block_number))`.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct FinalisedHeader {
    /// `instance_id`.
    pub instance: AccountId,
    /// A statement is refused on another chain or instance (F.5, F.15).
    pub chain: ChainBinding,
    pub slot: u64,
    pub beacon_root: Root,
    pub block_number: u64,
    /// History proofs start here.
    pub block_hash: Root,
    /// Accounts and storage slots (F.3).
    pub state_root: Root,
    /// Logs (F.3).
    pub receipts_root: Root,
    /// Of 512, so a consumer can require more than 2/3.
    pub signers: u16,
    /// Which committee signed.
    pub committee_period: u64,
}

/// Section 4.8, following LP-0012.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// `instance`: `instance_id`.
    CommitteeHandoff {
        instance: AccountId,
        period: u64,
        committee_root: Root,
    },
    /// `instance`: `instance_id`.
    HeaderFinalised {
        instance: AccountId,
        block_number: u64,
        header: AccountId,
    },
    /// Public path only; a private attestation emits nothing.
    Attested { statement: Statement },
}

impl InstanceConfig {
    /// Seed of the instance address: `H(checkpoint ‖ chain ‖ finality)`, the
    /// SHA-256 of this config's Borsh encoding.
    pub fn seed(&self) -> Root {
        sha256(&borsh::to_vec(self).unwrap_or_default())
    }
}

fn seed(tag: &[u8], instance: &AccountId, n: u64) -> Root {
    let mut buf = Vec::with_capacity(tag.len() + 40);
    buf.extend_from_slice(tag);
    buf.extend_from_slice(instance);
    buf.extend_from_slice(&n.to_be_bytes());
    sha256(&buf)
}

/// `H("state" ‖ instance ‖ block_number)`, `block_number` as 8 bytes big-endian.
pub fn state_seed(instance: &AccountId, block_number: u64) -> Root {
    seed(b"state", instance, block_number)
}

/// `H("committee" ‖ instance ‖ period)`, `period` as 8 bytes big-endian.
pub fn committee_seed(instance: &AccountId, period: u64) -> Root {
    seed(b"committee", instance, period)
}

/// `H("header" ‖ instance ‖ block_number)`, `block_number` as 8 bytes big-endian.
pub fn header_seed(instance: &AccountId, block_number: u64) -> Root {
    seed(b"header", instance, block_number)
}

impl ChainConfig {
    /// The light-client parameters of `config` under the mainnet preset.
    pub fn from_instance(config: &InstanceConfig) -> Self {
        Self::from_instance_with_preset(MAINNET_PRESET, config)
    }

    /// The light-client parameters of `config` under `preset`. Only the
    /// pinned preset passes [`crate::check_profile`].
    pub fn from_instance_with_preset(preset: Preset, config: &InstanceConfig) -> Self {
        let f = &config.finality;
        let mut cfg = Self::with_preset(
            preset,
            config.chain.chain_id,
            config.chain.genesis_validators_root,
            f.genesis_time,
            f.forks
                .iter()
                .map(|&(epoch, version)| Fork { version, epoch })
                .collect(),
        );
        cfg.min_participants = f.min_participants;
        cfg.weak_subjectivity_period = f.weak_subjectivity_period;
        cfg
    }

    /// The instance config of this chain, starting from `checkpoint`.
    pub fn instance_config(&self, checkpoint: Root) -> InstanceConfig {
        InstanceConfig {
            checkpoint,
            chain: ChainBinding {
                chain_id: self.chain_id,
                genesis_validators_root: self.genesis_validators_root,
            },
            finality: FinalityParams {
                genesis_time: self.genesis_time,
                forks: self.forks.iter().map(|f| (f.epoch, f.version)).collect(),
                min_participants: self.min_participants,
                weak_subjectivity_period: self.weak_subjectivity_period,
            },
        }
    }
}

/// The accounts `Init` writes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Initialised {
    pub instance: AccountId,
    pub state: ConsensusState,
    pub header: FinalisedHeader,
    pub committee: Committee,
}

/// `Init`: verifies the checkpoint against `config` and returns the first
/// state, header and committee. The checkpoint header records `signers: 0`
/// (no committee signed it) and its own period as `committee_period`.
pub fn init(
    config: &InstanceConfig,
    input: &BootstrapInput,
    pda: impl Fn(&Root) -> AccountId,
) -> Result<Initialised, Error> {
    if input.trusted_block_root != config.checkpoint {
        return Err(Error::CheckpointRootMismatch);
    }
    let cfg = ChainConfig::from_instance(config);
    let store = initialize_store(&cfg, input)?;
    let instance = pda(&config.seed());
    let period = cfg.period_at_slot(store.finalized.slot);
    let header = FinalisedHeader::from_store(config, instance, &store, 0, period);
    let header_account = pda(&header_seed(&instance, header.block_number));
    Ok(Initialised {
        instance,
        state: ConsensusState {
            instance,
            block_number: header.block_number,
            parent: header.block_number,
            period,
            current_committee: store.current_committee_root,
            next_committee: None,
            finalised_header: header_account,
        },
        committee: Committee {
            instance,
            period,
            root: store.current_committee_root,
            handoff_slot: store.finalized.slot,
        },
        header,
    })
}

/// The accounts and events a verified update writes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Advanced {
    pub state: ConsensusState,
    pub header: FinalisedHeader,
    /// The next period's committee, when this update handed it off.
    pub committee: Option<Committee>,
    pub events: Vec<Event>,
}

/// Checks that `state`, its `header` and `next` (the committee account of
/// `state.period + 1`, when the state has no next committee) belong to the
/// instance of `config`, and returns its id and the working store.
fn base(
    config: &InstanceConfig,
    state: &ConsensusState,
    header: &FinalisedHeader,
    next: Option<&Committee>,
    pda: &impl Fn(&Root) -> AccountId,
) -> Result<(AccountId, Store), Error> {
    let instance = pda(&config.seed());
    if state.instance != instance
        || header.instance != instance
        || header.block_number != state.block_number
        || state.finalised_header != pda(&header_seed(&instance, header.block_number))
    {
        return Err(Error::AccountMismatch);
    }
    let mut store = store_of(state, header);
    if let Some(c) = next {
        if state.next_committee.is_some()
            || c.instance != instance
            || c.period != state.period.saturating_add(1)
        {
            return Err(Error::AccountMismatch);
        }
        store.next_committee_root = Some(c.root);
    }
    Ok((instance, store))
}

/// A handoff without a new header: an update that installs the next
/// committee and leaves the finalized execution block as it is (a new
/// instance's first update, for example). The state account at that block
/// is already written, so the update writes only the `Committee` account of
/// `state.period + 1`. Later updates pass it to [`advance`] as `next`.
pub fn hand_off(
    config: &InstanceConfig,
    state: &ConsensusState,
    header: &FinalisedHeader,
    input: &UpdateInput,
    pda: impl Fn(&Root) -> AccountId,
) -> Result<(Committee, Event), Error> {
    let (instance, store) = base(config, state, header, None, &pda)?;
    let cfg = ChainConfig::from_instance(config);
    let next = apply_update(&cfg, &store, input)?;
    let root = match next.next_committee_root {
        Some(root)
            if store.next_committee_root.is_none()
                && next.execution.number == header.block_number =>
        {
            root
        }
        _ => return Err(Error::NoProgress),
    };
    let committee = Committee {
        instance,
        period: state.period.saturating_add(1),
        root,
        handoff_slot: input.update.attested_header.beacon().slot,
    };
    let event = Event::CommitteeHandoff {
        instance,
        period: committee.period,
        committee_root: root,
    };
    Ok((committee, event))
}

/// `Update`: checks `input` against the state it builds on (`state`, its
/// `header`, and `next` when the next committee came by [`hand_off`]) under
/// [`apply_update`], and returns what it writes. The update must reach a new
/// execution block ([`Error::NoProgress`] otherwise).
pub fn advance(
    config: &InstanceConfig,
    state: &ConsensusState,
    header: &FinalisedHeader,
    next: Option<&Committee>,
    input: &UpdateInput,
    pda: impl Fn(&Root) -> AccountId,
) -> Result<Advanced, Error> {
    let (instance, store) = base(config, state, header, next, &pda)?;
    let cfg = ChainConfig::from_instance(config);
    let next = apply_update(&cfg, &store, input)?;
    if next.execution.number == header.block_number {
        return Err(Error::NoProgress);
    }
    let update = &input.update;
    let signers = participation(&cfg, &update.sync_aggregate.bits)? as u16;
    let signed_in = cfg.period_at_slot(update.signature_slot);
    let new_header = FinalisedHeader::from_store(config, instance, &next, signers, signed_in);
    let header_account = pda(&header_seed(&instance, new_header.block_number));
    let period = cfg.period_at_slot(next.finalized.slot);
    let rotated = period != state.period;
    let committee = match next.next_committee_root {
        Some(root) if rotated || store.next_committee_root.is_none() => Some(Committee {
            instance,
            period: period + 1,
            root,
            handoff_slot: update.attested_header.beacon().slot,
        }),
        _ => None,
    };
    let mut events = Vec::new();
    if let Some(c) = &committee {
        events.push(Event::CommitteeHandoff {
            instance,
            period: c.period,
            committee_root: c.root,
        });
    }
    events.push(Event::HeaderFinalised {
        instance,
        block_number: new_header.block_number,
        header: header_account,
    });
    Ok(Advanced {
        state: ConsensusState {
            instance,
            block_number: new_header.block_number,
            parent: state.block_number,
            period,
            current_committee: next.current_committee_root,
            next_committee: next.next_committee_root,
            finalised_header: header_account,
        },
        header: new_header,
        committee,
        events,
    })
}

/// End of the update window of the state whose header is `header` (Unix ms):
/// `weak_subjectivity_period` past the header's slot. See
/// [`crate::stale_after_ms`].
pub fn update_deadline_ms(config: &InstanceConfig, header: &FinalisedHeader) -> u64 {
    let cfg = ChainConfig::from_instance(config);
    stale_after_ms(&cfg, &store_of_slot(header.slot))
}

impl FinalisedHeader {
    /// The header account of `store`'s finalized header.
    pub fn from_store(
        config: &InstanceConfig,
        instance: AccountId,
        store: &Store,
        signers: u16,
        committee_period: u64,
    ) -> Self {
        FinalisedHeader {
            instance,
            chain: config.chain.clone(),
            slot: store.finalized.slot,
            beacon_root: store.finalized.hash_tree_root(),
            block_number: store.execution.number,
            block_hash: store.execution.block_hash,
            state_root: store.execution.state_root,
            receipts_root: store.execution.receipts_root,
            signers,
            committee_period,
        }
    }
}

fn store_of_slot(slot: u64) -> Store {
    Store {
        finalized: BeaconBlockHeader {
            slot,
            ..Default::default()
        },
        execution: ExecutionAnchor::default(),
        current_committee_root: [0; 32],
        next_committee_root: None,
    }
}

/// The working store of a state. The sync rules read only the finalized
/// slot of the store's header, so the other beacon header fields stay zero.
fn store_of(state: &ConsensusState, header: &FinalisedHeader) -> Store {
    Store {
        execution: ExecutionAnchor {
            block_hash: header.block_hash,
            number: header.block_number,
            state_root: header.state_root,
            receipts_root: header.receipts_root,
        },
        current_committee_root: state.current_committee,
        next_committee_root: state.next_committee,
        ..store_of_slot(header.slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trip() {
        let cfg = ChainConfig::mainnet();
        let ic = cfg.instance_config([7; 32]);
        assert_eq!(ic.finality.min_participants, 342);
        assert_eq!(ChainConfig::from_instance(&ic), cfg);
        assert_ne!(ic.seed(), cfg.instance_config([8; 32]).seed());
    }

    #[test]
    fn seeds_are_distinct_per_tag() {
        let i = [1u8; 32];
        let all = alloc::vec![state_seed(&i, 5), committee_seed(&i, 5), header_seed(&i, 5)];
        assert!(all[0] != all[1] && all[1] != all[2] && all[0] != all[2]);
        assert_ne!(state_seed(&i, 5), state_seed(&i, 6));
    }
}
