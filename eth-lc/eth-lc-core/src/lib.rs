//! Ethereum light-client core for RISC Zero guests.
//!
//! The crate implements the consensus-specs light-client sync protocol
//! (tag `v1.7.0-beta.4`) for Capella through Gloas, an execution-layer anchor
//! per finalized header, and Merkle-Patricia claims against that anchor.
//!
//! Safety rests on two inputs: the trusted checkpoint behind
//! [`initialize_store`], and an honest supermajority of each sync committee
//! the store accepts as signer. See the crate README for the full trust model.
//!
//! The crate is `no_std` + `alloc` when the `std` feature is off.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(all(
    target_os = "zkvm",
    any(feature = "minimal-profile", feature = "spec-oracle")
))]
compile_error!(
    "eth-lc-core: the `minimal-profile` and `spec-oracle` features serve host tests only"
);

pub mod bls;
pub mod claim;
pub mod config;
pub mod crypto;
pub mod execution;
pub mod fork;
pub mod mpt;
#[cfg(feature = "spec-oracle")]
pub mod oracle;
pub mod profile;
pub mod ssz;
pub mod sync;
pub mod types;

pub use config::{ChainConfig, Fork};
pub use fork::ForkName;
pub use profile::check_profile;
pub use sync::{
    apply_update, get_lc_execution_root, initialize_store, is_valid_light_client_header,
    stale_after_ms, validate_light_client_update,
};
pub use types::*;

/// Errors of the light-client core. Each variant names the rule that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The chain config differs from every pinned profile.
    ProfileMismatch,
    /// The header slot falls before Capella.
    UnsupportedFork,
    /// The header variant differs from the fork at its own slot.
    HeaderVariant,
    /// The header fails `is_valid_light_client_header`.
    InvalidHeader,
    /// The bootstrap header root differs from the trusted block root.
    TrustedRootMismatch,
    /// The bootstrap committee branch fails.
    InvalidCurrentCommitteeBranch,
    /// The participation bitvector length differs from `sync_committee_size / 8`.
    BitsLength,
    /// Fewer participants than `MIN_SYNC_COMMITTEE_PARTICIPANTS`.
    TooFewParticipants,
    /// Slot order `current_slot >= signature_slot > attested_slot >= finalized_slot` fails.
    SlotOrder,
    /// The signature period is outside the periods the store accepts.
    SignaturePeriod,
    /// The attested slot is at or below the store's finalized slot, and the update brings an irrelevant next committee.
    NotRelevant,
    /// A genesis-slot finalized header carries nonzero fields.
    GenesisHeaderNotEmpty,
    /// The finality branch fails.
    InvalidFinalityBranch,
    /// The next-committee branch fails.
    InvalidNextCommitteeBranch,
    /// The update carries a next committee different from the stored one.
    NextCommitteeMismatch,
    /// A committee has the wrong size.
    CommitteeSize,
    /// The input committee hashes to a root other than the selected store root.
    CommitteeMismatch,
    /// The non-signer hints differ from the zero bits.
    HintMismatch,
    /// A hinted key fails to decode or differs from the committed key.
    InvalidKey,
    /// The participant key is the identity point.
    IdentityKey,
    /// The aggregate signature fails.
    InvalidSignature,
    /// Participation is below two thirds of the committee.
    NoSupermajority,
    /// The update's finality data is empty.
    MissingFinality,
    /// A next-committee signature comes with a finalized header outside the next period.
    AcceptRule,
    /// The update leaves both the finalized slot and the next committee as they are.
    NoProgress,
    /// The transition would skip a sync committee period.
    PeriodSkip,
    /// A Gloas header needs the RLP preimage of its execution block.
    MissingExecutionPreimage,
    /// A pre-Gloas header takes its anchor from the payload header; a preimage is extra input.
    UnexpectedExecutionPreimage,
    /// The preimage hash differs from the execution block hash.
    ExecutionHashMismatch,
    /// The execution header RLP is malformed.
    InvalidExecutionHeader,
    /// A Merkle-Patricia proof fails.
    InvalidProof,
    /// The receipt type byte is outside the supported set.
    UnknownReceiptType,
    /// The receipt RLP is malformed.
    InvalidReceipt,
    /// The account RLP is malformed.
    InvalidAccount,
    /// An integer field has a leading zero byte or exceeds 32 bytes.
    InvalidInteger,
    /// The proven receipt is absent from the trie.
    ReceiptAbsent,
    /// A log index, topic index or data word is out of range.
    OutOfRange,
    /// The condition field belongs to another evidence kind.
    FieldMismatch,
    /// The claim chain id differs from the record chain id.
    ChainIdMismatch,
    /// A condition evaluates to false.
    ConditionFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
