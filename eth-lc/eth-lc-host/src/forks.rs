//! Light-client containers per fork layout, as served by the Beacon API
//! (JSON) and stored by spec tests and chain-dirs (SSZ), and their conversion
//! to `eth-lc-core` types.
//!
//! Layouts follow consensus-specs `v1.7.0-beta.4`:
//! Capella (`specs/capella/light-client/sync-protocol.md`), Deneb
//! (`specs/deneb/...`), Electra and Fulu (`specs/electra/...`), Gloas
//! (`specs/gloas/...`).

use alloy_primitives::{Address, FixedBytes, B256, U256};
use anyhow::{anyhow, bail, ensure, Result};
use eth_lc_core as core;
use eth_lc_core::{ChainConfig, ForkName};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::{Unsigned, U11, U256 as N256, U32, U4, U5, U512, U6, U7, U9};
use ssz_types::{BitVector, FixedVector, VariableList};
use tree_hash_derive::TreeHash;

pub type PublicKeyBytes = FixedBytes<48>;
pub type SignatureBytes = FixedBytes<96>;

/// `BeaconBlockHeader`.
#[derive(Encode, Decode, TreeHash, Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct BeaconBlockHeader {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

/// `capella.ExecutionPayloadHeader`.
#[derive(Encode, Decode, TreeHash, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExecutionPayloadHeaderCapella {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, N256>,
    pub prev_randao: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub block_number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, U32>,
    #[serde(with = "serde_utils::quoted_u256")]
    pub base_fee_per_gas: U256,
    pub block_hash: B256,
    pub transactions_root: B256,
    pub withdrawals_root: B256,
}

/// `deneb.ExecutionPayloadHeader` (also Electra and Fulu).
#[derive(Encode, Decode, TreeHash, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExecutionPayloadHeaderDeneb {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, N256>,
    pub prev_randao: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub block_number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, U32>,
    #[serde(with = "serde_utils::quoted_u256")]
    pub base_fee_per_gas: U256,
    pub block_hash: B256,
    pub transactions_root: B256,
    pub withdrawals_root: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub blob_gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub excess_blob_gas: u64,
}

/// Capella `LightClientHeader`.
#[derive(Encode, Decode, TreeHash, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HeaderCapella {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeaderCapella,
    pub execution_branch: FixedVector<B256, U4>,
}

/// Deneb, Electra and Fulu `LightClientHeader`.
#[derive(Encode, Decode, TreeHash, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HeaderDeneb {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeaderDeneb,
    pub execution_branch: FixedVector<B256, U4>,
}

/// Gloas `LightClientHeader`.
#[derive(Encode, Decode, TreeHash, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HeaderGloas {
    pub beacon: BeaconBlockHeader,
    pub execution_block_hash: B256,
    pub execution_branch: FixedVector<B256, U11>,
}

/// `SyncCommittee` of `N` members.
#[derive(Encode, Decode, TreeHash, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(bound = "N: Unsigned + Clone")]
pub struct SyncCommittee<N: Unsigned + Clone> {
    pub pubkeys: FixedVector<PublicKeyBytes, N>,
    pub aggregate_pubkey: PublicKeyBytes,
}

/// `SyncAggregate` of `N` members.
#[derive(Encode, Decode, TreeHash, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(bound = "N: Unsigned + Clone")]
pub struct SyncAggregate<N: Unsigned + Clone> {
    pub sync_committee_bits: BitVector<N>,
    pub sync_committee_signature: SignatureBytes,
}

/// `LightClientBootstrap` with header `H`, committee size `N`, branch length `CB`.
#[derive(Encode, Decode, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(
    bound = "H: Serialize + serde::de::DeserializeOwned, N: Unsigned + Clone, CB: Unsigned + Clone"
)]
pub struct Bootstrap<H: Encode + Decode, N: Unsigned + Clone, CB: Unsigned + Clone> {
    pub header: H,
    pub current_sync_committee: SyncCommittee<N>,
    pub current_sync_committee_branch: FixedVector<B256, CB>,
}

/// `LightClientUpdate`.
#[derive(Encode, Decode, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(
    bound = "H: Serialize + serde::de::DeserializeOwned, N: Unsigned + Clone, NB: Unsigned + Clone, FB: Unsigned + Clone"
)]
pub struct Update<
    H: Encode + Decode,
    N: Unsigned + Clone,
    NB: Unsigned + Clone,
    FB: Unsigned + Clone,
> {
    pub attested_header: H,
    pub next_sync_committee: SyncCommittee<N>,
    pub next_sync_committee_branch: FixedVector<B256, NB>,
    pub finalized_header: H,
    pub finality_branch: FixedVector<B256, FB>,
    pub sync_aggregate: SyncAggregate<N>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub signature_slot: u64,
}

/// `LightClientFinalityUpdate`.
#[derive(Encode, Decode, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(
    bound = "H: Serialize + serde::de::DeserializeOwned, N: Unsigned + Clone, FB: Unsigned + Clone"
)]
pub struct FinalityUpdate<H: Encode + Decode, N: Unsigned + Clone, FB: Unsigned + Clone> {
    pub attested_header: H,
    pub finalized_header: H,
    pub finality_branch: FixedVector<B256, FB>,
    pub sync_aggregate: SyncAggregate<N>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub signature_slot: u64,
}

/// Preset of a network: the sync committee size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    /// 512 members.
    Mainnet,
    /// 32 members.
    Minimal,
}

impl Preset {
    pub fn of(cfg: &ChainConfig) -> Result<Self> {
        match cfg.sync_committee_size {
            512 => Ok(Self::Mainnet),
            32 => Ok(Self::Minimal),
            n => bail!("no preset with sync committee size {n}"),
        }
    }
}

/// The fork whose data layout an object uses (Beacon API `version`).
pub fn parse_fork(name: &str) -> Result<ForkName> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "capella" => ForkName::Capella,
        "deneb" => ForkName::Deneb,
        "electra" => ForkName::Electra,
        "fulu" => ForkName::Fulu,
        "gloas" => ForkName::Gloas,
        other => bail!("unsupported light-client data fork {other}"),
    })
}

/// Lower-case fork name, the Beacon API `version` string.
pub fn fork_str(fork: ForkName) -> &'static str {
    match fork {
        ForkName::Phase0 => "phase0",
        ForkName::Altair => "altair",
        ForkName::Bellatrix => "bellatrix",
        ForkName::Capella => "capella",
        ForkName::Deneb => "deneb",
        ForkName::Electra => "electra",
        ForkName::Fulu => "fulu",
        ForkName::Gloas => "gloas",
    }
}

/// A light-client object in the layout of its data fork, any preset.
#[derive(Clone, Debug, PartialEq)]
pub enum AnyHeader {
    Capella(HeaderCapella),
    Deneb(HeaderDeneb),
    Gloas(HeaderGloas),
}

/// Neutral form of a decoded bootstrap, before conversion to core types.
#[derive(Clone, Debug, PartialEq)]
pub struct RawBootstrap {
    pub header: AnyHeader,
    pub committee: core::SyncCommittee,
    pub branch: Vec<core::Root>,
}

/// Neutral form of a decoded update or finality update.
#[derive(Clone, Debug, PartialEq)]
pub struct RawUpdate {
    pub attested_header: AnyHeader,
    pub next: Option<(core::SyncCommittee, Vec<core::Root>)>,
    pub next_is_empty: bool,
    pub finalized_header: AnyHeader,
    pub finality_branch: Vec<core::Root>,
    pub bits: Vec<u8>,
    pub signature: [u8; 96],
    pub signature_slot: u64,
}

fn roots(v: &[B256]) -> Vec<core::Root> {
    v.iter().map(|r| r.0).collect()
}

fn committee<N: Unsigned + Clone>(c: &SyncCommittee<N>) -> core::SyncCommittee {
    core::SyncCommittee {
        pubkeys: c.pubkeys.iter().map(|k| k.0).collect(),
        aggregate_pubkey: c.aggregate_pubkey.0,
    }
}

fn committee_is_empty<N: Unsigned + Clone>(c: &SyncCommittee<N>) -> bool {
    c.aggregate_pubkey.is_zero() && c.pubkeys.iter().all(|k| k.is_zero())
}

trait IntoAny {
    fn into_any(self) -> AnyHeader;
}
impl IntoAny for HeaderCapella {
    fn into_any(self) -> AnyHeader {
        AnyHeader::Capella(self)
    }
}
impl IntoAny for HeaderDeneb {
    fn into_any(self) -> AnyHeader {
        AnyHeader::Deneb(self)
    }
}
impl IntoAny for HeaderGloas {
    fn into_any(self) -> AnyHeader {
        AnyHeader::Gloas(self)
    }
}

fn raw_bootstrap<H: Encode + Decode + IntoAny, N: Unsigned + Clone, CB: Unsigned + Clone>(
    b: Bootstrap<H, N, CB>,
) -> RawBootstrap {
    RawBootstrap {
        committee: committee(&b.current_sync_committee),
        branch: roots(&b.current_sync_committee_branch),
        header: b.header.into_any(),
    }
}

fn raw_update<
    H: Encode + Decode + IntoAny,
    N: Unsigned + Clone,
    NB: Unsigned + Clone,
    FB: Unsigned + Clone,
>(
    u: Update<H, N, NB, FB>,
) -> RawUpdate {
    let next_branch = roots(&u.next_sync_committee_branch);
    RawUpdate {
        next_is_empty: committee_is_empty(&u.next_sync_committee),
        next: Some((committee(&u.next_sync_committee), next_branch)),
        attested_header: u.attested_header.into_any(),
        finalized_header: u.finalized_header.into_any(),
        finality_branch: roots(&u.finality_branch),
        bits: u.sync_aggregate.sync_committee_bits.as_slice().to_vec(),
        signature: u.sync_aggregate.sync_committee_signature.0,
        signature_slot: u.signature_slot,
    }
}

fn raw_finality<H: Encode + Decode + IntoAny, N: Unsigned + Clone, FB: Unsigned + Clone>(
    u: FinalityUpdate<H, N, FB>,
) -> RawUpdate {
    RawUpdate {
        next: None,
        next_is_empty: true,
        attested_header: u.attested_header.into_any(),
        finalized_header: u.finalized_header.into_any(),
        finality_branch: roots(&u.finality_branch),
        bits: u.sync_aggregate.sync_committee_bits.as_slice().to_vec(),
        signature: u.sync_aggregate.sync_committee_signature.0,
        signature_slot: u.signature_slot,
    }
}

/// Wire encoding of an object: SSZ bytes or Beacon API JSON (`data` member).
pub enum Wire<'a> {
    Ssz(&'a [u8]),
    Json(&'a serde_json::Value),
}

fn parse<T: Decode + serde::de::DeserializeOwned>(w: &Wire) -> Result<T> {
    match w {
        Wire::Ssz(b) => T::from_ssz_bytes(b).map_err(|e| anyhow!("ssz decode: {e:?}")),
        Wire::Json(v) => Ok(serde_json::from_value((*v).clone())?),
    }
}

macro_rules! by_layout {
    ($fork:expr, $preset:expr, $mac:ident) => {
        match ($fork, $preset) {
            (ForkName::Capella, Preset::Mainnet) => $mac!(HeaderCapella, U512, U5, U5, U6),
            (ForkName::Capella, Preset::Minimal) => $mac!(HeaderCapella, U32, U5, U5, U6),
            (ForkName::Deneb, Preset::Mainnet) => $mac!(HeaderDeneb, U512, U5, U5, U6),
            (ForkName::Deneb, Preset::Minimal) => $mac!(HeaderDeneb, U32, U5, U5, U6),
            (ForkName::Electra | ForkName::Fulu, Preset::Mainnet) => {
                $mac!(HeaderDeneb, U512, U6, U6, U7)
            }
            (ForkName::Electra | ForkName::Fulu, Preset::Minimal) => {
                $mac!(HeaderDeneb, U32, U6, U6, U7)
            }
            (ForkName::Gloas, Preset::Mainnet) => $mac!(HeaderGloas, U512, U11, U11, U9),
            (ForkName::Gloas, Preset::Minimal) => $mac!(HeaderGloas, U32, U11, U11, U9),
            (f, _) => bail!("unsupported light-client data fork {f:?}"),
        }
    };
}

/// Decodes a `LightClientBootstrap` of data fork `fork`.
pub fn decode_bootstrap(fork: ForkName, preset: Preset, w: Wire) -> Result<RawBootstrap> {
    macro_rules! go {
        ($h:ty, $n:ty, $cb:ty, $nb:ty, $fb:ty) => {
            Ok(raw_bootstrap(parse::<Bootstrap<$h, $n, $cb>>(&w)?))
        };
    }
    by_layout!(fork, preset, go)
}

/// Decodes a `LightClientUpdate` of data fork `fork`.
pub fn decode_update(fork: ForkName, preset: Preset, w: Wire) -> Result<RawUpdate> {
    macro_rules! go {
        ($h:ty, $n:ty, $cb:ty, $nb:ty, $fb:ty) => {
            Ok(raw_update(parse::<Update<$h, $n, $nb, $fb>>(&w)?))
        };
    }
    by_layout!(fork, preset, go)
}

/// Decodes a `LightClientFinalityUpdate` of data fork `fork`.
pub fn decode_finality_update(fork: ForkName, preset: Preset, w: Wire) -> Result<RawUpdate> {
    macro_rules! go {
        ($h:ty, $n:ty, $cb:ty, $nb:ty, $fb:ty) => {
            Ok(raw_finality(parse::<FinalityUpdate<$h, $n, $fb>>(&w)?))
        };
    }
    by_layout!(fork, preset, go)
}

/// Re-encodes a Beacon API JSON object as SSZ (the form chain-dirs store).
pub fn json_to_ssz(
    kind: Kind,
    fork: ForkName,
    preset: Preset,
    v: &serde_json::Value,
) -> Result<Vec<u8>> {
    macro_rules! go {
        ($h:ty, $n:ty, $cb:ty, $nb:ty, $fb:ty) => {
            Ok(match kind {
                Kind::Bootstrap => {
                    serde_json::from_value::<Bootstrap<$h, $n, $cb>>(v.clone())?.as_ssz_bytes()
                }
                Kind::Update => {
                    serde_json::from_value::<Update<$h, $n, $nb, $fb>>(v.clone())?.as_ssz_bytes()
                }
                Kind::FinalityUpdate => {
                    serde_json::from_value::<FinalityUpdate<$h, $n, $fb>>(v.clone())?.as_ssz_bytes()
                }
            })
        };
    }
    by_layout!(fork, preset, go)
}

/// Kinds of light-client objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bootstrap,
    Update,
    FinalityUpdate,
}

fn beacon(h: &BeaconBlockHeader) -> core::BeaconBlockHeader {
    core::BeaconBlockHeader {
        slot: h.slot,
        proposer_index: h.proposer_index,
        parent_root: h.parent_root.0,
        state_root: h.state_root.0,
        body_root: h.body_root.0,
    }
}

fn bloom(v: &FixedVector<u8, N256>) -> [u8; 256] {
    let mut out = [0u8; 256];
    out.copy_from_slice(v);
    out
}

fn capella_payload(e: &ExecutionPayloadHeaderCapella) -> core::ExecutionPayloadHeaderCapella {
    core::ExecutionPayloadHeaderCapella {
        parent_hash: e.parent_hash.0,
        fee_recipient: e.fee_recipient.0 .0,
        state_root: e.state_root.0,
        receipts_root: e.receipts_root.0,
        logs_bloom: bloom(&e.logs_bloom),
        prev_randao: e.prev_randao.0,
        block_number: e.block_number,
        gas_limit: e.gas_limit,
        gas_used: e.gas_used,
        timestamp: e.timestamp,
        extra_data: e.extra_data.to_vec(),
        base_fee_per_gas: e.base_fee_per_gas.to_le_bytes(),
        block_hash: e.block_hash.0,
        transactions_root: e.transactions_root.0,
        withdrawals_root: e.withdrawals_root.0,
    }
}

fn deneb_payload(e: &ExecutionPayloadHeaderDeneb) -> core::ExecutionPayloadHeaderDeneb {
    core::ExecutionPayloadHeaderDeneb {
        parent_hash: e.parent_hash.0,
        fee_recipient: e.fee_recipient.0 .0,
        state_root: e.state_root.0,
        receipts_root: e.receipts_root.0,
        logs_bloom: bloom(&e.logs_bloom),
        prev_randao: e.prev_randao.0,
        block_number: e.block_number,
        gas_limit: e.gas_limit,
        gas_used: e.gas_used,
        timestamp: e.timestamp,
        extra_data: e.extra_data.to_vec(),
        base_fee_per_gas: e.base_fee_per_gas.to_le_bytes(),
        block_hash: e.block_hash.0,
        transactions_root: e.transactions_root.0,
        withdrawals_root: e.withdrawals_root.0,
        blob_gas_used: e.blob_gas_used,
        excess_blob_gas: e.excess_blob_gas,
    }
}

impl AnyHeader {
    pub fn beacon(&self) -> &BeaconBlockHeader {
        match self {
            Self::Capella(h) => &h.beacon,
            Self::Deneb(h) => &h.beacon,
            Self::Gloas(h) => &h.beacon,
        }
    }

    fn is_empty(&self) -> bool {
        let zero_branch = |b: &[B256]| b.iter().all(|n| n.is_zero());
        let body = match self {
            Self::Capella(h) => {
                zero_branch(&h.execution_branch)
                    && capella_payload(&h.execution) == Default::default()
            }
            Self::Deneb(h) => {
                zero_branch(&h.execution_branch)
                    && deneb_payload(&h.execution) == Default::default()
            }
            Self::Gloas(h) => zero_branch(&h.execution_branch) && h.execution_block_hash.is_zero(),
        };
        body && *self.beacon() == BeaconBlockHeader::default()
    }
}

/// Converts a data-layout header to the core variant of the fork at its own
/// slot. A Deneb-layout header at a Capella slot becomes a Capella header
/// (its blob fields must be zero). The empty header becomes the empty header
/// of the slot's layout. A Gloas-layout header at a pre-Gloas slot fails: the
/// Gloas layout drops the payload header that the older variants carry.
pub fn to_core_header(cfg: &ChainConfig, h: &AnyHeader) -> Result<core::LightClientHeader> {
    let slot_fork = cfg.fork_at_slot(h.beacon().slot);
    if h.is_empty() {
        let beacon = core::BeaconBlockHeader::default();
        return Ok(match slot_fork {
            ForkName::Gloas => core::LightClientHeader::Gloas {
                beacon,
                execution_block_hash: [0; 32],
                execution_branch: vec![[0; 32]; 11],
            },
            ForkName::Deneb | ForkName::Electra | ForkName::Fulu => {
                core::LightClientHeader::Deneb {
                    beacon,
                    execution: Default::default(),
                    execution_branch: vec![[0; 32]; 4],
                }
            }
            _ => core::LightClientHeader::Capella {
                beacon,
                execution: Default::default(),
                execution_branch: vec![[0; 32]; 4],
            },
        });
    }
    Ok(match (h, slot_fork) {
        (AnyHeader::Capella(h), ForkName::Capella) => core::LightClientHeader::Capella {
            beacon: beacon(&h.beacon),
            execution: capella_payload(&h.execution),
            execution_branch: roots(&h.execution_branch),
        },
        (AnyHeader::Deneb(h), ForkName::Deneb | ForkName::Electra | ForkName::Fulu) => {
            core::LightClientHeader::Deneb {
                beacon: beacon(&h.beacon),
                execution: deneb_payload(&h.execution),
                execution_branch: roots(&h.execution_branch),
            }
        }
        (AnyHeader::Deneb(h), ForkName::Capella) => {
            ensure!(
                h.execution.blob_gas_used == 0 && h.execution.excess_blob_gas == 0,
                "blob fields set before Deneb"
            );
            let d = deneb_payload(&h.execution);
            core::LightClientHeader::Capella {
                beacon: beacon(&h.beacon),
                execution: core::ExecutionPayloadHeaderCapella {
                    parent_hash: d.parent_hash,
                    fee_recipient: d.fee_recipient,
                    state_root: d.state_root,
                    receipts_root: d.receipts_root,
                    logs_bloom: d.logs_bloom,
                    prev_randao: d.prev_randao,
                    block_number: d.block_number,
                    gas_limit: d.gas_limit,
                    gas_used: d.gas_used,
                    timestamp: d.timestamp,
                    extra_data: d.extra_data,
                    base_fee_per_gas: d.base_fee_per_gas,
                    block_hash: d.block_hash,
                    transactions_root: d.transactions_root,
                    withdrawals_root: d.withdrawals_root,
                },
                execution_branch: roots(&h.execution_branch),
            }
        }
        (AnyHeader::Gloas(h), ForkName::Gloas) => core::LightClientHeader::Gloas {
            beacon: beacon(&h.beacon),
            execution_block_hash: h.execution_block_hash.0,
            execution_branch: roots(&h.execution_branch),
        },
        (_, f) => bail!("header layout has no core form at a {f:?} slot"),
    })
}

/// Converts a decoded bootstrap to the core type.
pub fn to_core_bootstrap(
    cfg: &ChainConfig,
    b: &RawBootstrap,
) -> Result<core::LightClientBootstrap> {
    Ok(core::LightClientBootstrap {
        header: to_core_header(cfg, &b.header)?,
        current_sync_committee: b.committee.clone(),
        current_sync_committee_branch: b.branch.clone(),
    })
}

/// Converts a decoded update to the core type. An all-zero branch maps to
/// `None`; the spec then requires the matching data to be empty.
pub fn to_core_update(cfg: &ChainConfig, u: &RawUpdate) -> Result<core::LightClientUpdate> {
    let zero = |b: &[core::Root]| b.iter().all(|n| *n == [0; 32]);
    let next = match &u.next {
        Some((_, branch)) if zero(branch) => {
            ensure!(
                u.next_is_empty,
                "next committee present with an empty branch"
            );
            None
        }
        other => other.clone(),
    };
    let finality = if zero(&u.finality_branch) {
        ensure!(
            u.finalized_header.is_empty(),
            "finalized header present with an empty branch"
        );
        None
    } else {
        Some((
            to_core_header(cfg, &u.finalized_header)?,
            u.finality_branch.clone(),
        ))
    };
    Ok(core::LightClientUpdate {
        attested_header: to_core_header(cfg, &u.attested_header)?,
        next_sync_committee: next,
        finality,
        sync_aggregate: core::SyncAggregate {
            bits: u.bits.clone(),
            signature: u.signature,
        },
        signature_slot: u.signature_slot,
    })
}
