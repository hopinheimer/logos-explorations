//! Stall detection, chain config checks and checkpoint checks for a new instance.
//!
//! An instance's trust anchor is its `Init`: the chain config (chain
//! identity and preset) and the checkpoint. The core checks the preset and
//! the structure of the identity only. [`verify_instance_config`] checks the
//! identity against the chain; [`verify_new_checkpoint`] runs it and then
//! checks the checkpoint.
//!
//! A stalled instance stays readable. Recovery deploys a new instance with a
//! fresh `Init`, anchored at a checkpoint that [`verify_new_checkpoint`]
//! accepts. The operator chooses endpoints run by independent parties; this
//! module checks agreement among them; independence stays the operator's responsibility.

use std::fmt;

use eth_lc_core::{
    initialize_store, stale_after_ms, BootstrapInput, ChainConfig, LightClientHeader, Root, Store,
};
use serde_json::{json, Value};

use crate::evidence::quantity;
use crate::execution::fetch_header_rlp;
use crate::forks::{self, json_to_ssz, Kind, Preset, Wire};
use crate::http::{get_json, rpc};

/// Default mainnet Beacon API endpoints for checkpoint checks: two operators,
/// both over https. Operators should add their own node.
pub const DEFAULT_ENDPOINTS: [&str; 2] = [
    "https://ethereum-beacon-api.publicnode.com",
    "https://lodestar-mainnet.chainsafe.io",
];

/// Default mainnet execution JSON-RPC endpoint for `eth_chainId` and execution headers.
pub const DEFAULT_RPC: &str = "https://ethereum-rpc.publicnode.com";

/// Beacon API `/eth/v1/config/spec` keys of the fork schedule, phase0 through Gloas.
const FORK_KEYS: [&str; 8] = [
    "GENESIS",
    "ALTAIR",
    "BELLATRIX",
    "CAPELLA",
    "DENEB",
    "ELECTRA",
    "FULU",
    "GLOAS",
];

/// Liveness of an instance store at a given time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StallStatus {
    /// Updates can still arrive for `remaining_ms`.
    Live { remaining_ms: u64 },
    /// The update window has closed. Migrate to a new instance.
    Stalled,
}

/// Liveness of `store` at `now_ms`, from [`stale_after_ms`].
pub fn stall_status(cfg: &ChainConfig, store: &Store, now_ms: u64) -> StallStatus {
    let stale = stale_after_ms(cfg, store);
    if now_ms < stale {
        StallStatus::Live {
            remaining_ms: stale - now_ms,
        }
    } else {
        StallStatus::Stalled
    }
}

/// Acceptance policy of [`verify_new_checkpoint`].
#[derive(Clone, Debug)]
pub struct CheckpointPolicy {
    /// Endpoints that must answer and agree.
    pub min_endpoints: usize,
    /// Maximum checkpoint age. The default, 256 epochs, is
    /// `MIN_VALIDATOR_WITHDRAWABILITY_DELAY`, the floor of
    /// `compute_weak_subjectivity_period` (`specs/phase0/weak-subjectivity.md`,
    /// `specs/electra/weak-subjectivity.md`, `specs/gloas/weak-subjectivity.md`).
    pub max_age_epochs: u64,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            min_endpoints: 2,
            max_age_epochs: 256,
        }
    }
}

/// Reasons [`verify_new_checkpoint`] refuses a checkpoint.
#[derive(Debug)]
pub enum CheckpointError {
    /// Fewer endpoints answered than the policy requires.
    TooFewEndpoints { answered: usize, required: usize },
    /// An endpoint reports another genesis validators root.
    GenesisMismatch { endpoint: String },
    /// An endpoint reports the root as orphaned or unfinalized.
    NotFinalized { endpoint: String },
    /// Endpoints serve different bootstrap bytes.
    BootstrapMismatch { endpoint: String },
    /// The bootstrap fails `initialize_store`.
    Initialize(eth_lc_core::Error),
    /// The checkpoint is older than the policy allows.
    TooOld { age_ms: u64, max_ms: u64 },
    /// A response failed to decode.
    Decode { endpoint: String, reason: String },
    /// An endpoint reports another value for a chain config field.
    ConfigMismatch { endpoint: String, field: String },
    /// No execution endpoint served the RLP header a Gloas-variant bootstrap needs.
    MissingExecutionHeader { reason: String },
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for CheckpointError {}

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// The chain config fields of `cfg` as Beacon API strings, with their keys.
fn expected_fields(cfg: &ChainConfig) -> Vec<(String, String)> {
    let mut v = vec![
        ("SECONDS_PER_SLOT".into(), cfg.seconds_per_slot.to_string()),
        ("SLOTS_PER_EPOCH".into(), cfg.slots_per_epoch.to_string()),
        (
            "EPOCHS_PER_SYNC_COMMITTEE_PERIOD".into(),
            cfg.epochs_per_sync_committee_period.to_string(),
        ),
        (
            "SYNC_COMMITTEE_SIZE".into(),
            cfg.sync_committee_size.to_string(),
        ),
    ];
    for (key, fork) in FORK_KEYS.iter().zip(&cfg.forks) {
        v.push((format!("{key}_FORK_VERSION"), hex0x(&fork.version)));
        if *key != "GENESIS" {
            v.push((format!("{key}_FORK_EPOCH"), fork.epoch.to_string()));
        }
    }
    v
}

/// Checks the chain config of an instance against the chain.
///
/// Succeeds only when: at least `min_endpoints` Beacon API endpoints answer;
/// each reports, in `/eth/v1/beacon/genesis` and `/eth/v1/config/spec`, the
/// config's genesis validators root, genesis time, preset fields, and every
/// fork version and epoch from phase0 through Gloas; at least one execution
/// endpoint answers `eth_chainId`; and each that answers reports `chain_id`.
pub fn verify_instance_config(
    cfg: &ChainConfig,
    endpoints: &[String],
    rpc_urls: &[String],
    policy: &CheckpointPolicy,
) -> Result<(), CheckpointError> {
    let answers: Vec<(String, Value, Value)> = endpoints
        .iter()
        .filter_map(|e| {
            let genesis = get_json(e, "/eth/v1/beacon/genesis").ok()?;
            let spec = get_json(e, "/eth/v1/config/spec").ok()?;
            Some((e.clone(), genesis, spec))
        })
        .collect();
    if answers.len() < policy.min_endpoints.max(1) {
        return Err(CheckpointError::TooFewEndpoints {
            answered: answers.len(),
            required: policy.min_endpoints,
        });
    }
    let fields = expected_fields(cfg);
    for (endpoint, genesis, spec) in &answers {
        let mismatch = |field: &str| CheckpointError::ConfigMismatch {
            endpoint: endpoint.clone(),
            field: field.to_string(),
        };
        let g = &genesis["data"];
        if g["genesis_validators_root"].as_str() != Some(&hex0x(&cfg.genesis_validators_root)) {
            return Err(CheckpointError::GenesisMismatch {
                endpoint: endpoint.clone(),
            });
        }
        if g["genesis_time"].as_str() != Some(&cfg.genesis_time.to_string()) {
            return Err(mismatch("genesis_time"));
        }
        for (key, want) in &fields {
            let got = spec["data"][key].as_str().map(str::to_ascii_lowercase);
            if got.as_deref() != Some(want.as_str()) {
                return Err(mismatch(key));
            }
        }
    }
    let mut chain_ids = 0;
    for url in rpc_urls {
        let Ok(id) = rpc(url, "eth_chainId", json!([])) else {
            continue;
        };
        if quantity(&id).ok() != Some(cfg.chain_id) {
            return Err(CheckpointError::ConfigMismatch {
                endpoint: url.clone(),
                field: "chain_id".into(),
            });
        }
        chain_ids += 1;
    }
    if chain_ids == 0 {
        return Err(CheckpointError::TooFewEndpoints {
            answered: 0,
            required: 1,
        });
    }
    Ok(())
}

struct Answer {
    endpoint: String,
    genesis: Value,
    header: Value,
    bootstrap: Value,
    /// `finalized.root` of `/eth/v1/beacon/states/head/finality_checkpoints`,
    /// asked only when the header response leaves `finalized` unset or false.
    finalized_checkpoint: Option<String>,
}

fn ask(endpoint: &str, root_hex: &str) -> anyhow::Result<Answer> {
    let header = get_json(endpoint, &format!("/eth/v1/beacon/headers/{root_hex}"))?;
    // Lodestar sets `finalized: false` on the header of the finalized checkpoint
    // itself; its checkpoint response names the root.
    let finalized_checkpoint = (header["finalized"] != Value::Bool(true))
        .then(|| get_json(endpoint, "/eth/v1/beacon/states/head/finality_checkpoints").ok())
        .flatten()
        .and_then(|c| c["data"]["finalized"]["root"].as_str().map(str::to_string));
    Ok(Answer {
        endpoint: endpoint.to_string(),
        genesis: get_json(endpoint, "/eth/v1/beacon/genesis")?,
        header,
        bootstrap: get_json(
            endpoint,
            &format!("/eth/v1/beacon/light_client/bootstrap/{root_hex}"),
        )?,
        finalized_checkpoint,
    })
}

/// Checks the chain config and a checkpoint `root` for a new instance and
/// returns its `Init` input.
///
/// Succeeds only when: [`verify_instance_config`] succeeds; at least
/// `min_endpoints` endpoints answer; each reports `root` as canonical and
/// finalized (the header response says `finalized: true`, or `root` is the
/// endpoint's finalized checkpoint); all serve the same bootstrap (compared
/// as SSZ bytes); for a Gloas-variant bootstrap header, an execution endpoint
/// serves the RLP header of its `execution_block_hash` (checked by
/// Keccak-256);
/// `initialize_store` succeeds locally; and the checkpoint is at most
/// `max_age_epochs` old at `now_ms`.
pub fn verify_new_checkpoint(
    cfg: &ChainConfig,
    endpoints: &[String],
    rpc_urls: &[String],
    root: Root,
    now_ms: u64,
    policy: &CheckpointPolicy,
) -> Result<BootstrapInput, CheckpointError> {
    verify_instance_config(cfg, endpoints, rpc_urls, policy)?;
    let root_hex = format!("0x{}", hex::encode(root));
    let answers: Vec<Answer> = endpoints
        .iter()
        .filter_map(|e| ask(e, &root_hex).ok())
        .collect();
    if answers.len() < policy.min_endpoints.max(1) {
        return Err(CheckpointError::TooFewEndpoints {
            answered: answers.len(),
            required: policy.min_endpoints,
        });
    }
    let gvr_hex = format!("0x{}", hex::encode(cfg.genesis_validators_root));
    let preset = Preset::of(cfg).map_err(|e| CheckpointError::Decode {
        endpoint: String::new(),
        reason: e.to_string(),
    })?;
    let mut agreed: Option<(String, Vec<u8>)> = None;
    for a in &answers {
        let endpoint = a.endpoint.clone();
        if a.genesis["data"]["genesis_validators_root"].as_str() != Some(gvr_hex.as_str()) {
            return Err(CheckpointError::GenesisMismatch { endpoint });
        }
        let h = &a.header;
        let finalized = h["finalized"] == Value::Bool(true)
            || a.finalized_checkpoint.as_deref() == Some(root_hex.as_str());
        if !finalized
            || h["data"]["canonical"] != Value::Bool(true)
            || h["data"]["root"].as_str() != Some(root_hex.as_str())
        {
            return Err(CheckpointError::NotFinalized { endpoint });
        }
        let decode = |reason: String| CheckpointError::Decode {
            endpoint: endpoint.clone(),
            reason,
        };
        let version = a.bootstrap["version"]
            .as_str()
            .ok_or_else(|| decode("bootstrap version".into()))?
            .to_string();
        let fork = forks::parse_fork(&version).map_err(|e| decode(e.to_string()))?;
        let bytes = json_to_ssz(Kind::Bootstrap, fork, preset, &a.bootstrap["data"])
            .map_err(|e| decode(e.to_string()))?;
        match &agreed {
            None => agreed = Some((version, bytes)),
            Some(first) if *first == (version, bytes) => {}
            Some(_) => return Err(CheckpointError::BootstrapMismatch { endpoint }),
        }
    }
    let Some((version, bytes)) = agreed else {
        return Err(CheckpointError::TooFewEndpoints {
            answered: 0,
            required: policy.min_endpoints,
        });
    };
    let decode = |reason: String| CheckpointError::Decode {
        endpoint: String::new(),
        reason,
    };
    let fork = forks::parse_fork(&version).map_err(|e| decode(e.to_string()))?;
    let raw = forks::decode_bootstrap(fork, preset, Wire::Ssz(&bytes))
        .map_err(|e| decode(e.to_string()))?;
    let bootstrap = forks::to_core_bootstrap(cfg, &raw).map_err(|e| decode(e.to_string()))?;
    let execution_header_rlp = match &bootstrap.header {
        LightClientHeader::Gloas {
            execution_block_hash,
            ..
        } => Some(execution_header(rpc_urls, *execution_block_hash)?),
        _ => None,
    };
    let input = BootstrapInput {
        trusted_block_root: root,
        bootstrap,
        execution_header_rlp,
    };
    initialize_store(cfg, &input).map_err(CheckpointError::Initialize)?;

    let max_ms = policy
        .max_age_epochs
        .saturating_mul(cfg.slots_per_epoch)
        .saturating_mul(cfg.seconds_per_slot)
        .saturating_mul(1000);
    let age_ms = now_ms.saturating_sub(cfg.slot_start_ms(input.bootstrap.header.beacon().slot));
    if age_ms > max_ms {
        return Err(CheckpointError::TooOld { age_ms, max_ms });
    }
    Ok(input)
}

/// The RLP header of `block_hash` from the first execution endpoint that
/// serves it; `fetch_header_rlp` checks it by Keccak-256.
fn execution_header(rpc_urls: &[String], block_hash: Root) -> Result<Vec<u8>, CheckpointError> {
    let mut reasons = Vec::new();
    for url in rpc_urls {
        match fetch_header_rlp(url, block_hash) {
            Ok(rlp) => return Ok(rlp),
            Err(e) => reasons.push(format!("{url}: {e}")),
        }
    }
    Err(CheckpointError::MissingExecutionHeader {
        reason: reasons.join("; "),
    })
}
