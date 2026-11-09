//! Stall detection and checkpoint checks for a new instance.
//!
//! A stalled instance stays readable. Recovery deploys a new instance with a
//! fresh `Init`, anchored at a checkpoint that [`verify_new_checkpoint`]
//! accepts. The operator chooses endpoints run by independent parties; this
//! module checks agreement among them; independence stays the operator's responsibility.

use std::fmt;

use eth_lc_core::{initialize_store, stale_after_ms, BootstrapInput, ChainConfig, Root, Store};
use serde_json::Value;

use crate::forks::{self, json_to_ssz, Kind, Preset, Wire};
use crate::http::get_json;

/// Default mainnet Beacon API endpoints for checkpoint checks.
pub const DEFAULT_ENDPOINTS: [&str; 3] = [
    "https://ethereum-beacon-api.publicnode.com",
    "https://lodestar-mainnet.chainsafe.io",
    "https://www.lightclientdata.org",
];

/// Liveness of an instance store at a given time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StallStatus {
    /// Updates can still arrive for `remaining_ms`.
    Live { remaining_ms: u64 },
    /// The window for honest updates has closed. Migrate to a new instance.
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
            min_endpoints: 3,
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
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for CheckpointError {}

struct Answer {
    endpoint: String,
    genesis: Value,
    header: Value,
    bootstrap: Value,
}

fn ask(endpoint: &str, root_hex: &str) -> anyhow::Result<Answer> {
    Ok(Answer {
        endpoint: endpoint.to_string(),
        genesis: get_json(endpoint, "/eth/v1/beacon/genesis")?,
        header: get_json(endpoint, &format!("/eth/v1/beacon/headers/{root_hex}"))?,
        bootstrap: get_json(
            endpoint,
            &format!("/eth/v1/beacon/light_client/bootstrap/{root_hex}"),
        )?,
    })
}

/// Checks a checkpoint `root` for a new instance and returns its `Init` input.
///
/// Succeeds only when: at least `min_endpoints` endpoints answer; each
/// reports `cfg.genesis_validators_root`; each reports `root` as canonical
/// and finalized; all serve the same bootstrap (compared as SSZ bytes);
/// `initialize_store` succeeds locally; and the checkpoint is at most
/// `max_age_epochs` old at `now_ms`.
pub fn verify_new_checkpoint(
    cfg: &ChainConfig,
    endpoints: &[String],
    root: Root,
    now_ms: u64,
    policy: &CheckpointPolicy,
) -> Result<BootstrapInput, CheckpointError> {
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
        if h["finalized"] != Value::Bool(true)
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
    let input = BootstrapInput {
        trusted_block_root: root,
        bootstrap,
        execution_header_rlp: None,
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
