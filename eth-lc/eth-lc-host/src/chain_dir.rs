//! Recorded chain directories: a bootstrap at a trusted root, consecutive
//! period updates, and a finality update, as SSZ files plus `chain.json`.
//!
//! ```text
//! chain.json            {"network", "trusted_block_root", "bootstrap", "updates", "finality_update"}
//! bootstrap.ssz         LightClientBootstrap of the named fork layout
//! update-<period>.ssz   LightClientUpdate (Beacon API `updates`, one per period)
//! finality-update.ssz   LightClientFinalityUpdate
//! execution/<hash>.rlp  RLP execution headers (optional), keyed by their Keccak-256
//! ```
//!
//! Gloas-variant headers take their anchor from an RLP execution header.
//! `load` reads every file in `execution/` and keys it by its own hash, so a
//! file can only supply the block whose hash it has.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use eth_lc_core::crypto::keccak256;
use eth_lc_core::{
    BootstrapInput, ChainConfig, LightClientHeader, LightClientUpdate, Root, Store, SyncCommittee,
    UpdateInput,
};
use serde::{Deserialize, Serialize};

use crate::forks::{self, Preset, Wire};
use crate::hints::key_hints;

/// One recorded object: its data fork layout and file name.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    pub fork: String,
    pub file: String,
}

/// `chain.json`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub network: String,
    pub trusted_block_root: String,
    pub bootstrap: Entry,
    pub updates: Vec<Entry>,
    pub finality_update: Option<Entry>,
}

/// A loaded chain directory in core types.
#[derive(Clone, Debug)]
pub struct ChainDir {
    pub cfg: ChainConfig,
    pub bootstrap: BootstrapInput,
    pub updates: Vec<LightClientUpdate>,
    pub finality_update: Option<LightClientUpdate>,
    /// RLP execution headers by block hash, from `execution/`.
    pub execution_headers: HashMap<Root, Vec<u8>>,
}

/// The execution block hash a header names: the payload's `block_hash`
/// (Capella and Deneb variants) or `execution_block_hash` (Gloas variant).
pub fn execution_block_hash(h: &LightClientHeader) -> Root {
    match h {
        LightClientHeader::Capella { execution, .. } => execution.block_hash,
        LightClientHeader::Deneb { execution, .. } => execution.block_hash,
        LightClientHeader::Gloas {
            execution_block_hash,
            ..
        } => *execution_block_hash,
    }
}

/// Parses a `0x`-prefixed 32-byte hex string.
pub fn parse_root(s: &str) -> Result<Root> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("root {s} is not 32 bytes"))
}

/// The config constructor of a network name.
pub fn network_config(name: &str) -> Result<ChainConfig> {
    match name {
        "mainnet" => Ok(ChainConfig::mainnet()),
        "sepolia" => Ok(ChainConfig::sepolia()),
        "hoodi" => Ok(ChainConfig::hoodi()),
        other => bail!("no config constructor for network {other}"),
    }
}

impl ChainDir {
    /// Loads `dir/chain.json` and the files it names.
    pub fn load(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let manifest: Manifest =
            serde_json::from_slice(&std::fs::read(dir.join("chain.json")).context("chain.json")?)?;
        let cfg = network_config(&manifest.network)?;
        let preset = Preset::of(&cfg)?;
        let read = |e: &Entry| -> Result<(eth_lc_core::ForkName, Vec<u8>)> {
            let path: PathBuf = dir.join(&e.file);
            Ok((
                forks::parse_fork(&e.fork)?,
                std::fs::read(&path).with_context(|| path.display().to_string())?,
            ))
        };
        let (fork, bytes) = read(&manifest.bootstrap)?;
        let mut execution_headers = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(dir.join("execution")) {
            for e in entries {
                let rlp = std::fs::read(e?.path())?;
                execution_headers.insert(keccak256(&rlp), rlp);
            }
        }
        let raw = forks::decode_bootstrap(fork, preset, Wire::Ssz(&bytes))?;
        let header = forks::to_core_bootstrap(&cfg, &raw)?;
        let bootstrap = BootstrapInput {
            trusted_block_root: parse_root(&manifest.trusted_block_root)?,
            execution_header_rlp: gloas_preimage(&execution_headers, &header.header)?,
            bootstrap: header,
        };
        let updates = manifest
            .updates
            .iter()
            .map(|e| {
                let (fork, bytes) = read(e)?;
                forks::to_core_update(
                    &cfg,
                    &forks::decode_update(fork, preset, Wire::Ssz(&bytes))?,
                )
            })
            .collect::<Result<_>>()?;
        let finality_update = manifest
            .finality_update
            .as_ref()
            .map(|e| {
                let (fork, bytes) = read(e)?;
                forks::to_core_update(
                    &cfg,
                    &forks::decode_finality_update(fork, preset, Wire::Ssz(&bytes))?,
                )
            })
            .transpose()?;
        Ok(Self {
            cfg,
            bootstrap,
            updates,
            finality_update,
            execution_headers,
        })
    }
}

/// The preimage a header's anchor needs: `None` for Capella and Deneb
/// variants, the recorded RLP header for a Gloas variant.
fn gloas_preimage(
    headers: &HashMap<Root, Vec<u8>>,
    h: &LightClientHeader,
) -> Result<Option<Vec<u8>>> {
    match h {
        LightClientHeader::Gloas {
            execution_block_hash,
            ..
        } => headers
            .get(execution_block_hash)
            .cloned()
            .map(Some)
            .with_context(|| {
                format!(
                    "no recorded execution header 0x{}",
                    hex::encode(execution_block_hash)
                )
            }),
        _ => Ok(None),
    }
}

impl ChainDir {
    /// The committee behind the store root that `update`'s signature period
    /// selects, from the committees this directory carries.
    pub fn committee_for(
        &self,
        store: &Store,
        update: &LightClientUpdate,
    ) -> Result<SyncCommittee> {
        let cfg = &self.cfg;
        let want = if cfg.period_at_slot(update.signature_slot)
            == cfg.period_at_slot(store.finalized.slot)
        {
            Some(store.current_committee_root)
        } else {
            store.next_committee_root
        };
        std::iter::once(&self.bootstrap.bootstrap.current_sync_committee)
            .chain(
                self.updates
                    .iter()
                    .filter_map(|u| u.next_sync_committee.as_ref().map(|(c, _)| c)),
            )
            .find(|c| Some(c.hash_tree_root()) == want)
            .cloned()
            .context("no recorded committee matches the selected store root")
    }

    /// The guest input for `update` on top of `store`: the signing committee,
    /// its key hints, and the RLP execution header when a Gloas-variant
    /// finalized header advances the store.
    pub fn update_input(&self, store: &Store, update: &LightClientUpdate) -> Result<UpdateInput> {
        let committee = self.committee_for(store, update)?;
        let execution_header_rlp = match &update.finality {
            Some((h, _)) if h.beacon().slot > store.finalized.slot => {
                gloas_preimage(&self.execution_headers, h)?
            }
            _ => None,
        };
        Ok(UpdateInput {
            hints: key_hints(&committee, &update.sync_aggregate.bits)?,
            committee,
            update: update.clone(),
            execution_header_rlp,
        })
    }

    /// All recorded updates in order: the period updates, then the finality update.
    pub fn all_updates(&self) -> impl Iterator<Item = &LightClientUpdate> {
        self.updates.iter().chain(self.finality_update.iter())
    }
}
