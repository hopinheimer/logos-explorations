//! Recorded chain directories: a bootstrap at a trusted root, consecutive
//! period updates, and a finality update, as SSZ files plus `chain.json`.
//!
//! ```text
//! chain.json            {"network", "trusted_block_root", "bootstrap", "updates", "finality_update"}
//! bootstrap.ssz         LightClientBootstrap of the named fork layout
//! update-<period>.ssz   LightClientUpdate (Beacon API `updates`, one per period)
//! finality-update.ssz   LightClientFinalityUpdate
//! ```

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use eth_lc_core::{
    profile, BootstrapInput, ChainConfig, LightClientUpdate, Root, Store, SyncCommittee,
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
}

/// Parses a `0x`-prefixed 32-byte hex string.
pub fn parse_root(s: &str) -> Result<Root> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("root {s} is not 32 bytes"))
}

/// The pinned config of a network name.
pub fn network_config(name: &str) -> Result<ChainConfig> {
    match name {
        "mainnet" => Ok(profile::mainnet()),
        other => bail!("no pinned profile for network {other}"),
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
        let raw = forks::decode_bootstrap(fork, preset, Wire::Ssz(&bytes))?;
        let bootstrap = BootstrapInput {
            trusted_block_root: parse_root(&manifest.trusted_block_root)?,
            bootstrap: forks::to_core_bootstrap(&cfg, &raw)?,
            execution_header_rlp: None,
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
        })
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

    /// The guest input for `update` on top of `store`: the signing committee and its key hints.
    pub fn update_input(&self, store: &Store, update: &LightClientUpdate) -> Result<UpdateInput> {
        let committee = self.committee_for(store, update)?;
        Ok(UpdateInput {
            hints: key_hints(&committee, &update.sync_aggregate.bits)?,
            committee,
            update: update.clone(),
            execution_header_rlp: None,
        })
    }

    /// All recorded updates in order: the period updates, then the finality update.
    pub fn all_updates(&self) -> impl Iterator<Item = &LightClientUpdate> {
        self.updates.iter().chain(self.finality_update.iter())
    }
}
