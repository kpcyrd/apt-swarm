use crate::config::Config;
use crate::errors::*;
use crate::p2p::proto::PeerAddr;
use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use tokio::fs;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PeerStats {}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PeerDb {
    pub peers: BTreeMap<PeerAddr, PeerStats>,
}

impl PeerDb {
    pub fn add_peer(&mut self, addr: PeerAddr) -> (&mut PeerStats, bool) {
        match self.peers.entry(addr) {
            entry @ Entry::Vacant(_) => (entry.or_default(), true),
            entry @ Entry::Occupied(_) => (entry.or_default(), false),
        }
    }

    pub async fn read(config: &Config) -> Result<Self> {
        let path = config.peerdb_path()?;
        debug!("Reading peerdb from file: {path:?}");
        let Ok(buf) = fs::read(&path).await else {
            debug!("Failed to read peerdb file, using empty");
            return Ok(PeerDb::default());
        };
        let Ok(db) = serde_json::from_slice(&buf) else {
            debug!("Failed to parse peerdb file, using empty");
            return Ok(PeerDb::default());
        };
        Ok(db)
    }

    pub async fn write(&self, config: &Config) -> Result<()> {
        let buf = serde_json::to_string(self).context("Failed to serialize peerdb")?;
        let new_path = config.peerdb_new_path()?;
        debug!("Writing peerdb file to disk: {new_path:?}");
        fs::write(&new_path, &buf)
            .await
            .with_context(|| anyhow!("Failed to write peerdb file at {new_path:?}"))?;
        let path = config.peerdb_path()?;
        debug!("Moving peerdb file to final location: {path:?}");
        fs::rename(&new_path, &path)
            .await
            .with_context(|| anyhow!("Failed to rename peerdb {new_path:?} to {path:?}"))?;
        Ok(())
    }
}
