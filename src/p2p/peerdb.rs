use crate::config::Config;
use crate::errors::*;
use crate::p2p::proto::PeerAddr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::fs;

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Metric {
    pub last_attempt: Option<DateTime<Utc>>,
    pub errors_since: usize,
    pub last_success: Option<DateTime<Utc>>,
}

impl Metric {
    pub fn successful(&mut self) {
        self.errors_since = 0;
        let now = Utc::now();
        self.last_success = Some(now);
        self.last_attempt = Some(now);
    }

    pub fn error(&mut self) {
        self.errors_since += 1;
        self.last_attempt = Some(Utc::now());
    }
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PeerStats {
    #[serde(default)]
    pub connect: Metric,
    #[serde(default)]
    pub handshake: Metric,
    #[serde(default)]
    pub sync: Metric,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
struct Data {
    pub peers: BTreeMap<PeerAddr, PeerStats>,
}

pub struct PeerDb {
    data: Data,
    path: PathBuf,
    new_path: PathBuf,
}

impl PeerDb {
    pub fn add_peer(&mut self, addr: PeerAddr) -> (&mut PeerStats, bool) {
        trace!("Adding address to peerdb: {addr:?}");
        match self.data.peers.entry(addr) {
            entry @ Entry::Vacant(_) => (entry.or_default(), true),
            entry @ Entry::Occupied(_) => (entry.or_default(), false),
        }
    }

    pub fn add_peers(&mut self, addrs: &[PeerAddr]) -> bool {
        let mut any_new = false;
        for addr in addrs {
            let (_peer, new) = self.add_peer(addr.clone());
            any_new |= new;
        }
        any_new
    }

    pub fn peers(&self) -> &BTreeMap<PeerAddr, PeerStats> {
        &self.data.peers
    }

    pub fn sample(&self) -> Vec<PeerAddr> {
        let Some((first, _)) = fastrand::choice(&self.data.peers) else {
            return Vec::new();
        };
        // TODO: make this smarter
        vec![first.clone()]
    }

    pub async fn read(config: &Config) -> Result<Self> {
        let mut db = Self {
            data: Data::default(),
            path: config.peerdb_path()?,
            new_path: config.peerdb_new_path()?,
        };

        let path = &db.path;
        debug!("Reading peerdb from file: {path:?}");
        let Ok(buf) = fs::read(&path).await else {
            debug!("Failed to read peerdb file, using empty");
            return Ok(db);
        };
        let Ok(data) = serde_json::from_slice(&buf) else {
            debug!("Failed to parse peerdb file, using empty");
            return Ok(db);
        };

        db.data = data;
        Ok(db)
    }

    pub async fn write(&self) -> Result<()> {
        let buf = serde_json::to_string(&self.data).context("Failed to serialize peerdb")?;

        let new_path = &self.new_path;
        debug!("Writing peerdb file to disk: {new_path:?}");
        fs::write(&new_path, &buf)
            .await
            .with_context(|| anyhow!("Failed to write peerdb file at {new_path:?}"))?;

        let path = &self.path;
        debug!("Moving peerdb file to final location: {path:?}");
        fs::rename(&new_path, &path)
            .await
            .with_context(|| anyhow!("Failed to rename peerdb {new_path:?} to {path:?}"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_db() {
        let data = r#"
        {"peers":{"[2001:db8::]:16169":{}}}
        "#;
        let data = serde_json::from_str::<Data>(data).unwrap();
        assert_eq!(
            data,
            Data {
                peers: [("[2001:db8::]:16169".parse().unwrap(), PeerStats::default())]
                    .into_iter()
                    .collect(),
            }
        );
    }
}
