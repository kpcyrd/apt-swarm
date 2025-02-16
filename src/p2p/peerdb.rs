use crate::config::Config;
use crate::errors::*;
use crate::p2p::proto::PeerAddr;
use chrono::{DateTime, Utc};
use colored::{Color, Colorize};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
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

    pub fn format_stats(&self) -> String {
        format!(
            "last_attempt={:<19}  errors_since={}  last_success={}",
            Self::format_time_opt(self.last_attempt).yellow(),
            self.errors_since
                .to_string()
                .color(if self.errors_since == 0 {
                    Color::Green
                } else {
                    Color::Red
                }),
            Self::format_time_opt(self.last_success).yellow(),
        )
    }

    fn format_time_opt(time: Option<DateTime<Utc>>) -> Cow<'static, str> {
        if let Some(time) = time {
            Cow::Owned(Self::format_time(time))
        } else {
            Cow::Borrowed("-")
        }
    }

    fn format_time(time: DateTime<Utc>) -> String {
        time.format("%FT%T").to_string()
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
    pub last_advertised: Option<DateTime<Utc>>,
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
    /// Register a peer address in the database
    ///
    /// Returns true if we haven't known this address before.
    pub fn add_peer(&mut self, addr: PeerAddr) -> (&mut PeerStats, bool) {
        trace!("Adding address to peerdb: {addr:?}");
        match self.data.peers.entry(addr) {
            entry @ Entry::Vacant(_) => (entry.or_default(), true),
            entry @ Entry::Occupied(_) => (entry.or_default(), false),
        }
    }

    /// Register a list of peers that has been actively advertised to us
    ///
    /// The database should always be written afterwards to `last_advertised`
    /// is persisted properly.
    pub fn add_advertised_peers(&mut self, addrs: &[PeerAddr]) {
        let now = Utc::now();
        for addr in addrs {
            let (peer, _new) = self.add_peer(addr.clone());
            peer.last_advertised = Some(now);
        }
    }

    pub fn peers(&self) -> &BTreeMap<PeerAddr, PeerStats> {
        &self.data.peers
    }

    /// Return a sample of random peers to connect to
    pub fn sample(&self) -> Vec<PeerAddr> {
        let Some((first, _)) = fastrand::choice(&self.data.peers) else {
            return Vec::new();
        };
        // TODO: make this smarter
        vec![first.clone()]
    }

    /// Remove old peers that both:
    ///
    /// - we couldn't successfully connect/handshake with in a while
    /// - haven't been advertised anymore in a while
    ///
    /// Peers that are still being advertised, but we couldn't
    /// connect/handshake with in a while are still being kept around so we don't
    /// stop toning down our connection attempts to them.
    ///
    /// Returns true if any peers have been removed.
    pub fn gc_old_peers(&mut self) -> bool {
        false
    }

    /// Load the local peerdb file from disk.
    ///
    /// If this fails, return an empty database so we self-heal.
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

    /// Write the peerdb to disk, in a way so we don't accidentally lose data
    /// on an unexpected crash
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
