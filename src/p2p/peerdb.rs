use crate::config::Config;
use crate::errors::*;
use crate::p2p::proto::PeerAddr;
use chrono::{DateTime, Utc};
use colored::{Color, Colorize};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time;

const EXPIRE_ERROR_THRESHOLD: usize = 30;
const EXPIRE_UNLESS_ADVERTISED_SINCE: Duration = Duration::from_secs(3600 * 24 * 14);

const PEERDB_EXPIRE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum Req {
    AddAdvertisedPeers(Vec<PeerAddr>),
    Sample(mpsc::Sender<Vec<PeerAddr>>),
    Metric {
        metric: MetricType,
        value: MetricValue,
        addr: PeerAddr,
    },
    Write,
}

#[derive(Debug, Clone)]
pub struct Client {
    tx: mpsc::Sender<Req>,
}

impl Client {
    pub fn new() -> (Self, mpsc::Receiver<Req>) {
        let (tx, rx) = mpsc::channel(1024);
        (Self { tx }, rx)
    }

    async fn request<T>(&self, req: Req, mut rx: mpsc::Receiver<T>) -> Result<T> {
        self.tx
            .send(req)
            .await
            .map_err(|_| anyhow!("PeerDb server disconnected"))?;
        let ret = rx.recv().await.context("PeerDb server disconnected")?;
        Ok(ret)
    }

    fn lossy_send(&self, req: Req) {
        if let Err(TrySendError::Full(req)) = self.tx.try_send(req) {
            warn!("Discarding peerdb request because backlog is full: {req:?}");
        }
    }

    pub fn add_advertised_peers(&self, addrs: Vec<PeerAddr>) {
        self.lossy_send(Req::AddAdvertisedPeers(addrs));
    }

    #[inline]
    pub fn successful(&self, metric: MetricType, addr: PeerAddr) {
        self.lossy_send(Req::Metric {
            metric,
            value: MetricValue::Successful,
            addr,
        })
    }

    #[inline]
    pub fn error(&self, metric: MetricType, addr: PeerAddr) {
        self.lossy_send(Req::Metric {
            metric,
            value: MetricValue::Error,
            addr,
        })
    }

    pub async fn sample(&self) -> Result<Vec<PeerAddr>> {
        let (tx, rx) = mpsc::channel(1);
        self.request(Req::Sample(tx), rx).await
    }

    pub fn write(&self) {
        self.lossy_send(Req::Write);
    }
}

pub fn format_time_opt(time: Option<DateTime<Utc>>) -> Cow<'static, str> {
    if let Some(time) = time {
        Cow::Owned(format_time(time))
    } else {
        Cow::Borrowed("-")
    }
}

pub fn format_time(time: DateTime<Utc>) -> String {
    time.format("%FT%T").to_string()
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Metric {
    pub last_attempt: Option<DateTime<Utc>>,
    pub errors_since: usize,
    pub last_success: Option<DateTime<Utc>>,
}

impl Metric {
    pub fn metric(&mut self, value: MetricValue) {
        match value {
            MetricValue::Successful => self.successful(),
            MetricValue::Error => self.error(),
        }
    }

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
            format_time_opt(self.last_attempt).yellow(),
            self.errors_since
                .to_string()
                .color(if self.errors_since == 0 {
                    Color::Green
                } else {
                    Color::Red
                }),
            format_time_opt(self.last_success).yellow(),
        )
    }
}

#[derive(Debug)]
pub enum MetricType {
    Connect,
    Handshake,
}

#[derive(Debug)]
pub enum MetricValue {
    Successful,
    Error,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PeerStats {
    #[serde(default)]
    pub connect: Metric,
    #[serde(default)]
    pub handshake: Metric,
    pub last_advertised: Option<DateTime<Utc>>,
}

impl PeerStats {
    pub fn metric(&mut self, metric: MetricType, value: MetricValue) {
        match metric {
            MetricType::Connect => self.connect.metric(value),
            MetricType::Handshake => self.handshake.metric(value),
        }
    }

    pub fn expired(&self, now: DateTime<Utc>) -> bool {
        // only remove peers that have been advertised, but not recently
        let Some(last_advertised) = self.last_advertised else {
            return false;
        };
        if last_advertised + EXPIRE_UNLESS_ADVERTISED_SINCE > now {
            return false;
        }

        // expire peers we couldn't connect to in a while
        if self.connect.errors_since > EXPIRE_ERROR_THRESHOLD {
            return true;
        }

        // expire peers we couldn't handshake with in a while
        if self.handshake.errors_since > EXPIRE_ERROR_THRESHOLD {
            return true;
        }

        // peer is still good
        false
    }
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
    pub fn expire_old_peers(&mut self, now: DateTime<Utc>) -> bool {
        let before = self.data.peers.len();
        self.data.peers.retain(|_, peer| !peer.expired(now));
        let after = self.data.peers.len();
        if after != before {
            info!("Removed {} expired peers", before.saturating_sub(after));
            true
        } else {
            false
        }
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

pub async fn spawn(mut peerdb: PeerDb, mut rx: mpsc::Receiver<Req>) -> Result<Infallible> {
    let mut interval = time::interval(PEERDB_EXPIRE_INTERVAL);

    loop {
        tokio::select! {
            req = rx.recv() => {
                let Some(req) = req else { break };
                match req {
                    Req::AddAdvertisedPeers(addrs) => {
                        peerdb.add_advertised_peers(&addrs);
                        peerdb.write().await?;
                    }
                    Req::Sample(tx) => {
                        let sample = peerdb.sample();
                        tx.send(sample).await.ok();
                    }
                    Req::Metric { metric, value, addr } => {
                        let (peer, _new) = peerdb.add_peer(addr);
                        peer.metric(metric, value);
                    }
                    Req::Write => peerdb.write().await?,
                }
            }
            _ = interval.tick() => {
                if peerdb.expire_old_peers(Utc::now()) {
                    peerdb.write().await?;
                }
            }
        }
    }
    bail!("PeerDb channel has been closed");
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

    #[test]
    fn test_expired_peers() {
        fn datetime(s: &str) -> DateTime<Utc> {
            s.parse::<DateTime<Utc>>().unwrap()
        }
        let now = datetime("2025-02-17T01:00:00Z");

        // empty
        assert!(!PeerStats {
            connect: Metric::default(),
            handshake: Metric::default(),
            last_advertised: None,
        }
        .expired(now));

        // connect errors
        assert!(PeerStats {
            connect: Metric {
                last_attempt: Some(datetime("2025-02-17T00:45:00Z")),
                errors_since: 500,
                last_success: None,
            },
            handshake: Metric::default(),
            last_advertised: Some(datetime("2025-01-01T13:37:00Z")),
        }
        .expired(now));

        // handshake errors
        assert!(PeerStats {
            connect: Metric {
                last_attempt: Some(datetime("2025-02-17T00:45:00Z")),
                errors_since: 0,
                last_success: Some(datetime("2025-02-17T00:45:00Z")),
            },
            handshake: Metric {
                last_attempt: Some(datetime("2025-02-17T00:45:00Z")),
                errors_since: 500,
                last_success: Some(datetime("2025-01-14T00:45:00Z")),
            },
            last_advertised: Some(datetime("2025-01-01T13:37:00Z")),
        }
        .expired(now));

        // connect errors but recently advertised
        assert!(!PeerStats {
            connect: Metric {
                last_attempt: Some(datetime("2025-02-17T00:45:00Z")),
                errors_since: 500,
                last_success: None,
            },
            handshake: Metric::default(),
            last_advertised: Some(datetime("2025-02-14T13:37:00Z")),
        }
        .expired(now));

        // handshake errors but recently advertised
        assert!(!PeerStats {
            connect: Metric {
                last_attempt: Some(datetime("2025-02-17T00:45:00Z")),
                errors_since: 0,
                last_success: Some(datetime("2025-02-17T00:45:00Z")),
            },
            handshake: Metric {
                last_attempt: Some(datetime("2025-02-17T00:45:00Z")),
                errors_since: 500,
                last_success: Some(datetime("2025-01-14T00:45:00Z")),
            },
            last_advertised: Some(datetime("2025-02-14T13:37:00Z")),
        }
        .expired(now));

        // connect errors but never advertised
        assert!(!PeerStats {
            connect: Metric {
                last_attempt: Some(datetime("2025-02-17T00:45:00Z")),
                errors_since: 500,
                last_success: None,
            },
            handshake: Metric::default(),
            last_advertised: None,
        }
        .expired(now));

        // handshake errors but never advertised
        assert!(!PeerStats {
            connect: Metric {
                last_attempt: Some(datetime("2025-02-17T00:45:00Z")),
                errors_since: 0,
                last_success: Some(datetime("2025-02-17T00:45:00Z")),
            },
            handshake: Metric {
                last_attempt: Some(datetime("2025-02-17T00:45:00Z")),
                errors_since: 500,
                last_success: Some(datetime("2025-01-14T00:45:00Z")),
            },
            last_advertised: None,
        }
        .expired(now));
    }
}
