use crate::config::Repository;
use crate::db::DatabaseClient;
use crate::errors::*;
use crate::fetch;
use crate::keyring::Keyring;
use crate::p2p;
use crate::sync;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

pub struct GossipStats {
    last_announced_index: String,
    last_announced_at: time::Instant,
    next_idle_announce_after: Duration,
}

impl GossipStats {
    pub fn new(idx: String) -> Self {
        GossipStats {
            last_announced_index: idx,
            last_announced_at: time::Instant::now(),
            next_idle_announce_after: p2p::GOSSIP_IDLE_ANNOUNCE_INTERVAL,
        }
    }

    pub fn needs_announcement(&self, idx: &str) -> bool {
        if self.last_announced_index != idx {
            true
        } else {
            let elapsed = time::Instant::now().duration_since(self.last_announced_at);
            elapsed >= self.next_idle_announce_after
        }
    }

    pub fn update_announced_index(&mut self, idx: String) {
        self.last_announced_index = idx;
        self.last_announced_at = time::Instant::now();
    }
}

pub async fn spawn_fetch_timer<D: DatabaseClient>(
    db: &mut D,
    keyring: Keyring,
    repositories: Vec<Repository>,
    proxy: Option<SocketAddr>,
    announce_addrs: Vec<SocketAddr>,
    p2p_tx: Option<mpsc::Sender<String>>,
) -> Result<Infallible> {
    let mut stats = HashMap::new();
    for key in keyring.all_fingerprints() {
        stats.insert(key, GossipStats::new("TODO".to_string()));
    }

    let keyring = Arc::new(Some(keyring));
    let mut interval = time::interval(p2p::FETCH_INTERVAL - p2p::FETCH_INTERVAL_JITTER);

    loop {
        interval.tick().await;
        p2p::random_jitter(p2p::FETCH_INTERVAL_JITTER).await;
        info!("Fetch timer has started");
        if let Err(err) =
            fetch::fetch_updates(db, keyring.clone(), None, repositories.clone(), proxy).await
        {
            error!("Fetch timer has crashed: {err:#}");
        } else {
            debug!("Fetch timer has completed");
        }

        for (fp, gossip) in &mut stats {
            let query = sync::Query {
                fp: fp.clone(),
                hash_algo: "sha256".to_string(),
                prefix: None,
            };

            match db.index_from_scan(&query).await {
                Ok((idx, count)) => {
                    debug!("Recalculated index for gossip checks: fp={fp:X} idx={idx:?} count={count:?}");
                    if count > 0 && gossip.needs_announcement(&idx) {
                        let mut msg = format!("[sync] fp={fp:X} idx={idx} count={count}");

                        for addr in &announce_addrs {
                            msg += &format!(" addr={addr}");
                        }

                        if let Some(p2p_tx) = &p2p_tx {
                            trace!("Sending to p2p channel: {:?}", msg);
                            // if the p2p channel crashed do not interrupt monitoring
                            if let Err(err) = p2p_tx.try_send(msg) {
                                warn!("Failed to send to p2p channel: {err:#}");
                            }
                        }
                        gossip.update_announced_index(idx);
                    }
                }
                Err(err) => {
                    error!("Failed to access database: {err:#}");
                }
            }
        }
    }
}
