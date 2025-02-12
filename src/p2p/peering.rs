use crate::db::DatabaseClient;
use crate::errors::*;
use crate::keyring::Keyring;
use crate::p2p;
use crate::p2p::proto::PeerAddr;
use crate::sync;
use ipnetwork::IpNetwork;
use sequoia_openpgp::Fingerprint;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time;

pub static P2P_BLOCK_LIST: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| {
    vec![
        "127.0.0.1/8".parse().unwrap(),
        "10.0.0.1/8".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
        "192.168.0.0/16".parse().unwrap(),
        "169.254.0.0/16".parse().unwrap(),
        "224.0.0.0/4".parse().unwrap(),
    ]
});
pub static P2P_ILLEGAL_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 587, 993, 995, 1194, 3128, 3389, 5900, 6667, 6669,
    6697, 8080,
];

// When an ip is in cooldown, this port is still allowed, until the specific port goes into cooldown too
pub const STANDARD_P2P_PORT: u16 = 16169;

pub const COOLDOWN_LRU_SIZE: usize = 16_384;
pub const COOLDOWN_PORT_AFTER_SUCCESS: Duration = Duration::from_secs(60 * 5); // 5min
pub const COOLDOWN_PORT_AFTER_ERROR: Duration = Duration::from_secs(60 * 60); // 1hour
pub const COOLDOWN_HOST_AFTER_ERROR: Duration = Duration::from_secs(60 * 60); // 1hour
pub const COOLDOWN_HOST_THRESHOLD: usize = 10;

pub async fn pull_from_peer<D: DatabaseClient + Sync + Send>(
    db: &mut D,
    keyring: &Keyring,
    fingerprints: &[Fingerprint],
    addr: &PeerAddr,
    proxy: Option<SocketAddr>,
) -> Result<()> {
    let mut sock = sync::connect(addr, proxy).await?;
    let (rx, mut tx) = sock.split();

    let result = sync::sync_pull(db, keyring, fingerprints, false, &mut tx, rx).await;

    tx.shutdown().await.ok();
    result
}

#[derive(Debug, Default)]
pub struct CooldownEntry {
    tries: VecDeque<time::Instant>,
}

impl CooldownEntry {
    fn filter(&mut self) {
        let now = time::Instant::now();
        self.tries.retain(|e| now < *e);
    }

    pub fn has_capacity(&mut self) -> bool {
        self.filter();
        self.tries.len() < COOLDOWN_HOST_THRESHOLD
    }

    pub fn mark_bad(&mut self) {
        self.filter();
        self.tries
            .push_back(time::Instant::now() + COOLDOWN_HOST_AFTER_ERROR);
    }
}

#[derive(Debug)]
pub struct Cooldowns {
    ip_cache: lru::LruCache<IpAddr, CooldownEntry>,
    port_cache: lru::LruCache<PeerAddr, time::Instant>,
}

impl Cooldowns {
    pub fn new() -> Self {
        let ip_cache = lru::LruCache::new(NonZeroUsize::new(COOLDOWN_LRU_SIZE).unwrap());
        let port_cache = lru::LruCache::new(NonZeroUsize::new(COOLDOWN_LRU_SIZE).unwrap());
        Cooldowns {
            ip_cache,
            port_cache,
        }
    }

    pub fn can_approach(&mut self, addr: &PeerAddr) -> bool {
        let now = time::Instant::now();

        if let PeerAddr::Inet(addr) = &addr {
            if addr.port() != STANDARD_P2P_PORT {
                if let Some(entry) = self.ip_cache.get_mut(&addr.ip()) {
                    if !entry.has_capacity() {
                        return false;
                    }
                }
            }
        }

        if let Some(entry) = self.port_cache.get(addr) {
            now >= *entry
        } else {
            true
        }
    }

    pub fn mark_ok(&mut self, addr: PeerAddr) {
        self.port_cache
            .put(addr, time::Instant::now() + COOLDOWN_PORT_AFTER_SUCCESS);
    }

    pub fn mark_bad(&mut self, addr: PeerAddr) {
        if let PeerAddr::Inet(addr) = &addr {
            self.ip_cache
                .get_or_insert_mut(addr.ip(), CooldownEntry::default)
                .mark_bad();
        }

        self.port_cache
            .put(addr, time::Instant::now() + COOLDOWN_PORT_AFTER_ERROR);
    }
}

impl Default for Cooldowns {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn spawn<D: DatabaseClient + Sync + Send>(
    db: &mut D,
    keyring: Keyring,
    proxy: Option<SocketAddr>,
    mut rx: mpsc::Receiver<p2p::proto::PeerGossip>,
) -> Result<Infallible> {
    // keep track of connection attempts to avoid flooding
    let mut cooldown = Cooldowns::new();

    while let Some(gossip) = rx.recv().await {
        // TODO: only connect if we're not already in sync
        // TODO: allow concurrent syncs

        for addr in &gossip.addrs {
            if let PeerAddr::Inet(addr) = &addr {
                for block in P2P_BLOCK_LIST.iter() {
                    if block.contains(addr.ip()) {
                        debug!(
                            "Address is on a blocklist, skipping: addr={addr:?}, block={block:?}"
                        );
                        continue;
                    }
                }
                if P2P_ILLEGAL_PORTS.contains(&addr.port()) {
                    debug!("Port is on blocklist, skipping: addr={addr:?}");
                    continue;
                }
            }

            if !cooldown.can_approach(addr) {
                debug!("Address is still in cooldown, skipping for now: {addr:?}");
                continue;
            }

            p2p::random_jitter(p2p::P2P_SYNC_CONNECT_JITTER).await;

            info!("Syncing from remote peer: {addr:?}");
            let ret = pull_from_peer(db, &keyring, &[], addr, proxy).await;
            debug!("Connection to {addr:?} has been closed");
            match ret {
                Ok(_) => {
                    cooldown.mark_ok(addr.clone());
                    break;
                }
                Err(err) => {
                    warn!("Error while syncing from peer {addr:?}: {err:#}");
                    cooldown.mark_bad(addr.clone());
                }
            }
        }
    }

    bail!("Peering task has crashed")
}
