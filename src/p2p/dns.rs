use crate::errors::*;
use crate::p2p;
use crate::p2p::proto::{PeerAddr, SyncRequest};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time;

pub const DNS_SEEDS: &[&str] = &["dnsseed.apt-swarm.orca.toys"];

const DNS_DEBOUNCE: Duration = Duration::from_millis(100);
const DNS_QUERY_COOLDOWN: Duration = Duration::from_secs(60 * 60); // 1h
const DNS_QUERY_JITTER: Duration = Duration::from_secs(60 * 3); // 3min

pub async fn resolve(dns: &str) -> Result<impl Iterator<Item = SocketAddr>> {
    info!("Resolving dns name: {dns:?}");
    let host = format!("{dns}:16169");
    let stream = tokio::net::lookup_host(host.clone())
        .await
        .context(anyhow!("Failed to resolve: {host:?}"))?;
    Ok(stream)
}

pub async fn spawn(dns: Vec<String>, peering_tx: mpsc::Sender<SyncRequest>) -> Result<Infallible> {
    // briefly delay this in case we error out for some reason
    tokio::time::sleep(DNS_DEBOUNCE).await;

    loop {
        for name in &dns {
            match resolve(name).await {
                Ok(addrs) => {
                    for addr in addrs {
                        debug!("Resolved dns name to address: {addr:?}");
                        let addr = SyncRequest {
                            hint: None,
                            addrs: vec![PeerAddr::Inet(addr)],
                        };
                        if let Err(TrySendError::Full(addr)) = peering_tx.try_send(addr) {
                            warn!("Discarding addr because peering backlog is full: {addr:?}");
                        }
                    }
                }
                Err(err) => error!("Failed to query dns name {name:?}: {err:#}"),
            }
        }
        time::sleep(DNS_QUERY_COOLDOWN).await;
        p2p::random_jitter(DNS_QUERY_JITTER).await;
    }
}
