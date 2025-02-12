#[cfg(unix)]
pub mod db;
pub mod dns;
pub mod fetch;
#[cfg(feature = "irc")]
pub mod irc;
pub mod peering;
pub mod proto;
pub mod sync;
pub mod update_check;

use crate::args::P2p;
use crate::config::Config;
use crate::db::{Database, DatabaseServer};
use crate::errors::*;
use crate::keyring::Keyring;
use socket2::{Domain, Socket, Type};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time;

const FETCH_INTERVAL: Duration = Duration::from_secs(60 * 15); // 15min
const FETCH_INTERVAL_JITTER: Duration = Duration::from_secs(45);
const SYNC_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 15); // 15min
const UPDATE_CHECK_DEBOUNCE: Duration = Duration::from_secs(5);
const UPDATE_SHUTDOWN_DELAY: Duration = Duration::from_secs(60 * 20); // 20min

const P2P_SYNC_CONNECT_JITTER: Duration = Duration::from_secs(3);

const GOSSIP_IDLE_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3600 * 24); // 1h, set this to 24h later
const P2P_SYNC_PORT_BACKLOG: u32 = 1024;

pub async fn random_jitter(jitter: Duration) {
    let jitter = fastrand::u64(..jitter.as_secs());
    time::sleep(Duration::from_secs(jitter)).await;
}

pub async fn spawn(
    db: Database,
    keyring: Keyring,
    config: Config,
    p2p: P2p,
    proxy: Option<SocketAddr>,
) -> Result<Infallible> {
    let mut set = JoinSet::new();

    let (mut db_server, mut db_client) = DatabaseServer::new(db);
    set.spawn(async move {
        db_server.run().await?;
        bail!("Database server has terminated");
    });

    #[cfg(unix)]
    {
        let db_client = db_client.clone();
        let db_socket_path = config.db_socket_path()?;
        set.spawn(async move { db::spawn_unix_db_server(&db_client, db_socket_path).await });
    }

    let (irc_tx, irc_rx) = mpsc::channel(32);
    let irc_tx = cfg!(feature = "irc").then(|| irc_tx);

    if !p2p.no_bind {
        for addr in p2p.bind {
            let db_client = db_client.clone();
            let socket = match addr {
                SocketAddr::V4(_) => Socket::new(Domain::IPV4, Type::STREAM, None)?,
                SocketAddr::V6(_) => {
                    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
                    socket
                        .set_only_v6(true)
                        .context("Failed to set port to ipv6-only")?;
                    socket
                }
            };
            socket
                .set_reuse_address(true)
                .context("Failed to set reuseaddr for port")?;
            socket
                .set_nonblocking(true)
                .context("Failed to set port to non-blocking")?;
            let socket = TcpSocket::from_std_stream(socket.into());

            socket
                .bind(addr)
                .with_context(|| anyhow!("Failed to bind to address: {:?}", addr))?;
            let listener = socket.listen(P2P_SYNC_PORT_BACKLOG)?;

            debug!("Listening on address: {addr:?}");
            set.spawn(async move { sync::spawn_sync_server(&db_client, listener).await });
        }
    }

    if !p2p.no_fetch {
        let mut db_client = db_client.clone();
        let keyring = keyring.clone();
        let repositories = config.data.repositories;
        set.spawn(async move {
            fetch::spawn_fetch_timer(
                &mut db_client,
                keyring,
                repositories,
                proxy,
                p2p.announce,
                irc_tx,
            )
            .await
        });
    }

    if let Some(image) = p2p.check_container_updates {
        let commit = match p2p.update_assume_commit {
            Some(s) if s.is_empty() => {
                bail!("Update checks are configured but current commit is empty string")
            }
            Some(commit) => commit,
            None => bail!("Update checks are configured but current commit is not provided"),
        };
        set.spawn(update_check::spawn_update_check(image, commit));
    }

    let (peering_tx, peering_rx) = mpsc::channel(1024);
    set.spawn(async move { peering::spawn(&mut db_client, keyring, proxy, peering_rx).await });

    #[cfg(feature = "irc")]
    if !p2p.irc.no_irc {
        set.spawn(irc::spawn(irc_rx, p2p.irc.irc_channel, peering_tx.clone()));
    }

    if !p2p.dns.no_dns {
        set.spawn(dns::spawn(p2p.dns.dns, peering_tx));
    }

    // if irc is not enabled, supress an unused variable warning
    #[cfg(not(feature = "irc"))]
    let _ = irc_rx;

    info!("Successfully started p2p node...");
    let result = set
        .join_next()
        .await
        .context("All features have been disabled, nothing to do")?;
    result.context("Failed to wait for task")?
}
