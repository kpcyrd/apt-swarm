use crate::args::{ContainerUpdateCheck, P2p};
use crate::config::Repository;
use crate::db::Database;
use crate::db::DatabaseClient;
use crate::db::DatabaseServer;
use crate::errors::*;
use crate::fetch;
use crate::keyring::Keyring;
use crate::plumbing::update;
use crate::sync;
use futures::prelude::*;
use irc::client::prelude::{Client, Command, Config, Response};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time;

const FETCH_INTERVAL: Duration = Duration::from_secs(60 * 15); // 15min
const INTERVAL_JITTER: Duration = Duration::from_secs(45);

const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 15); // 15min
const UPDATE_CHECK_DEBOUNCE: Duration = Duration::from_secs(5);
const UPDATE_SHUTDOWN_DELAY: Duration = Duration::from_secs(60 * 20); // 20min

const GOSSIP_IDLE_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3600 * 24); // 1h, set this to 24h later

const IRC_DEBOUNCE: Duration = Duration::from_millis(250);

fn random_nickname() -> String {
    let mut buf = [0u8; 3];
    getrandom::getrandom(&mut buf).expect("Failed to use getrandom");
    let name = format!("apt-swarm-{}", hex::encode(buf));
    name
}

async fn spawn_irc(
    debounce: Option<Duration>,
    mut rx: mpsc::Receiver<String>,
) -> Result<Infallible> {
    if let Some(debounce) = debounce {
        tokio::time::sleep(debounce).await;
    }

    info!("Connecting to irc for peer discovery...");
    let nickname = random_nickname();
    let channel = "##apt-swarm-p2p";

    let config = Config {
        nickname: Some(nickname),
        server: Some("irc.hackint.org".to_string()),
        channels: vec![channel.to_string()],
        realname: Some("p2p bootstrap https://github.com/kpcyrd/apt-swarm".to_string()),
        use_tls: Some(true),
        ..Default::default()
    };

    let mut client = Client::from_config(config).await?;

    client
        .identify()
        .context("Failed to identify with irc server")?;

    let mut stream = client.stream().context("Failed to setup irc stream")?;

    loop {
        tokio::select! {
            msg = stream.next() => {
                if let Some(message) = msg.transpose().context("Failed to read from irc stream")? {
                    trace!("Received msg from irc server: {message:?}");
                    match message.command {
                        Command::PRIVMSG(target, msg) => {
                            debug!("Received irc privmsg: {:?}: {:?}", target, msg);
                            if target != channel {
                                continue;
                            }
                        }
                        Command::Response(Response::RPL_ISUPPORT, _) => {
                            // client.send_quit("QUIT")?;
                        }
                        _ => (),
                    }
                } else {
                    bail!("irc client has been shutdown");
                }
            }
            msg = rx.recv() => {
                if let Some(msg) = msg {
                    debug!("Sending message to irc: {msg:?}");
                    client.send_privmsg(channel, &msg)
                        .context("Failed to send to irc")?;
                    // slowing this down slightly, just in case
                    time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
    }
}

async fn random_jitter() {
    let jitter = fastrand::u64(..INTERVAL_JITTER.as_secs() * 2);
    time::sleep(Duration::from_secs(jitter)).await;
}

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
            next_idle_announce_after: GOSSIP_IDLE_ANNOUNCE_INTERVAL,
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

async fn spawn_fetch_timer<D: DatabaseClient>(
    db: &D,
    keyring: Keyring,
    repositories: Vec<Repository>,
    p2p_tx: mpsc::Sender<String>,
) -> Result<Infallible> {
    let mut stats = HashMap::new();
    for key in keyring.all_fingerprints() {
        stats.insert(key, GossipStats::new("TODO".to_string()));
    }

    let keyring = Arc::new(Some(keyring));
    let mut interval = time::interval(FETCH_INTERVAL - INTERVAL_JITTER);

    loop {
        interval.tick().await;
        random_jitter().await;
        info!("Fetch timer has started");
        if let Err(err) =
            fetch::fetch_updates(db, keyring.clone(), None, repositories.clone()).await
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
                        let msg = format!("[sync] fp={fp:X} idx={idx} count={count}");
                        trace!("Sending to p2p channel: {:?}", msg);
                        // if the p2p channel crashed do not interrupt monitoring
                        if let Err(err) = p2p_tx.try_send(msg) {
                            warn!("Failed to send to p2p channel: {err:#}");
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

pub async fn spawn_update_check(image: String, commit: String) -> Result<Infallible> {
    let mut interval = time::interval(UPDATE_CHECK_INTERVAL);
    debug!("Delaying first update check");
    time::sleep(UPDATE_CHECK_DEBOUNCE).await;
    let check = ContainerUpdateCheck { image, commit };
    loop {
        interval.tick().await;
        match update::check(&check).await {
            Ok(update::Updates::Available { current, latest }) => {
                warn!(
                    "We're running an outdated version of {:?}, going to shutdown in some minutes... (current={:?}, latest={:?})",
                    check.image, current, latest
                );
                time::sleep(UPDATE_SHUTDOWN_DELAY).await;
                bail!("Sending shutdown signal to request container image update");
            }
            Ok(_) => (),
            Err(err) => {
                warn!("Update check failed: {err:#}");
            }
        }
    }
}

pub async fn spawn(
    db: Database,
    keyring: Keyring,
    p2p: P2p,
    repositories: Vec<Repository>,
) -> Result<Infallible> {
    let mut set = JoinSet::new();

    let (mut db_server, db_client) = DatabaseServer::new(db);
    set.spawn(async move {
        db_server.run().await?;
        bail!("Database server has terminated");
    });

    let (p2p_tx, p2p_rx) = mpsc::channel(32);

    if !p2p.no_fetch {
        set.spawn(
            async move { spawn_fetch_timer(&db_client, keyring, repositories, p2p_tx).await },
        );
    }

    if let Some(image) = p2p.check_container_updates {
        let commit = match p2p.update_assume_commit {
            Some(s) if s.is_empty() => {
                bail!("Update checks are configured but current commit is empty string")
            }
            Some(commit) => commit,
            None => bail!("Update checks are configured but current commit is not provided"),
        };
        set.spawn(spawn_update_check(image, commit));
    }

    if !p2p.no_irc {
        // briefly delay the connection, so we don't spam irc in case something crashes immediately
        set.spawn(spawn_irc(Some(IRC_DEBOUNCE), p2p_rx));
    }

    info!("Successfully started p2p node...");
    let result = set
        .join_next()
        .await
        .context("All features have been disabled, nothing to do")?;
    result.context("Failed to wait for task")?
}
