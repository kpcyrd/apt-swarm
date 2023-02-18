use crate::args::{ContainerUpdateCheck, P2p};
use crate::config::Repository;
use crate::db::Database;
use crate::errors::*;
use crate::fetch;
use crate::keyring::Keyring;
use crate::plumbing::update;
use futures::prelude::*;
use irc::client::prelude::{Client, Command, Config, Response};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::time;

const FETCH_INTERVAL: Duration = Duration::from_secs(60 * 15); // 15min
const INTERVAL_JITTER: Duration = Duration::from_secs(45);

const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 15); // 15min
const UPDATE_CHECK_DEBOUNCE: Duration = Duration::from_secs(5);
const UPDATE_SHUTDOWN_DELAY: Duration = Duration::from_secs(60 * 20); // 20min

const IRC_DEBOUNCE: Duration = Duration::from_millis(250);

fn random_nickname() -> String {
    let mut buf = [0u8; 3];
    getrandom::getrandom(&mut buf).expect("Failed to use getrandom");
    let name = format!("apt-swarm-{}", hex::encode(buf));
    name
}

async fn spawn_irc(debounce: Option<Duration>) -> Result<Infallible> {
    if let Some(debounce) = debounce {
        tokio::time::sleep(debounce).await;
    }

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

    while let Some(message) = stream
        .next()
        .await
        .transpose()
        .context("Failed to read from irc stream")?
    {
        trace!("Received msg from irc server: {message:?}");
        match message.command {
            Command::PRIVMSG(target, msg) => {
                debug!("Received irc privmsg: {:?}: {:?}", target, msg);
                if target != channel {
                    continue;
                }
            }
            Command::Response(Response::RPL_ISUPPORT, _) => {
                client.send_privmsg("##apt-swarm-p2p", "ohai :3")?;

                // client.send_quit("QUIT")?;
            }
            _ => (),
        }
    }

    bail!("irc client has been shutdown");
}

async fn random_jitter() {
    let jitter = fastrand::u64(..INTERVAL_JITTER.as_secs() * 2);
    time::sleep(Duration::from_secs(jitter)).await;
}

async fn spawn_fetch_timer(
    db: &Database,
    keyring: Keyring,
    repositories: Vec<Repository>,
) -> Result<Infallible> {
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
    }
}

pub async fn spawn_update_check(image: String, commit: String) -> Result<Infallible> {
    let mut interval = time::interval(UPDATE_CHECK_INTERVAL);
    debug!("Delaying first update check");
    interval.tick().await;
    time::sleep(UPDATE_CHECK_DEBOUNCE).await;
    let check = ContainerUpdateCheck { image, commit };
    loop {
        interval.tick().await;
        match update::check(&check).await {
            Ok(update::Updates::Available { current, latest }) => {
                info!(
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

    if !p2p.no_fetch {
        set.spawn(async move { spawn_fetch_timer(&db, keyring, repositories).await });
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
        set.spawn(spawn_irc(Some(IRC_DEBOUNCE)));
    }

    let result = set
        .join_next()
        .await
        .context("All features have been disabled, nothing to do")?;
    result.context("Failed to wait for task")?
}
