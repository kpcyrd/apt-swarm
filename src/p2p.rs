use crate::config::Repository;
use crate::db::Database;
use crate::errors::*;
use crate::fetch;
use crate::keyring::Keyring;
use std::convert::Infallible;
use std::sync::Arc;
// use crate::fetch;
use futures::prelude::*;
use irc::client::prelude::{Client, Command, Config, Response};
use std::time::Duration;
use tokio::time;

const FETCH_INTERVAL: u64 = 60 * 15; // 15min
const INTERVAL_JITTER: u64 = 45;

fn random_nickname() -> String {
    let mut buf = [0u8; 3];
    getrandom::getrandom(&mut buf).expect("Failed to use getrandom");
    let name = format!("apt-swarm-{}", hex::encode(buf));
    name
}

async fn spawn_irc() -> Result<Infallible> {
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
    let jitter = fastrand::u64(..INTERVAL_JITTER * 2);
    time::sleep(Duration::from_secs(jitter)).await;
}

async fn spawn_fetch_timer(
    db: &Database,
    keyring: Keyring,
    repositories: Vec<Repository>,
) -> Result<Infallible> {
    let keyring = Arc::new(Some(keyring));
    let mut interval = time::interval(Duration::from_secs(FETCH_INTERVAL - INTERVAL_JITTER));

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

pub async fn spawn(
    db: &Database,
    keyring: Keyring,
    repositories: Vec<Repository>,
) -> Result<Infallible> {
    tokio::select! {
        r = spawn_irc() => r,
        r = spawn_fetch_timer(db, keyring, repositories) => r,
    }
}
