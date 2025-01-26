use crate::errors::*;
use crate::p2p;
use crate::p2p::proto::PeerGossip;
use futures::prelude::*;
use irc::client::prelude::{Client, Command, Config, Response};
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time;

pub const IRC_DEBOUNCE: Duration = Duration::from_millis(250);
pub const IRC_RECONNECT_COOLDOWN: Duration = Duration::from_secs(60); // 1min
pub const IRC_RECONNECT_JITTER: Duration = Duration::from_secs(60 * 3); // 3min

fn random_nickname() -> String {
    let mut buf = [0u8; 3];
    getrandom::fill(&mut buf).expect("Failed to use getrandom");
    let name = format!("apt-swarm-{}", hex::encode(buf));
    name
}

pub async fn connect_irc(
    rx: &mut mpsc::Receiver<String>,
    peering_tx: &mpsc::Sender<PeerGossip>,
) -> Result<Infallible> {
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

                            if !msg.starts_with("[sync] ") {
                                continue;
                            }

                            match msg.parse::<PeerGossip>() {
                                Ok(gi) => {
                                    info!("Discovered peer: {gi:?}");
                                    if let Err(TrySendError::Full(gi)) = peering_tx.try_send(gi) {
                                        warn!("Discarding peer gossip because peering backlog is full: {gi:?}");
                                    }
                                }
                                Err(err) => {
                                    warn!("Malformed irc message: {err:#}");
                                }
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

pub async fn spawn_irc(
    debounce: Option<Duration>,
    mut rx: mpsc::Receiver<String>,
    peering_tx: mpsc::Sender<PeerGossip>,
) -> Result<Infallible> {
    if let Some(debounce) = debounce {
        tokio::time::sleep(debounce).await;
    }

    loop {
        let Err(err) = connect_irc(&mut rx, &peering_tx).await;
        error!("irc connection has crashed: {err:#}");

        time::sleep(IRC_RECONNECT_COOLDOWN).await;
        p2p::random_jitter(IRC_RECONNECT_JITTER).await;
    }
}
