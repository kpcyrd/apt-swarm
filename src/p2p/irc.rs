use crate::errors::*;
use crate::p2p;
use crate::p2p::proto::{PeerGossip, SyncRequest};
use futures::prelude::*;
use irc::client::prelude::{Client, Command, Config, Response};
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time;
use url::Url;

const IRC_DEBOUNCE: Duration = Duration::from_millis(250);
pub const IRC_RECONNECT_COOLDOWN: Duration = Duration::from_secs(60); // 1min
pub const IRC_RECONNECT_JITTER: Duration = Duration::from_secs(60 * 3); // 3min

const IRC_CLIENT_ID: &str = concat!(
    "p2p bootstrap - v",
    env!("CARGO_PKG_VERSION"),
    " https://github.com/kpcyrd/apt-swarm"
);

fn random_nickname() -> String {
    let mut buf = [0u8; 3];
    getrandom::fill(&mut buf).expect("Failed to use getrandom");
    let name = format!("apt-swarm-{}", hex::encode(buf));
    name
}

fn parse_channel(url: &str) -> Result<(String, String)> {
    let url = Url::parse(url).with_context(|| anyhow!("Failed to parse url: {url:?}"))?;

    if url.scheme() != "ircs" {
        bail!("Only secure ircs:// links are supported: {url:?}");
    }

    let mut host = url
        .host_str()
        .with_context(|| anyhow!("Could not found host in irc url: {url:?}"))?
        .to_string();

    if let Some(port) = url.port() {
        host += &format!(":{port}");
    }

    if !["", "/"].contains(&url.path()) {
        bail!("Found unexpected path in irc url: {url:?}");
    }

    let fragment = url
        .fragment()
        .with_context(|| anyhow!("Could not find channel in irc url: {url:?}"))?;
    Ok((host, format!("#{fragment}")))
}

pub async fn connect_irc(
    rx: &mut mpsc::Receiver<String>,
    irc: &(String, String),
    peering_tx: &mpsc::Sender<SyncRequest>,
) -> Result<Infallible> {
    let (server, channel) = irc;
    info!("Connecting to irc for peer discovery (server={server:?}, channel={channel:?})...");
    let nickname = random_nickname();

    let config = Config {
        nickname: Some(nickname),
        server: Some("irc.hackint.org".to_string()),
        channels: vec![channel.to_string()],
        realname: Some(IRC_CLIENT_ID.to_string()),
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
                            if target != *channel {
                                continue;
                            }

                            if !msg.starts_with("[sync] ") {
                                continue;
                            }

                            match msg.parse::<PeerGossip>() {
                                Ok(info) => {
                                    info!("Discovered peer: {info:?}");
                                    let info = SyncRequest::from(info);
                                    if let Err(TrySendError::Full(info)) = peering_tx.try_send(info) {
                                        warn!("Discarding peer gossip because peering backlog is full: {info:?}");
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

pub async fn spawn(
    mut rx: mpsc::Receiver<String>,
    url: String,
    peering_tx: mpsc::Sender<SyncRequest>,
) -> Result<Infallible> {
    // briefly delay the connection, so we don't spam irc in case something crashes immediately
    tokio::time::sleep(IRC_DEBOUNCE).await;

    let irc = parse_channel(&url)?;
    loop {
        let Err(err) = connect_irc(&mut rx, &irc, &peering_tx).await;
        error!("irc connection has crashed: {err:#}");

        time::sleep(IRC_RECONNECT_COOLDOWN).await;
        p2p::random_jitter(IRC_RECONNECT_JITTER).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_irc_url() {
        let url = "ircs://irc.hackint.org/##apt-swarm-p2p";
        let (server, channel) = parse_channel(url).unwrap();
        assert_eq!(server, "irc.hackint.org");
        assert_eq!(channel, "##apt-swarm-p2p");

        let url = "ircs://irc.hackint.org##apt-swarm-p2p";
        let (server, channel) = parse_channel(url).unwrap();
        assert_eq!(server, "irc.hackint.org");
        assert_eq!(channel, "##apt-swarm-p2p");

        let url = "ircs://irc.hackint.org:1337/##apt-swarm-p2p";
        let (server, channel) = parse_channel(url).unwrap();
        assert_eq!(server, "irc.hackint.org:1337");
        assert_eq!(channel, "##apt-swarm-p2p");
    }

    #[test]
    fn test_parse_irc_invalid() {
        assert!(parse_channel("irc://irc.hackint.org/##apt-swarm-p2p").is_err());
        assert!(parse_channel("https://irc.hackint.org/##apt-swarm-p2p").is_err());
        assert!(parse_channel("ircs://irc.hackint.org/").is_err());
        assert!(parse_channel("ircs://irc.hackint.org/abc").is_err());
        assert!(parse_channel("ircs://irc.hackint.org/abc##apt-swarm-p2p").is_err());
    }
}
