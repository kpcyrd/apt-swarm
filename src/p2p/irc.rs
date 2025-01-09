use crate::errors::*;
use crate::p2p;
use futures::prelude::*;
use irc::client::prelude::{Client, Command, Config, Response};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time;

fn random_nickname() -> String {
    let mut buf = [0u8; 3];
    getrandom::getrandom(&mut buf).expect("Failed to use getrandom");
    let name = format!("apt-swarm-{}", hex::encode(buf));
    name
}

#[derive(Debug, PartialEq)]
pub struct PeerGossip {
    pub fp: sequoia_openpgp::Fingerprint,
    pub idx: String,
    pub count: u64,
    pub addrs: Vec<SocketAddr>,
}

impl FromStr for PeerGossip {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s
            .strip_prefix("[sync] ")
            .context("Message is missing the [sync] tag")?;

        let mut split = s.split(' ');
        let fp = split
            .next()
            .context("Missing mandatory attribute: fingerprint")?;
        let fp = fp
            .strip_prefix("fp=")
            .with_context(|| anyhow!("First attribute is expected to be fingerprint: {fp:?}"))?;
        let fp = fp
            .parse()
            .with_context(|| anyhow!("Failed to parse as fingerprint: {fp:?}"))?;

        let idx = split.next().context("Missing mandatory attribute: index")?;
        let idx = idx
            .strip_prefix("idx=")
            .with_context(|| anyhow!("First attribute is expected to be index: {idx:?}"))?
            .to_string();

        let count = split.next().context("Missing mandatory attribute: count")?;
        let count = count
            .strip_prefix("count=")
            .with_context(|| anyhow!("First attribute is expected to be count: {count:?}"))?;
        let count = count
            .parse()
            .with_context(|| anyhow!("Failed to parse as count: {count:?}"))?;

        let mut addrs = Vec::new();

        for extra in split {
            if let Some(addr) = extra.strip_prefix("addr=") {
                let addr = addr
                    .parse()
                    .with_context(|| anyhow!("Failed to parse as address: {addr:?}"))?;
                addrs.push(addr);
            }
        }

        Ok(PeerGossip {
            fp,
            idx,
            count,
            addrs,
        })
    }
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

        time::sleep(p2p::IRC_RECONNECT_COOLDOWN).await;
        p2p::random_jitter(p2p::IRC_RECONNECT_JITTER).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_irc_no_addrs() -> Result<()> {
        let s = "[sync] fp=ED541312A33F1128F10B1C6C54404762BBB6E853 idx=sha256:1994bea786a499ec72ce94a45e2830ce31746a5ef4fb7a2b73ba0934e4a046ac count=180";
        let gi = s.parse::<PeerGossip>()?;
        assert_eq!(
            gi,
            PeerGossip {
                fp: "ED541312A33F1128F10B1C6C54404762BBB6E853".parse()?,
                idx: "sha256:1994bea786a499ec72ce94a45e2830ce31746a5ef4fb7a2b73ba0934e4a046ac"
                    .to_string(),
                count: 180,
                addrs: Vec::new(),
            }
        );
        Ok(())
    }

    #[test]
    fn test_parse_irc_multiple_addrs() -> Result<()> {
        let s = "[sync] fp=2265EB4CB2BF88D900AE8D1B74A941BA219EC810 idx=sha256:55a00753512036f55ccc421217e008e4922c66592e6281b09de2fcba4dbd59ce count=12 addr=192.0.2.146:16169 addr=[2001:db8:c010:8f3a::1]:16169";
        let gi = s.parse::<PeerGossip>()?;
        assert_eq!(
            gi,
            PeerGossip {
                fp: "2265EB4CB2BF88D900AE8D1B74A941BA219EC810".parse()?,
                idx: "sha256:55a00753512036f55ccc421217e008e4922c66592e6281b09de2fcba4dbd59ce"
                    .to_string(),
                count: 12,
                addrs: vec![
                    "192.0.2.146:16169".parse()?,
                    "[2001:db8:c010:8f3a::1]:16169".parse()?,
                ],
            }
        );
        Ok(())
    }
}
