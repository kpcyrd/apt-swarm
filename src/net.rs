use crate::errors::*;
use crate::p2p::proto::PeerAddr;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;
use tokio_socks::tcp::Socks5Stream;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
pub const PROXY_TIMEOUT: Duration = Duration::from_secs(30);

pub const MAX_LINE_LENGTH: u64 = 512;

pub async fn connect(addr: &PeerAddr, proxy: Option<SocketAddr>) -> Result<TcpStream> {
    let PeerAddr::Inet(addr) = addr else {
        bail!("Connecting to onions is not yet implemented")
    };

    // TODO: only do this for PeerAddr::Inet
    let target = proxy.unwrap_or(*addr);

    info!("Creating tcp connection to {target:?}");
    let sock = TcpStream::connect(target);
    let mut sock = time::timeout(CONNECT_TIMEOUT, sock)
        .await
        .with_context(|| anyhow!("Connecting to {target:?} timed out"))?
        .with_context(|| anyhow!("Failed to connect to {target:?}"))?;

    if let Some(proxy) = proxy {
        debug!("Requesting socks5 connection to {addr:?}");
        let connect = Socks5Stream::connect_with_socket(sock, addr);

        sock = time::timeout(PROXY_TIMEOUT, connect)
            .await
            .with_context(|| anyhow!("Connecting to {addr:?} (with socks5 {proxy:?}) timed out"))?
            .with_context(|| anyhow!("Failed to connect to {addr:?} (with socks5 {proxy:?})"))?
            .into_inner()
    }

    debug!("Connection has been established");

    Ok(sock)
}

pub async fn handshake<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut rx: R,
    mut tx: W,
) -> Result<()> {
    debug!("Sending protocol probe to remote peer");
    time::timeout(HANDSHAKE_TIMEOUT, tx.write_all(b"//\n"))
        .await
        .context("Sending handshake protocol probe timed out")?
        .context("Failed to send protocol probe")?;

    let mut buf = [0u8; 3];
    time::timeout(HANDSHAKE_TIMEOUT, rx.read_exact(&mut buf))
        .await
        .context("Sending handshake protocol probe timed out")?
        .context("Failed to receive handshake response")?;

    if buf == *b":0\n" {
        debug!("Remote peer has sent expected response");
        Ok(())
    } else {
        bail!("Invalid handshake response: {buf:?}")
    }
}
