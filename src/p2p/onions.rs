use crate::errors::*;
use arti_client::{TorClient, TorClientConfig};
use std::convert::Infallible;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn spawn() -> Result<Infallible> {
    let config = TorClientConfig::default();
    info!("Connecting to Tor...");
    let tor_client = TorClient::create_bootstrapped(config).await?;

    info!("Connecting to example.com");
    let mut stream = tor_client.connect(("example.com", 80)).await?;

    info!("Sending request...");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;

    info!("Reading response...");
    let mut buf = String::new();
    stream.read_to_string(&mut buf).await?;
    println!("{}", buf);

    info!("Arti test completed");

    std::future::pending().await
}
