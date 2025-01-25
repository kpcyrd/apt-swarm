use crate::errors::*;
use arti_client::{
    config::{onion_service::OnionServiceConfigBuilder, TorClientConfigBuilder},
    TorClient,
};
use futures::StreamExt;
use std::convert::Infallible;
use std::path::PathBuf;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::StreamRequest;
use tor_proto::stream::IncomingStreamRequest;

const HIDDEN_SERVICE_PORT: u16 = 16169;

async fn handle_tor_client(stream_request: StreamRequest) -> Result<()> {
    let request = stream_request.request();
    debug!("Received onion stream request: {request:?}");
    match request {
        IncomingStreamRequest::Begin(begin) if begin.port() == HIDDEN_SERVICE_PORT => {
            let onion_service_stream = stream_request
                .accept(Connected::new_empty())
                .await
                .context("Failed to accept hidden service client")?;
            debug!("Accepted tcp client through hidden service");

            // Simple echo server
            let (read, mut write) = onion_service_stream.split();
            let reader = BufReader::new(read);
            let mut lines = reader.lines();

            while let Some(line) = lines
                .next_line()
                .await
                .context("Failed to read next line")?
            {
                info!("Received line: {line:?}");
                write.write_all(line.as_bytes()).await?;
                write.write_all(b"\n").await?;
                write.flush().await?;
            }
        }
        _ => stream_request.shutdown_circuit()?,
    }
    Ok(())
}

pub async fn spawn(path: PathBuf) -> Result<Infallible> {
    let state_dir = path.join("state");
    let cache_dir = path.join("cache");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
        .build()
        .context("Failed to setup tor client config")?;

    info!("Connecting to Tor...");
    let tor_client = TorClient::create_bootstrapped(config).await?;

    info!("Setting up hidden service...");
    // TODO: this is not really ephemeral yet
    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname("ephemeral".parse()?)
        .build()
        .context("Failed to setup hidden service config")?;
    let (service, request_stream) = tor_client
        .launch_onion_service(svc_cfg)
        .context("Failed to launch onion service")?;
    let onion_name = service
        .onion_name()
        .context("Failed to determine onion name")?;
    info!("Running service with onion name = {onion_name}");

    let stream_requests = tor_hsservice::handle_rend_requests(request_stream);
    tokio::pin!(stream_requests);
    info!("Ready to serve onion connections");

    while let Some(stream_request) = stream_requests.next().await {
        debug!("Received tor client circuit");
        tokio::spawn(async move {
            if let Err(err) = handle_tor_client(stream_request).await {
                if let Some(tor_proto::Error::EndReceived(reason)) = err
                    .downcast_ref::<io::Error>()
                    .and_then(|io_err| io_err.get_ref())
                    .and_then(|cause| cause.downcast_ref::<tor_proto::Error>())
                {
                    // Handle this specific case
                    debug!("Client has disconnected: reason={reason:?}");
                } else {
                    // Normal error handling
                    error!("Error serving hidden service client: {err:#}");
                }
            }
            debug!("Closing hidden service connection");
        });
    }

    /*
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
    */

    bail!("Onion thread has exited")
}
