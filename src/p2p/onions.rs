use crate::args;
use crate::errors::*;
use arti_client::{
    config::{onion_service::OnionServiceConfigBuilder, TorClientConfigBuilder},
    TorClient,
};
use futures::StreamExt;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tor_cell::relaycell::msg::Connected;
use tor_config::ExplicitOrAuto;
use tor_hsservice::StreamRequest;
use tor_keymgr::config::ArtiKeystoreKind;
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;

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

async fn setup(path: &Path) -> Result<TorClient<PreferredRuntime>> {
    let state_dir = path.join("state");
    let cache_dir = path.join("cache");

    let mut config = TorClientConfigBuilder::from_directories(state_dir, cache_dir);

    config
        .storage()
        .keystore()
        .primary()
        .kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));

    let config = config
        .build()
        .context("Failed to setup tor client config")?;

    info!("Connecting to Tor...");
    let tor_client = TorClient::create_bootstrapped(config)
        .await
        .context("Failed to setup tor client")?;
    Ok(tor_client)
}

pub async fn connect(path: PathBuf, onion: &str, port: u16) -> Result<()> {
    let tor_client = setup(&path).await?;

    info!("Connecting to {onion}:{port}...");
    let stream = tor_client.connect((onion, port)).await?;
    info!("Successfully connected");

    let (mut read, mut write) = stream.split();
    tokio::select!(
        ret = async {
            let mut stdout = io::stdout();
            io::copy(&mut read, &mut stdout).await
                .map(|_| ())
        } => ret,
        ret = async {
            let mut stdin = io::stdin();
            let mut buf = [0u8; 1024];
            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(0) => break Ok(()),
                    Ok(n) => n,
                    Err(err) => break Err(err),
                };
                if let Err(err) = write.write_all(&buf[..n]).await {
                    break Err(err);
                }
                // tor connection is buffered, needs an explict flush
                // this is also the reason we don't just use tokio::io::copy_bidirectional
                if let Err(err) = write.flush().await {
                    break Err(err);
                }
            }
        } => ret,
    )?;
    write.shutdown().await?;
    info!("Connection closed");

    Ok(())
}

pub async fn spawn(path: PathBuf, config: args::OnionOptions) -> Result<Infallible> {
    // if requested, acquire a guard that disables log scrubbing for the time it's held
    let _guard: Option<_> = config
        .onions_log_sensitive_information
        .then(safelog::disable_safe_logging)
        .transpose()?;
    let tor_client = setup(&path).await?;

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
                let root_cause = err
                    .downcast_ref::<io::Error>()
                    .and_then(|io_err| io_err.get_ref())
                    .and_then(|cause| cause.downcast_ref::<tor_proto::Error>());

                match root_cause {
                    Some(tor_proto::Error::EndReceived(reason)) => {
                        debug!("Client has disconnected: reason={reason:?}");
                    }
                    // this is likely `stream channel disappeared without END cell?`
                    Some(tor_proto::Error::StreamProto(violation)) => {
                        debug!("Client disconnected due to stream violation: {violation}");
                    }
                    _ => error!("Error serving hidden service client: {err:#}"),
                }
            }
            debug!("Closing hidden service connection");
        });
    }

    bail!("Onion thread has exited")
}
