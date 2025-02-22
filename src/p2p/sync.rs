use crate::db::DatabaseServerClient;
use crate::errors::*;
use crate::p2p::{self, peerdb};
use crate::sync;
use std::convert::Infallible;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

pub async fn serve_sync_client(
    db: &mut DatabaseServerClient,
    peerdb: peerdb::Client,
    mut stream: TcpStream,
) -> Result<()> {
    let (rx, mut tx) = stream.split();
    let result =
        sync::sync_yield(db, Some(peerdb), rx, &mut tx, Some(p2p::SYNC_IDLE_TIMEOUT)).await;
    tx.shutdown().await.ok();
    result
}

pub async fn spawn_sync_server(
    db: &DatabaseServerClient,
    peerdb: peerdb::Client,
    listener: TcpListener,
) -> Result<Infallible> {
    loop {
        let (stream, src_addr) = listener.accept().await?;
        debug!("Accepted connection from client: {:?}", src_addr);

        let mut db = db.clone();
        let peerdb = peerdb.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_sync_client(&mut db, peerdb, stream).await {
                error!("Error while serving client: {err:#}");
            } else {
                debug!("Client disconnected: {src_addr:?}");
            }
        });
    }
}
