use crate::db::unix::{ErrorResponse, Query, Response};
use crate::db::{DatabaseClient, DatabaseServerClient};
use crate::errors::*;
use crate::sync;
use std::convert::Infallible;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

pub async fn serve_request(db: &mut DatabaseServerClient, buf: &[u8]) -> Result<Response> {
    let query = serde_json::from_slice(buf).context("Failed to deserialize query")?;
    match query {
        Query::AddRelease(fp, signed) => {
            let fp = fp.parse().context("Failed to parse fingerprint")?;
            let hash = db.add_release(&fp, &signed).await?;
            Ok(Response::Inserted(hash))
        }
        Query::IndexFromScan(query) => {
            let fp = query.fp.parse().context("Failed to parse fingerprint")?;
            let index = db
                .index_from_scan(&sync::Query {
                    fp,
                    hash_algo: query.hash_algo,
                    prefix: query.prefix,
                })
                .await?;
            Ok(Response::Index(index))
        }
        Query::Delete(key) => {
            db.delete(&key).await?;
            Ok(Response::Ok)
        }
        Query::Count(key) => {
            let count = db.count(&key).await?;
            Ok(Response::Num(count))
        }
        Query::Flush => {
            db.flush().await?;
            Ok(Response::Ok)
        }
    }
}

pub async fn serve_db_client(db: &mut DatabaseServerClient, mut stream: UnixStream) -> Result<()> {
    let (rx, mut tx) = stream.split();
    let mut reader = BufReader::new(rx);

    let mut buf = Vec::new();
    loop {
        buf.clear();
        reader
            .read_until(b'\n', &mut buf)
            .await
            .context("Failed to read from database client")?;
        if !buf.ends_with(b"\n") {
            // client has disconnected
            return Ok(());
        }

        match serve_request(db, &buf).await {
            Ok(Response::Ok) => tx.write_all(b"\n").await?,
            Ok(response) => {
                let mut err = serde_json::to_string(&response)?;
                err.push('\n');
                tx.write_all(err.as_bytes()).await?;
            }
            Err(err) => {
                let err = ErrorResponse::new(&err);
                let mut err = serde_json::to_string(&err)?;
                err.push('\n');
                tx.write_all(err.as_bytes()).await?;
            }
        }
    }
}

pub async fn spawn_db_server(db: &DatabaseServerClient, path: PathBuf) -> Result<Infallible> {
    fs::remove_file(&path).await.ok();
    let listener = UnixListener::bind(&path)
        .with_context(|| anyhow!("Failed to bind database socket at: {path:?}"))?;
    debug!("Bound database socket at {path:?}");

    loop {
        let (stream, _src_addr) = listener.accept().await?;
        debug!("Accepted database client on unix domain socket");

        let mut db = db.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_db_client(&mut db, stream).await {
                error!("Error while serving database client: {err:#}");
            } else {
                debug!("Database client disconnected");
            }
        });
    }
}
