use super::proto::{Query, Response, SyncQuery};
use super::DatabaseClient;
use crate::db;
use crate::errors::*;
use crate::signed::Signed;
use crate::sync;
use async_trait::async_trait;
use bstr::BString;
use sequoia_openpgp::Fingerprint;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::UnixStream;

pub struct DatabaseUnixClient {
    socket: BufStream<UnixStream>,
}

impl DatabaseUnixClient {
    pub async fn connect(path: &Path) -> Result<Self> {
        let socket = UnixStream::connect(path)
            .await
            .with_context(|| anyhow!("Failed to connect to socket at {path:?}"))?;
        debug!("Connected to unix domain socket at {path:?}");
        let socket = BufStream::new(socket);
        Ok(Self { socket })
    }

    pub async fn send_query(&mut self, q: &Query) -> Result<()> {
        let mut json = serde_json::to_string(q).context("Failed to serialize message as json")?;
        json.push('\n');
        self.socket
            .write_all(json.as_bytes())
            .await
            .context("Failed to send to database server")?;
        self.socket.flush().await?;
        Ok(())
    }

    pub async fn recv_response(&mut self) -> Result<Response> {
        let mut buf = Vec::new();
        self.socket.read_until(b'\n', &mut buf).await?;

        if buf.is_empty() {
            bail!("Database has disconnected without sending a response");
        } else if buf == b"\n" {
            Ok(Response::Ok)
        } else {
            let response = serde_json::from_slice::<Response>(&buf)?;
            match response {
                Response::Error(error) => {
                    bail!("Error from server: {}", error.err);
                }
                _ => Ok(response),
            }
        }
    }
}

#[async_trait]
impl DatabaseClient for DatabaseUnixClient {
    async fn add_release(&mut self, fp: &Fingerprint, signed: &Signed) -> Result<String> {
        self.send_query(&Query::AddRelease(fp.to_string(), signed.clone()))
            .await?;
        let inserted = self.recv_response().await?;
        if let Response::Inserted(hash) = inserted {
            info!("Added release to database: {hash:?}");
            Ok(hash)
        } else {
            bail!("Unexpected response type from database: {inserted:?}");
        }
    }

    async fn index_from_scan(&mut self, query: &sync::Query) -> Result<(String, usize)> {
        self.send_query(&Query::IndexFromScan(SyncQuery {
            fp: query.fp.to_string(),
            hash_algo: query.hash_algo.clone(),
            prefix: query.prefix.clone(),
        }))
        .await?;
        let index = self.recv_response().await?;
        if let Response::Index(index) = index {
            Ok(index)
        } else {
            bail!("Unexpected response type from database: {index:?}");
        }
    }

    async fn spill(&self, _prefix: &[u8]) -> Result<Vec<(db::Key, db::Value)>> {
        todo!("DatabaseUnixClient::spill")
    }

    async fn get_value(&self, _key: &[u8]) -> Result<db::Value> {
        todo!("DatabaseUnixClient::get_value")
    }

    async fn count(&mut self, prefix: &[u8]) -> Result<u64> {
        self.send_query(&Query::Count(BString::new(prefix.to_vec())))
            .await?;
        let count = self.recv_response().await?;
        if let Response::Num(count) = count {
            Ok(count)
        } else {
            bail!("Unexpected response type from database: {count:?}");
        }
    }
}
