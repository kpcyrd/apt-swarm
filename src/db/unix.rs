use super::{Database, DatabaseClient};
use crate::errors::*;
use crate::signed::Signed;
use crate::sync;
use async_trait::async_trait;
use bstr::BString;
use sequoia_openpgp::Fingerprint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::UnixStream;

#[derive(Serialize, Deserialize)]
pub enum Query {
    AddRelease(String, Signed),
    Delete(BString),
    Count(BString),
    Flush,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Num(u64),
    Error(ErrorResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub err: String,
}

impl ErrorResponse {
    pub fn new(err: &anyhow::Error) -> Self {
        Self {
            err: format!("{:#}", err),
        }
    }
}

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
    async fn add_release(&mut self, fp: &Fingerprint, signed: &Signed) -> Result<()> {
        // this is only calculated for logging
        let normalized = signed.to_clear_signed()?;

        let mut hasher = Sha256::new();
        hasher.update(&normalized);
        let result = hasher.finalize();
        let hash = format!("{fp:X}/sha256:{result:x}");

        info!("Adding release to database: {hash:?}");
        self.send_query(&Query::AddRelease(fp.to_string(), signed.clone()))
            .await?;
        self.recv_response().await?;
        Ok(())
    }

    async fn index_from_scan(&self, _query: &sync::Query) -> Result<(String, usize)> {
        todo!("DatabaseUnixClient::index_from_scan")
    }

    async fn scan_keys(&self, _prefix: &[u8]) -> Result<Vec<sled::IVec>> {
        todo!("DatabaseUnixClient::scan_keys")
    }

    async fn get_value(&self, _key: &[u8]) -> Result<sled::IVec> {
        todo!("DatabaseUnixClient::get_value")
    }

    async fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.send_query(&Query::Delete(BString::new(key.to_vec())))
            .await?;
        self.recv_response().await?;
        Ok(())
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

    async fn flush(&mut self) -> Result<()> {
        self.send_query(&Query::Flush).await?;
        self.recv_response().await?;
        Ok(())
    }
}

pub enum DatabaseHandle {
    Direct(Database),
    Unix(DatabaseUnixClient),
}

#[async_trait]
impl DatabaseClient for DatabaseHandle {
    async fn add_release(&mut self, fp: &Fingerprint, signed: &Signed) -> Result<()> {
        match self {
            Self::Direct(db) => db.add_release(fp, signed).await,
            Self::Unix(unix) => unix.add_release(fp, signed).await,
        }
    }

    async fn index_from_scan(&self, query: &sync::Query) -> Result<(String, usize)> {
        match self {
            Self::Direct(db) => db.index_from_scan(query).await,
            Self::Unix(unix) => unix.index_from_scan(query).await,
        }
    }

    async fn scan_keys(&self, prefix: &[u8]) -> Result<Vec<sled::IVec>> {
        match self {
            Self::Direct(db) => db.scan_keys(prefix).await,
            Self::Unix(unix) => unix.scan_keys(prefix).await,
        }
    }

    async fn get_value(&self, key: &[u8]) -> Result<sled::IVec> {
        match self {
            Self::Direct(db) => db.get_value(key).await,
            Self::Unix(unix) => unix.get_value(key).await,
        }
    }

    async fn delete(&mut self, key: &[u8]) -> Result<()> {
        match self {
            Self::Direct(db) => db.delete(key).await,
            Self::Unix(unix) => unix.delete(key).await,
        }
    }

    async fn count(&mut self, prefix: &[u8]) -> Result<u64> {
        match self {
            Self::Direct(db) => db.count(prefix).await,
            Self::Unix(unix) => unix.count(prefix).await,
        }
    }

    async fn flush(&mut self) -> Result<()> {
        match self {
            Self::Direct(db) => db.flush().await,
            Self::Unix(unix) => unix.flush().await,
        }
    }
}
