#[cfg(unix)]
use super::unix::DatabaseUnixClient;
use super::{Database, DatabaseClient};
use crate::db;
use crate::errors::*;
use crate::signed::Signed;
use crate::sync;
use async_trait::async_trait;
use bstr::BString;
use sequoia_openpgp::Fingerprint;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Query {
    AddRelease(String, Signed),
    IndexFromScan(SyncQuery),
    // Delete(BString),
    Count(BString),
}

#[derive(Serialize, Deserialize)]
pub struct SyncQuery {
    pub fp: String,
    pub hash_algo: String,
    pub prefix: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Inserted(String),
    Num(u64),
    Index((String, usize)),
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

pub enum DatabaseHandle {
    Direct(Database),
    #[cfg(unix)]
    Unix(DatabaseUnixClient),
}

#[async_trait]
impl DatabaseClient for DatabaseHandle {
    async fn add_release(&mut self, fp: &Fingerprint, signed: &Signed) -> Result<String> {
        match self {
            Self::Direct(db) => db.add_release(fp, signed).await,
            #[cfg(unix)]
            Self::Unix(unix) => unix.add_release(fp, signed).await,
        }
    }

    async fn index_from_scan(&mut self, query: &sync::Query) -> Result<(String, usize)> {
        match self {
            Self::Direct(db) => db.index_from_scan(query).await,
            #[cfg(unix)]
            Self::Unix(unix) => unix.index_from_scan(query).await,
        }
    }

    async fn spill(&self, prefix: &[u8]) -> Result<Vec<(db::Key, db::Value)>> {
        match self {
            Self::Direct(db) => db.spill(prefix).await,
            #[cfg(unix)]
            Self::Unix(db) => db.spill(prefix).await,
        }
    }

    async fn get_value(&self, key: &[u8]) -> Result<db::Value> {
        match self {
            Self::Direct(db) => db.get_value(key).await,
            #[cfg(unix)]
            Self::Unix(unix) => unix.get_value(key).await,
        }
    }

    async fn count(&mut self, prefix: &[u8]) -> Result<u64> {
        match self {
            Self::Direct(db) => db.count(prefix).await,
            #[cfg(unix)]
            Self::Unix(unix) => unix.count(prefix).await,
        }
    }
}
