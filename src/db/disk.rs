use super::{DatabaseClient, DatabaseHandle, DatabaseUnixClient};
use crate::config::Config;
use crate::errors::*;
use crate::signed::Signed;
use crate::sync;
use async_trait::async_trait;
use sequoia_openpgp::Fingerprint;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug)]
pub struct Database {
    sled: sled::Db,
}

#[async_trait]
impl DatabaseClient for Database {
    async fn add_release(&mut self, fp: &Fingerprint, signed: &Signed) -> Result<()> {
        let normalized = signed.to_clear_signed()?;

        let mut hasher = Sha256::new();
        hasher.update(&normalized);
        let result = hasher.finalize();
        let hash = format!("{fp:X}/sha256:{result:x}");

        info!("Adding release to database: {hash:?}");
        self.insert(hash.as_bytes(), &normalized)?;
        Ok(())
    }

    async fn index_from_scan(&mut self, query: &sync::Query) -> Result<(String, usize)> {
        sync::index_from_scan(self, query)
    }

    async fn scan_keys(&self, prefix: &[u8]) -> Result<Vec<sled::IVec>> {
        let mut out = Vec::new();
        for item in self.scan_prefix(prefix) {
            let (hash, _data) = item.context("Failed to read from database")?;
            out.push(hash);
        }
        Ok(out)
    }

    async fn get_value(&self, key: &[u8]) -> Result<sled::IVec> {
        let value = self.sled.get(key).context("Failed to read from database")?;
        let value = value.context("Key not found in database")?;
        Ok(value)
    }

    async fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.sled.remove(key)?;
        Ok(())
    }

    async fn count(&mut self, prefix: &[u8]) -> Result<u64> {
        let count = self.sled.scan_prefix(prefix).count();
        Ok(count as u64)
    }

    async fn flush(&mut self) -> Result<()> {
        self.sled
            .flush_async()
            .await
            .context("Failed to flush database to disk")?;
        Ok(())
    }
}

impl Database {
    pub async fn open(config: &Config) -> Result<DatabaseHandle> {
        let sock_path = config.db_socket_path()?;

        if let Ok(client) = DatabaseUnixClient::connect(&sock_path).await {
            Ok(DatabaseHandle::Unix(client))
        } else {
            Ok(DatabaseHandle::Direct(Self::open_directly(config).await?))
        }
    }

    pub async fn open_directly(config: &Config) -> Result<Self> {
        let path = config.database_path()?;
        let db = Self::open_at(&path, config.db_cache_limit)?;
        Ok(db)
    }

    pub fn open_at(path: &Path, db_cache_limit: Option<u64>) -> Result<Self> {
        debug!("Opening database at {path:?}");
        let mut config = sled::Config::default()
            .path(path)
            .use_compression(true)
            // we don't really care about explicit flushing
            .flush_every_ms(Some(10_000));

        if let Some(db_cache_limit) = db_cache_limit {
            debug!("Setting sled cache capacity to {db_cache_limit:?}");
            config = config.cache_capacity(db_cache_limit);
        }

        let sled = config
            .open()
            .with_context(|| anyhow!("Failed to open database at {path:?}"))?;

        Ok(Database { sled })
    }

    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<sled::IVec>> {
        let value = self.sled.get(key)?;
        Ok(value)
    }

    pub fn insert<K: AsRef<[u8]>>(&self, key: K, value: &[u8]) -> Result<()> {
        self.sled.insert(key, value)?;
        Ok(())
    }

    pub fn scan_prefix(&self, prefix: &[u8]) -> sled::Iter {
        self.sled.scan_prefix(prefix)
    }
}
