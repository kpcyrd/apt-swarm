use crate::config::Config;
use crate::sync;
use async_trait::async_trait;
use crate::errors::*;
use crate::signed::Signed;
use sha2::{Digest, Sha256};

#[async_trait]
pub trait DatabaseClient {
    async fn add_release(&self, fp: &sequoia_openpgp::Fingerprint, signed: &Signed) -> Result<()>;

    async fn index_from_scan(&self, query: &sync::Query) -> Result<(String, usize)>;

    async fn scan_keys(&self, prefix: &[u8]) -> Result<Vec<sled::IVec>>;

    async fn get_value(&self, key: &[u8]) -> Result<sled::IVec>;
}

#[derive(Debug)]
pub struct Database {
    sled: sled::Db,
}

#[async_trait]
impl DatabaseClient for Database {
    async fn add_release(&self, fp: &sequoia_openpgp::Fingerprint, signed: &Signed) -> Result<()> {
        let normalized = signed.to_clear_signed()?;

        let mut hasher = Sha256::new();
        hasher.update(&normalized);
        let result = hasher.finalize();
        let hash = format!("{fp:X}/sha256:{result:x}");

        info!("Adding release to database: {hash:?}");
        self.insert(hash.as_bytes(), &normalized)?;
        Ok(())
    }

    async fn index_from_scan(&self, query: &sync::Query) -> Result<(String, usize)> {
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
}

impl Database {
    pub fn open(config: &Config) -> Result<Self> {
        let path = config.database_path()?;
        debug!("Opening database at {path:?}");
        let config = sled::Config::default()
            .path(&path)
            .use_compression(true)
            // we don't really care about explicit flushing
            .flush_every_ms(Some(30_000));

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

    pub fn delete<K: AsRef<[u8]>>(&self, key: K) -> Result<()> {
        self.sled.remove(key)?;
        Ok(())
    }

    /// This function doesn't need to be called explicitly, but calling it allows better error handling than `drop` does
    pub async fn flush(&self) -> Result<()> {
        self.sled
            .flush_async()
            .await
            .context("Failed to flush database to disk")?;
        Ok(())
    }

    pub fn scan_prefix(&self, prefix: &[u8]) -> sled::Iter {
        self.sled.scan_prefix(prefix)
    }
}
