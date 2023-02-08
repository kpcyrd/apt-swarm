use crate::config::Config;
use crate::errors::*;
use crate::signed;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct Database {
    sled: sled::Db,
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

    /// This function doesn't need to be called explicitly, but calling it allows better error handling than `drop` does
    pub async fn flush(&self) -> Result<()> {
        self.sled
            .flush_async()
            .await
            .context("Failed to flush database to disk")?;
        Ok(())
    }

    pub fn add_release(&self, release: &[u8]) -> Result<()> {
        // TODO: consider making a `Normalized` type to allow passing already normalized structs, without risking of getting passed un-normalized releases
        let (normalized, _remaining) =
            signed::canonicalize(release).context("Failed to canonicalize release")?;

        let mut hasher = Sha256::new();
        hasher.update(&normalized);
        let result = hasher.finalize();
        let hash = format!("sha256:{result:x}");

        info!("Adding release to database: {hash:?}");
        self.insert(hash.as_bytes(), &normalized)?;
        Ok(())
    }

    pub fn scan_prefix(&self, prefix: &[u8]) -> sled::Iter {
        self.sled.scan_prefix(prefix)
    }
}
