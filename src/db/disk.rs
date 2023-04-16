use super::{DatabaseClient, DatabaseHandle, DatabaseUnixClient};
use crate::config::Config;
use crate::errors::*;
use crate::signed::Signed;
use crate::sync;
use async_trait::async_trait;
use heed::types::*;
use sequoia_openpgp::Fingerprint;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs;

pub struct Database {
    env: heed::Env,
    heed: heed::Database<ByteSlice, ByteSlice>,
}

#[async_trait]
impl DatabaseClient for Database {
    async fn add_release(&mut self, fp: &Fingerprint, signed: &Signed) -> Result<String> {
        let normalized = signed.to_clear_signed()?;

        let mut hasher = Sha256::new();
        hasher.update(&normalized);
        let result = hasher.finalize();
        let hash = format!("{fp:X}/sha256:{result:x}");

        info!("Adding release to database: {hash:?}");
        self.insert(hash.as_bytes(), &normalized)?;
        Ok(hash)
    }

    async fn index_from_scan(&mut self, query: &sync::Query) -> Result<(String, usize)> {
        let prefix = query.to_string();

        let mut counter = 0;
        let mut hasher = Sha256::new();

        let rotxn = self.env.read_txn()?;
        for item in self
            .heed
            .prefix_iter(&rotxn, prefix.as_bytes())?
            .lazily_decode_data()
        {
            let (hash, _data) = item.context("Failed to read from database")?;
            hasher.update(hash);
            hasher.update(b"\n");
            counter += 1;
        }

        let result = hasher.finalize();
        Ok((format!("sha256:{result:x}"), counter))
    }

    async fn scan_keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
        let rotxn = self.env.read_txn()?;
        let mut out = Vec::new();

        if prefix.is_empty() {
            for item in self.heed.iter(&rotxn)?.lazily_decode_data() {
                let (hash, _data) = item.context("Failed to read from database")?;
                out.push(hash.to_vec());
            }
        } else {
            for item in self.heed.prefix_iter(&rotxn, prefix)?.lazily_decode_data() {
                let (hash, _data) = item.context("Failed to read from database")?;
                out.push(hash.to_vec());
            }
        }

        Ok(out)
    }

    async fn get_value(&self, key: &[u8]) -> Result<Vec<u8>> {
        let value = self.get(key).context("Failed to read from database")?;
        let value = value.context("Key not found in database")?;
        Ok(value)
    }

    async fn delete(&mut self, key: &[u8]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.heed.delete(&mut wtxn, key)?;
        wtxn.commit()?;
        Ok(())
    }

    async fn count(&mut self, prefix: &[u8]) -> Result<u64> {
        let rotxn = self.env.read_txn()?;
        let count = self
            .heed
            .prefix_iter(&rotxn, prefix)
            .context("Failed to read from database")?
            .lazily_decode_data()
            .count();
        Ok(count as u64)
    }

    async fn flush(&mut self) -> Result<()> {
        self.env
            .force_sync()
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
        let db = Self::open_at(&path).await?;
        Ok(db)
    }

    pub async fn open_at(path: &Path) -> Result<Self> {
        debug!("Opening database at {path:?}");
        fs::create_dir_all(&path).await?;

        let statvfs = nix::sys::statvfs::statvfs(path)
            .with_context(|| anyhow!("Failed to get filesystem statistics for {path:?}"))?;
        let map_size = statvfs.fragment_size() * statvfs.blocks();
        let map_size = map_size
            .try_into()
            .context("Failed to convert u64 to usize: {map_size:?}")?;

        debug!("Setting lmdb map size to {map_size:?} bytes");
        let mut env_builder = heed::EnvOpenOptions::new();
        env_builder.map_size(map_size).max_dbs(3);

        unsafe {
            env_builder.flag(heed::Flags::MdbNoSync);
        }

        let env = env_builder
            .open(path)
            .map_err(|err| anyhow!("Failed to open LMDB database at {path:?}: {err:#}"))?;

        let mut wtxn = env.write_txn()?;
        let heed = env
            .create_database(&mut wtxn, None)
            .map_err(|err| anyhow!("Failed to access default LMDB database: {err:#}"))?;
        wtxn.commit()?;

        Ok(Database { env, heed })
    }

    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>> {
        let rotxn = self.env.read_txn()?;
        let value = self.heed.get(&rotxn, key.as_ref())?;
        Ok(value.map(Vec::from))
    }

    pub fn insert<K: AsRef<[u8]>>(&self, key: K, value: &[u8]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.heed.put(&mut wtxn, key.as_ref(), value)?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn read_txn(&self) -> Result<heed::RoTxn> {
        let tx = self.env.read_txn()?;
        Ok(tx)
    }

    pub fn scan_prefix<'a>(&self, rotxn: &'a heed::RoTxn, prefix: &[u8]) -> Result<Iter<'a>> {
        let iter = self.heed.prefix_iter(rotxn, prefix)?;
        Ok(iter)
    }
}

type Iter<'a> = heed::RoPrefix<'a, ByteSlice, ByteSlice>;
