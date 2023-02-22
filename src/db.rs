use crate::config::Config;
use crate::errors::*;
use crate::signed::Signed;
use crate::sync;
use async_trait::async_trait;
use sequoia_openpgp::Fingerprint;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

#[async_trait]
pub trait DatabaseClient {
    async fn add_release(&self, fp: &Fingerprint, signed: &Signed) -> Result<()>;

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
    async fn add_release(&self, fp: &Fingerprint, signed: &Signed) -> Result<()> {
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

pub enum Query {
    AddRelease(Fingerprint, Signed, mpsc::Sender<()>),
    IndexFromScan(sync::Query, mpsc::Sender<(String, usize)>),
    ScanKeys(Vec<u8>, mpsc::Sender<Vec<sled::IVec>>),
    GetValue(Vec<u8>, mpsc::Sender<sled::IVec>),
}

#[derive(Debug)]
pub struct DatabaseServer {
    db: Database,
    rx: mpsc::Receiver<Query>,
}

impl DatabaseServer {
    pub fn new(db: Database) -> (DatabaseServer, DatabaseServerClient) {
        let (tx, rx) = mpsc::channel(32);

        let server = DatabaseServer { db, rx };
        let client = DatabaseServerClient { tx };

        (server, client)
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Some(msg) = self.rx.recv().await {
            match msg {
                Query::AddRelease(fp, signed, tx) => {
                    self.db.add_release(&fp, &signed).await?;
                    tx.send(()).await.ok();
                }
                Query::IndexFromScan(query, tx) => {
                    let ret = self.db.index_from_scan(&query).await?;
                    tx.send(ret).await.ok();
                }
                Query::ScanKeys(prefix, tx) => {
                    let ret = self.db.scan_keys(&prefix).await?;
                    tx.send(ret).await.ok();
                }
                Query::GetValue(key, tx) => {
                    let ret = self.db.get_value(&key).await?;
                    tx.send(ret).await.ok();
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DatabaseServerClient {
    tx: mpsc::Sender<Query>,
}

impl DatabaseServerClient {
    async fn request<T>(&self, query: Query, mut rx: mpsc::Receiver<T>) -> Result<T> {
        self.tx
            .send(query)
            .await
            .map_err(|_| anyhow!("Database server disconnected"))?;
        let ret = rx.recv().await.context("Database server disconnected")?;
        Ok(ret)
    }
}

#[async_trait]
impl DatabaseClient for DatabaseServerClient {
    async fn add_release(&self, fp: &Fingerprint, signed: &Signed) -> Result<()> {
        let (tx, rx) = mpsc::channel(1);
        let query = Query::AddRelease(fp.clone(), signed.clone(), tx);
        self.request(query, rx).await
    }

    async fn index_from_scan(&self, query: &sync::Query) -> Result<(String, usize)> {
        let (tx, rx) = mpsc::channel(1);
        let query = Query::IndexFromScan(query.clone(), tx);
        self.request(query, rx).await
    }

    async fn scan_keys(&self, prefix: &[u8]) -> Result<Vec<sled::IVec>> {
        let (tx, rx) = mpsc::channel(1);
        let query = Query::ScanKeys(prefix.to_vec(), tx);
        self.request(query, rx).await
    }

    async fn get_value(&self, key: &[u8]) -> Result<sled::IVec> {
        let (tx, rx) = mpsc::channel(1);
        let query = Query::GetValue(key.to_vec(), tx);
        self.request(query, rx).await
    }
}
