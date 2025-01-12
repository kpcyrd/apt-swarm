use super::{Database, DatabaseClient};
use crate::db;
use crate::errors::*;
use crate::signed::Signed;
use crate::sync;
use async_trait::async_trait;
use sequoia_openpgp::Fingerprint;
use tokio::sync::mpsc;

pub enum Query {
    AddRelease(Fingerprint, Signed, mpsc::Sender<String>),
    IndexFromScan(sync::Query, mpsc::Sender<(String, usize)>),
    Spill(Vec<u8>, mpsc::Sender<Vec<(db::Key, db::Value)>>),
    GetValue(Vec<u8>, mpsc::Sender<db::Value>),
    // Delete(Vec<u8>, mpsc::Sender<()>),
    Count(Vec<u8>, mpsc::Sender<u64>),
    Flush(mpsc::Sender<()>),
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
                    let hash = self.db.add_release(&fp, &signed).await?;
                    tx.send(hash).await.ok();
                }
                Query::IndexFromScan(query, tx) => {
                    let ret = self.db.index_from_scan(&query).await?;
                    tx.send(ret).await.ok();
                }
                Query::Spill(prefix, tx) => {
                    let ret = self.db.spill(&prefix).await?;
                    tx.send(ret).await.ok();
                }
                Query::GetValue(key, tx) => {
                    let ret = self.db.get_value(&key).await?;
                    tx.send(ret).await.ok();
                }
                Query::Count(key, tx) => {
                    let ret = self.db.count(&key).await?;
                    tx.send(ret).await.ok();
                }
                Query::Flush(tx) => {
                    tx.send(()).await.ok();
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
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
    async fn add_release(&mut self, fp: &Fingerprint, signed: &Signed) -> Result<String> {
        let (tx, rx) = mpsc::channel(1);
        let query = Query::AddRelease(fp.clone(), signed.clone(), tx);
        self.request(query, rx).await
    }

    async fn index_from_scan(&mut self, query: &sync::Query) -> Result<(String, usize)> {
        let (tx, rx) = mpsc::channel(1);
        let query = Query::IndexFromScan(query.clone(), tx);
        self.request(query, rx).await
    }

    async fn spill(&self, prefix: &[u8]) -> Result<Vec<(db::Key, db::Value)>> {
        let (tx, rx) = mpsc::channel(1);
        let query = Query::Spill(prefix.to_vec(), tx);
        self.request(query, rx).await
    }

    async fn get_value(&self, key: &[u8]) -> Result<db::Value> {
        let (tx, rx) = mpsc::channel(1);
        let query = Query::GetValue(key.to_vec(), tx);
        self.request(query, rx).await
    }

    async fn count(&mut self, key: &[u8]) -> Result<u64> {
        let (tx, rx) = mpsc::channel(1);
        let query = Query::Count(key.to_vec(), tx);
        self.request(query, rx).await
    }

    async fn flush(&mut self) -> Result<()> {
        let (tx, rx) = mpsc::channel(1);
        let query = Query::Flush(tx);
        self.request(query, rx).await
    }
}
