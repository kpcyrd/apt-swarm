pub mod channel;
pub mod compression;
pub mod disk;
pub mod exclusive;
pub mod header;
pub mod unix;

pub use self::channel::{DatabaseServer, DatabaseServerClient};
pub use self::disk::{AccessMode, Database};
pub use self::unix::{DatabaseHandle, DatabaseUnixClient};

use crate::errors::*;
use crate::signed::Signed;
use crate::sync;
use async_trait::async_trait;
use sequoia_openpgp::Fingerprint;

pub type Key = Vec<u8>;
pub type Value = Vec<u8>;

#[async_trait]
pub trait DatabaseClient {
    async fn add_release(&mut self, fp: &Fingerprint, signed: &Signed) -> Result<String>;

    async fn index_from_scan(&mut self, query: &sync::Query) -> Result<(String, usize)>;

    async fn batch_index_from_scan(
        &mut self,
        query: &mut sync::Query,
    ) -> Result<(sync::BatchIndex, usize)> {
        let mut batch = sync::BatchIndex::new();
        let mut total = 0;

        query.enter();
        loop {
            let (index, count) = self.index_from_scan(query).await?;
            let prefix = query.prefix.as_deref().unwrap_or("");

            trace!(
                "Calculated index for prefix: index={index:?}, prefix={:?}, count={count:?}",
                prefix
            );

            // TODO: consider only adding responses with count > 0
            batch.add(index, prefix.to_string(), count)?;
            total += count;

            if query.increment() {
                break;
            }
        }

        Ok((batch, total))
    }

    async fn scan_keys(&self, prefix: &[u8]) -> Result<Vec<Key>>;

    async fn get_value(&self, key: &[u8]) -> Result<Value>;

    async fn count(&mut self, prefix: &[u8]) -> Result<u64>;

    /// This function doesn't need to be called explicitly, but calling it allows better error handling than `drop` does
    async fn flush(&mut self) -> Result<()>;
}
