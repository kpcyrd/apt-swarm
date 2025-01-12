use crate::db;
use crate::db::compression;
use crate::db::header::BlockHeader;
use crate::errors::*;
use async_trait::async_trait;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, BufReader, SeekFrom};

#[async_trait]
pub trait Consume {
    type Item: Ord + 'static;

    async fn consume(reader: &mut BufReader<File>, header: &BlockHeader) -> Result<Self::Item>;
}

pub struct ReadValue;

#[async_trait]
impl Consume for ReadValue {
    type Item = db::Value;

    async fn consume(reader: &mut BufReader<File>, header: &BlockHeader) -> Result<Self::Item> {
        let mut compressed = vec![0u8; header.length as usize];
        reader
            .read_exact(&mut compressed)
            .await
            .context("Failed to read block data")?;

        let data = compression::decompress(&compressed)
            .await
            .context("Failed to decompress block data")?;

        Ok(data)
    }
}

pub struct SkipValue;

#[async_trait]
impl Consume for SkipValue {
    type Item = ();

    async fn consume(reader: &mut BufReader<File>, header: &BlockHeader) -> Result<Self::Item> {
        reader
            .seek(SeekFrom::Current(header.length as i64))
            .await
            .context("Failed to seek over block data")?;
        Ok(())
    }
}
