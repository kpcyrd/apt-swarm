use crate::db;
use crate::db::compression;
use crate::db::header::BlockHeader;
use crate::errors::*;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, SeekFrom};

#[async_trait]
pub trait Consume {
    type Item: Ord + 'static;

    async fn consume<R: AsyncRead + AsyncSeek + Unpin + Send>(
        mut reader: R,
        header: &BlockHeader,
    ) -> Result<Self::Item>;
}

/// Read and return data
pub struct ReadValue;

#[async_trait]
impl Consume for ReadValue {
    type Item = db::Value;

    async fn consume<R: AsyncRead + AsyncSeek + Unpin + Send>(
        mut reader: R,
        header: &BlockHeader,
    ) -> Result<Self::Item> {
        let mut compressed = vec![0u8; header.data_length as usize];
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

/// Skip over data immediately, possibly beyond EOF
pub struct FastSkipValue;

#[async_trait]
impl Consume for FastSkipValue {
    type Item = ();

    async fn consume<R: AsyncRead + AsyncSeek + Unpin + Send>(
        mut reader: R,
        header: &BlockHeader,
    ) -> Result<Self::Item> {
        reader
            .seek(SeekFrom::Current(header.data_length as i64))
            .await
            .context("Failed to seek over block data")?;
        trace!("Seeked forward by {} bytes", header.data_length);
        Ok(())
    }
}

/// Skip over data, verify enough data is present before seek
pub struct CheckedSkipValue;

#[async_trait]
impl Consume for CheckedSkipValue {
    type Item = ();

    async fn consume<R: AsyncRead + AsyncSeek + Unpin + Send>(
        mut reader: R,
        header: &BlockHeader,
    ) -> Result<Self::Item> {
        // determine if enough data is available
        let pos = reader
            .stream_position()
            .await
            .context("Failed to determine stream position")?;
        let end = reader
            .seek(SeekFrom::End(0))
            .await
            .context("Failed to seek to file end")?;

        let remaining = end - pos;
        if remaining < header.data_length {
            bail!(
                "Seek failed, missing {} bytes",
                header.data_length - remaining
            );
        }

        // we have enough data, perform seek
        let new = reader
            .seek(SeekFrom::Start(pos + header.data_length))
            .await
            .context("Failed to seek over block data")?;
        trace!("Seeked forward by {} bytes", new - pos);
        Ok(())
    }
}
