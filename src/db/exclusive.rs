use crate::db::consume::{self, Consume};
use crate::db::header::BlockHeader;
use crate::errors::*;
use advisory_lock::{AdvisoryFileLock, FileLockMode};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncSeek, BufReader};

#[derive(Debug)]
pub struct Lock {
    // we only need to hold this, but don't use it for anything
    #[allow(dead_code)]
    file: File,
}

impl Lock {
    pub async fn acquire(path: &Path) -> Result<Self> {
        debug!("Acquiring exclusive lock on directory: {path:?}");
        let file = File::open(path)
            .await
            .with_context(|| anyhow!("Failed to open directory: {path:?}"))?;
        let file = file.into_std().await;
        AdvisoryFileLock::try_lock(&file, FileLockMode::Exclusive)
            .with_context(|| anyhow!("Failed to acquire exclusive lock for: {path:?}"))?;
        debug!("Successfully acquired exclusive lock");
        let file = file.into();
        Ok(Self { file })
    }
}

#[derive(Debug)]
pub struct Exclusive {
    // we only need to hold this, but don't use it for anything
    #[allow(dead_code)]
    lock: Lock,
    verified_shards: BTreeSet<PathBuf>,
}

impl Exclusive {
    pub async fn acquire(path: &Path) -> Result<Self> {
        let lock = Lock::acquire(path).await?;
        Ok(Exclusive {
            lock,
            verified_shards: BTreeSet::new(),
        })
    }

    #[cfg(test)]
    pub fn dummy() -> Result<Self> {
        let file = tempfile::tempfile()?;
        Ok(Exclusive {
            lock: Lock {
                file: File::from_std(file),
            },
            verified_shards: BTreeSet::new(),
        })
    }

    async fn verify_next_block<R: AsyncRead + AsyncSeek + Unpin + Send>(
        path: &Path,
        mut reader: R,
    ) -> Result<u64> {
        let (header, n) = BlockHeader::parse(&mut reader)
            .await
            .with_context(|| anyhow!("Failed to read block header: {path:?}"))?;

        // skip over data, verify the expected number of bytes is present
        consume::CheckedSkipValue::consume(&mut reader, &header)
            .await
            .with_context(|| anyhow!("Failed to process block: {path:?}"))?;
        trace!("Successfully verified block data is present");

        Ok(n as u64 + header.length)
    }

    pub async fn ensure_tail_integrity<P: AsRef<Path>>(
        &mut self,
        path: P,
        file: &mut File,
    ) -> Result<()> {
        let path = path.as_ref();
        if !self.verified_shards.contains(path) {
            debug!("Verifying tail integrity of on-disk file: {path:?}");
            let mut last_valid_offset = 0;
            let mut reader = BufReader::new(&mut *file);
            loop {
                // check if more data is available
                if reader
                    .fill_buf()
                    .await
                    .with_context(|| anyhow!("Failed to check for end of file: {path:?}"))?
                    .is_empty()
                {
                    // reached EOF
                    break;
                }

                // verify next block is fully present on disk
                match Self::verify_next_block(path, &mut reader).await {
                    Ok(n) => {
                        last_valid_offset += n;
                    }
                    Err(err) => {
                        warn!("File contains partial block, truncating to end of last valid block (offset={last_valid_offset}): {err:#}");
                        file.set_len(last_valid_offset).await.with_context(|| {
                            anyhow!("Failed to truncate file to last valid offset: {path:?}")
                        })?;
                        break;
                    }
                }
            }

            self.verified_shards.insert(path.to_owned());
            debug!("Verified tail integrity of on-disk file: {path:?}");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{self, AsyncSeekExt, AsyncWriteExt};

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn tempfile() -> Result<File> {
        Ok(File::from_std(tempfile::tempfile()?))
    }

    async fn file_to_buf(file: &mut File) -> Result<Vec<u8>> {
        file.rewind().await?;
        let mut buf = Vec::new();
        io::copy(file, &mut buf)
            .await
            .context("Failed to read to buffer")?;
        Ok(buf)
    }

    #[tokio::test]
    async fn test_lock_directory() {
        init();
        let dir = tempfile::tempdir().unwrap();
        let _lock = Lock::acquire(dir.path()).await.unwrap();
        let err = Lock::acquire(dir.path()).await.err().unwrap().to_string();
        let (err, _) = err.split_once(": ").unwrap();
        assert_eq!(err, "Failed to acquire exclusive lock for");
    }

    #[tokio::test]
    async fn test_release_lock() {
        init();
        let dir = tempfile::tempdir().unwrap();
        {
            let _lock = Lock::acquire(dir.path()).await.unwrap();
            let err = Lock::acquire(dir.path()).await.err().unwrap().to_string();
            let (err, _) = err.split_once(": ").unwrap();
            assert_eq!(err, "Failed to acquire exclusive lock for");
        }
        let _lock = Lock::acquire(dir.path()).await.unwrap();
    }

    fn bytes_block1() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(39u16.to_be_bytes());
        bytes.extend(b"sha256:");
        bytes.extend([
            0xe8, 0x47, 0x12, 0x23, 0x87, 0x09, 0x39, 0x8f, 0x6d, 0x34, 0x9d, 0xc2, 0x25, 0x0b,
            0x0e, 0xfc, 0xa4, 0xb7, 0x2d, 0x8c, 0x2b, 0xfb, 0x7b, 0x74, 0x33, 0x9d, 0x30, 0xba,
            0x94, 0x05, 0x6b, 0x14,
        ]);
        bytes.extend(4u64.to_be_bytes());
        bytes.extend(b"ohai");
        bytes
    }

    fn bytes_block2() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(39u16.to_be_bytes());
        bytes.extend(b"sha256:");
        bytes.extend([
            0xa8, 0xf0, 0xaf, 0x3c, 0x68, 0xac, 0xb0, 0x82, 0xa4, 0x65, 0xc9, 0x68, 0x0e, 0x79,
            0x02, 0x61, 0x55, 0xcb, 0x56, 0x69, 0x2d, 0xa7, 0x36, 0x4d, 0xf7, 0x37, 0xc4, 0xe4,
            0x75, 0xb7, 0x3a, 0x3a,
        ]);
        bytes.extend(20u64.to_be_bytes());
        bytes.extend(b"hello world, it's me");
        bytes
    }

    #[tokio::test]
    async fn test_tail_integrity_one_block() {
        init();

        // write data
        let mut file = tempfile().unwrap();
        file.write_all(&bytes_block1()).await.unwrap();
        file.rewind().await.unwrap();

        // verify
        let mut exclusive = Exclusive::dummy().unwrap();
        exclusive
            .ensure_tail_integrity("/tmp/apt-swarm/sha256:xx", &mut file)
            .await
            .unwrap();

        let buf = file_to_buf(&mut file).await.unwrap();
        assert_eq!(
            buf,
            &[
                0, 39, 115, 104, 97, 50, 53, 54, 58, 232, 71, 18, 35, 135, 9, 57, 143, 109, 52,
                157, 194, 37, 11, 14, 252, 164, 183, 45, 140, 43, 251, 123, 116, 51, 157, 48, 186,
                148, 5, 107, 20, 0, 0, 0, 0, 0, 0, 0, 4, 111, 104, 97, 105,
            ]
        );
    }

    #[tokio::test]
    async fn test_tail_integrity_two_blocks() {
        init();

        // write data
        let mut file = tempfile().unwrap();
        file.write_all(&bytes_block1()).await.unwrap();
        file.write_all(&bytes_block2()).await.unwrap();
        file.rewind().await.unwrap();

        // verify
        let mut exclusive = Exclusive::dummy().unwrap();
        exclusive
            .ensure_tail_integrity("/tmp/apt-swarm/sha256:xx", &mut file)
            .await
            .unwrap();

        let buf = file_to_buf(&mut file).await.unwrap();
        assert_eq!(
            buf,
            &[
                0, 39, 115, 104, 97, 50, 53, 54, 58, 232, 71, 18, 35, 135, 9, 57, 143, 109, 52,
                157, 194, 37, 11, 14, 252, 164, 183, 45, 140, 43, 251, 123, 116, 51, 157, 48, 186,
                148, 5, 107, 20, 0, 0, 0, 0, 0, 0, 0, 4, 111, 104, 97, 105, 0, 39, 115, 104, 97,
                50, 53, 54, 58, 168, 240, 175, 60, 104, 172, 176, 130, 164, 101, 201, 104, 14, 121,
                2, 97, 85, 203, 86, 105, 45, 167, 54, 77, 247, 55, 196, 228, 117, 183, 58, 58, 0,
                0, 0, 0, 0, 0, 0, 20, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 44, 32,
                105, 116, 39, 115, 32, 109, 101,
            ]
        );
    }

    #[tokio::test]
    async fn test_tail_integrity_empty() {
        init();

        let mut file = tempfile().unwrap();
        let mut exclusive = Exclusive::dummy().unwrap();
        exclusive
            .ensure_tail_integrity("/tmp/apt-swarm/sha256:xx", &mut file)
            .await
            .unwrap();
        assert_eq!(
            exclusive.verified_shards,
            ["/tmp/apt-swarm/sha256:xx".into()].into_iter().collect()
        );

        let buf = file_to_buf(&mut file).await.unwrap();
        assert_eq!(buf, b"");
    }

    #[tokio::test]
    async fn test_tail_integrity_first_block_truncated() {
        init();

        // write data (test with partial block header)
        let mut file = tempfile().unwrap();
        file.write_all(&bytes_block1()[..43]).await.unwrap();
        file.rewind().await.unwrap();

        // verify
        let mut exclusive = Exclusive::dummy().unwrap();
        exclusive
            .ensure_tail_integrity("/tmp/apt-swarm/sha256:xx", &mut file)
            .await
            .unwrap();

        let buf = file_to_buf(&mut file).await.unwrap();
        assert_eq!(buf, b"");
    }

    #[tokio::test]
    async fn test_tail_integrity_second_block_truncated() {
        init();

        // write data (test with partial block data)
        let mut file = tempfile().unwrap();
        file.write_all(&bytes_block1()).await.unwrap();
        file.write_all(&bytes_block2()[..50]).await.unwrap();
        file.rewind().await.unwrap();

        // verify
        let mut exclusive = Exclusive::dummy().unwrap();
        exclusive
            .ensure_tail_integrity("/tmp/apt-swarm/sha256:xx", &mut file)
            .await
            .unwrap();

        let buf = file_to_buf(&mut file).await.unwrap();
        assert_eq!(
            buf,
            &[
                0, 39, 115, 104, 97, 50, 53, 54, 58, 232, 71, 18, 35, 135, 9, 57, 143, 109, 52,
                157, 194, 37, 11, 14, 252, 164, 183, 45, 140, 43, 251, 123, 116, 51, 157, 48, 186,
                148, 5, 107, 20, 0, 0, 0, 0, 0, 0, 0, 4, 111, 104, 97, 105,
            ]
        );
    }
}
