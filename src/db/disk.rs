use super::{
    compression, exclusive,
    header::{BlockHeader, CryptoHash},
    DatabaseClient, DatabaseHandle, DatabaseUnixClient,
};
use crate::config::Config;
use crate::db;
use crate::errors::*;
use crate::signed::Signed;
use crate::sync;
use async_trait::async_trait;
use bstr::BStr;
use futures::{Stream, StreamExt};
use sequoia_openpgp::Fingerprint;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, SeekFrom};

pub const SHARD_ID_SIZE: usize = 2;

/// Writers should open the database in exclusive mode
/// Readers can operate on a database that's being written to
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum AccessMode {
    Exclusive,
    Relaxed,
}

fn folder_matches_prefix<'a>(folder: &str, full_prefix: &'a [u8]) -> Option<&'a [u8]> {
    let (prefix, suffix) = full_prefix
        .split_at_checked(folder.len())
        .unwrap_or((full_prefix, &[]));
    if BStr::new(folder.as_bytes()).starts_with(prefix) {
        if prefix != full_prefix {
            suffix.strip_prefix(b"/")
        } else {
            Some(suffix)
        }
    } else {
        None
    }
}

fn file_matches_prefix(file: &str, prefix: &[u8]) -> bool {
    let prefix = prefix
        .split_at_checked(file.len())
        .map(|(prefix, _)| prefix)
        .unwrap_or(prefix);
    BStr::new(file.as_bytes()).starts_with(prefix)
}

#[derive(Debug)]
pub struct Database {
    path: PathBuf,
    lock: Option<exclusive::Lock>,
}

#[async_trait]
impl DatabaseClient for Database {
    async fn add_release(&mut self, fp: &Fingerprint, signed: &Signed) -> Result<String> {
        let normalized = signed.to_clear_signed()?;
        let hash = CryptoHash::calculate(&normalized);

        let (key, _new) = self.insert(fp, hash, &normalized).await?;
        Ok(key)
    }

    async fn index_from_scan(&mut self, query: &sync::Query) -> Result<(String, usize)> {
        sync::index_from_scan(self, query).await
    }

    async fn spill(&self, prefix: &[u8]) -> Result<Vec<(db::Key, db::Value)>> {
        let mut out = Vec::new();
        let stream = self.scan_prefix(prefix);
        tokio::pin!(stream);
        while let Some(item) = stream.next().await {
            let (hash, data) = item.context("Failed to read from database (spill)")?;
            out.push((hash, data));
        }
        Ok(out)
    }

    async fn get_value(&self, key: &[u8]) -> Result<db::Value> {
        let value = self.get(key).await?;
        let value = value.context("Key not found in database")?;
        Ok(value)
    }

    async fn count(&mut self, prefix: &[u8]) -> Result<u64> {
        let count = self.scan_prefix(prefix).count().await;
        Ok(count as u64)
    }

    async fn flush(&mut self) -> Result<()> {
        /*
        self.sled
            .flush_async()
            .await
            .context("Failed to flush database to disk")?;
        Ok(())
        */
        warn!("TODO: flush is not actually implemented");
        Ok(())
    }
}

impl Database {
    #[inline]
    fn is_exclusive(&self) -> bool {
        self.lock.is_some()
    }

    pub async fn open(config: &Config, mode: AccessMode) -> Result<DatabaseHandle> {
        let sock_path = config.db_socket_path()?;

        if mode != AccessMode::Exclusive {
            if let Ok(client) = DatabaseUnixClient::connect(&sock_path).await {
                return Ok(DatabaseHandle::Unix(client));
            }
        }

        Ok(DatabaseHandle::Direct(
            Self::open_directly(config, mode).await?,
        ))
    }

    pub async fn open_directly(config: &Config, mode: AccessMode) -> Result<Self> {
        let path = config.database_path()?;
        let db = Self::open_at(path, mode).await?;
        Ok(db)
    }

    pub async fn open_at(path: PathBuf, mode: AccessMode) -> Result<Self> {
        debug!("Opening database at {path:?}");

        fs::create_dir_all(&path)
            .await
            .with_context(|| anyhow!("Failed to create directory: {path:?}"))?;

        let lock = if mode == AccessMode::Exclusive {
            let lock = exclusive::Lock::acquire(&path).await?;
            Some(lock)
        } else {
            None
        };

        Ok(Database { path, lock })
    }

    pub async fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<db::Value>> {
        let stream = self.scan_prefix(key.as_ref());
        tokio::pin!(stream);
        let Some(entry) = stream.next().await else {
            return Ok(None);
        };
        let entry = entry.context("Failed to read from database (get)")?;
        Ok(Some(entry.1))
    }

    // TODO: this function should expect some fingerprint and CryptoHash argument (maybe?)
    // TODO: this function is only used in one place and can be easily changed
    pub async fn insert(
        &self,
        fp: &Fingerprint,
        hash: CryptoHash,
        value: &[u8],
    ) -> Result<(String, bool)> {
        if !self.is_exclusive() {
            bail!("Tried to perform insert on readonly database");
        }

        // TODO: check if we can clean this up further
        let fp_str = format!("{fp:X}");
        let hash_str = hash.as_str();
        let key = format!("{fp_str}/{hash_str}");

        if self.get(&key).await?.is_some() {
            info!("Skipping document, already present: {key:?}");
            return Ok((key, false));
        }
        info!("Adding document to database: {key:?}");

        let idx = hash_str
            .find(':')
            .with_context(|| anyhow!("Missing hash id in key: {key:?}"))?;

        let (shard, _) = hash_str
            .split_at_checked(idx + 1 + SHARD_ID_SIZE)
            .with_context(|| anyhow!("Key is too short: {key:?}"))?;

        let folder = self.path.join(fp_str);
        fs::create_dir_all(&folder)
            .await
            .with_context(|| anyhow!("Failed to create folder: {folder:?}"))?;
        let path = folder.join(shard);

        let compressed = compression::compress(value)
            .await
            .with_context(|| anyhow!("Failed to compress block data: {path:?}"))?;
        let header = BlockHeader::new(hash, compressed.len());

        // TODO: check the file is in a clean state

        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(&path)
            .await
            .with_context(|| anyhow!("Failed to open file: {path:?}"))?;

        header
            .write(&mut file)
            .await
            .context("Failed to write block header")?;
        file.write_all(&compressed)
            .await
            .context("Failed to write block data")?;

        Ok((key, true))
    }

    async fn read_directory_sorted(path: &Path) -> Result<Vec<(PathBuf, String)>> {
        let mut dir = match fs::read_dir(path).await {
            Ok(dir) => dir,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(vec![]),
            Err(err) => {
                return Err(err).with_context(|| anyhow!("Failed to read directory: {path:?}"));
            }
        };

        let mut out = Vec::new();
        while let Some(entry) = dir
            .next_entry()
            .await
            .with_context(|| anyhow!("Failed to read next directory entry: {path:?}"))?
        {
            let path = entry.path();

            let filename = entry
                .file_name()
                .into_string()
                .map_err(|err| anyhow!("Found invalid directory entry name: {err:?}"))?;

            out.push((path, filename));
        }

        out.sort();
        Ok(out)
    }

    async fn read_shard(
        path: &Path,
        folder_name: &str,
        partitioned_prefix: &[u8],
    ) -> Result<Vec<(db::Key, db::Value)>> {
        let file = fs::File::open(path)
            .await
            .with_context(|| anyhow!("Failed to open database file: {path:?}"))?;

        let mut out = Vec::new();
        let mut reader = BufReader::new(file);

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

            let (header, _n) = BlockHeader::parse(&mut reader)
                .await
                .with_context(|| anyhow!("Failed to read block header: {path:?}"))?;

            debug!("Parsed block header: {header:?}");
            if header.hash.0.as_bytes().starts_with(partitioned_prefix) {
                // header is eligible, add to list

                // TODO: this shouldn't automatically read the value into memory
                // TODO: this won't work correctly on 32 bit with very large files
                let mut compressed = vec![0u8; header.length as usize];
                reader
                    .read_exact(&mut compressed)
                    .await
                    .with_context(|| anyhow!("Failed to read block data: {path:?}"))?;

                let data = compression::decompress(&compressed)
                    .await
                    .with_context(|| anyhow!("Failed to decompress block data: {path:?}"))?;

                let key = format!("{}/{}", folder_name, header.hash.0);
                out.push((key.into_bytes(), data));
            } else {
                // does not match prefix, skip over it
                reader
                    .seek(SeekFrom::Current(header.length as i64))
                    .await
                    .with_context(|| anyhow!("Failed to seek over block data: {path:?}"))?;
            }
        }

        out.sort();
        Ok(out)
    }

    pub fn scan_keys<'a>(&'a self, prefix: &'a [u8]) -> impl Stream<Item = Result<db::Key>> + 'a {
        self.scan_prefix(prefix)
            .map(|item| item.map(|(key, _value)| key))
    }

    pub fn scan_prefix<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> impl Stream<Item = Result<(db::Key, db::Value)>> + 'a {
        async_stream::try_stream! {
            for (folder_path, folder_name) in Self::read_directory_sorted(&self.path).await? {
                if !folder_path.is_dir() {
                    warn!("Found unexpected file in storage folder: {folder_path:?}");
                    continue;
                }

                let Some(partitioned_prefix) = folder_matches_prefix(&folder_name, prefix)
                else {
                    continue;
                };

                for (path, filename) in Self::read_directory_sorted(&folder_path).await? {
                    if !file_matches_prefix(&filename, partitioned_prefix) {
                        continue;
                    }

                    for item in Self::read_shard(&path, &folder_name, partitioned_prefix).await? {
                        yield item;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_folder_folder_matches_prefix() {
        assert_eq!(
            folder_matches_prefix("ED541312A33F1128F10B1C6C54404762BBB6E853", b""),
            Some(&b""[..])
        );
        assert_eq!(
            folder_matches_prefix("ED541312A33F1128F10B1C6C54404762BBB6E853", b"E"),
            Some(&b""[..])
        );
        assert_eq!(
            folder_matches_prefix("ED541312A33F1128F10B1C6C54404762BBB6E853", b"EF"),
            None
        );
        assert_eq!(
            folder_matches_prefix("ED541312A33F1128F10B1C6C54404762BBB6E853", b"ED541312"),
            Some(&b""[..])
        );
        assert_eq!(
            folder_matches_prefix(
                "ED541312A33F1128F10B1C6C54404762BBB6E853",
                b"ED541312A33F1128F10B1C6C54404762BBB6E853"
            ),
            Some(&b""[..])
        );
        assert_eq!(
            folder_matches_prefix(
                "ED541312A33F1128F10B1C6C54404762BBB6E853",
                b"ED541312A33F1128F10B1C6C54404762BBB6E853/"
            ),
            Some(&b""[..])
        );
        assert_eq!(
            folder_matches_prefix(
                "ED541312A33F1128F10B1C6C54404762BBB6E853",
                b"ED541312A33F1128F10B1C6C54404762BBB6E853/sha256:"
            ),
            Some(&b"sha256:"[..])
        );
        assert_eq!(folder_matches_prefix(
            "ED541312A33F1128F10B1C6C54404762BBB6E853",
            b"ED541312A33F1128F10B1C6C54404762BBB6E853/sha256:ffe924d86aa74fdfe8b8d4b8cd9623c5df7aef626a7aada3416dc83e44e7939d"
        ), Some(&b"sha256:ffe924d86aa74fdfe8b8d4b8cd9623c5df7aef626a7aada3416dc83e44e7939d"[..]));
    }

    #[test]
    fn test_folder_folder_matches_prefix_bad_inputs() {
        assert_eq!(
            folder_matches_prefix(
                "ED541312A33F1128F10B1C6C54404762BBB6E853",
                b"ED541312A33F1128F10B1C6C54404762BBB6E853//"
            ),
            Some(&b"/"[..])
        );
        assert_eq!(
            folder_matches_prefix(
                "ED541312A33F1128F10B1C6C54404762BBB6E853",
                b"ED541312A33F1128F10B1C6C54404762BBB6E8533"
            ),
            None
        );
        assert_eq!(
            folder_matches_prefix(
                "ED541312A33F1128F10B1C6C54404762BBB6E853",
                b"ED541312A33F1128F10B1C6C54404762BBB6E85333"
            ),
            None
        );
        assert_eq!(
            folder_matches_prefix(
                "ED541312A33F1128F10B1C6C54404762BBB6E853",
                b"ED541312A33F1128F10B1C6C54404762BBB6E8533/"
            ),
            None
        );
    }

    #[test]
    fn test_file_matches_prefix() {
        assert!(file_matches_prefix("sha256:ff", b""));
        assert!(file_matches_prefix("sha256:ff", b"sha"));
        assert!(file_matches_prefix("sha256:ff", b"sha256:"));
        assert!(file_matches_prefix("sha256:ff", b"sha256:f"));
        assert!(file_matches_prefix("sha256:ff", b"sha256:ffe"));
        assert!(file_matches_prefix(
            "sha256:ff",
            b"sha256:ffe924d86aa74fdfe8b8d4b8cd9623c5df7aef626a7aada34"
        ));
        assert!(!file_matches_prefix("sha256:ff", b"sha256:e"));
        assert!(!file_matches_prefix("sha256:ff", b"sha256:fe"));
        assert!(!file_matches_prefix(
            "sha512:ff",
            b"sha256:ffe924d86aa74fdfe8b8d4b8cd9623c5df7aef626a7aada34"
        ));
        assert!(!file_matches_prefix(
            "sha256:ff",
            b"sha512:ffe924d86aa74fdfe8b8d4b8cd9623c5df7aef626a7aada34"
        ));
    }
}
