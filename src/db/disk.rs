use super::{DatabaseClient, DatabaseHandle, DatabaseUnixClient};
use crate::config::Config;
use crate::errors::*;
use crate::newdb::header::BlockHeader;
use crate::signed::Signed;
use crate::sled;
use crate::sync;
use async_trait::async_trait;
use bstr::BStr;
use bstr::ByteSlice;
use sequoia_openpgp::Fingerprint;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

pub const SHARD_ID_SIZE: usize = 2;

/// Writers should open the database in exclusive mode
/// Readers can operate on a database that's being written to
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum AccessMode {
    Exclusive,
    Relaxed,
}

fn is_valid_key_fp(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| match b {
        b'0'..=b'9' => true,
        b'A'..=b'F' => true,
        _ => false,
    })
}

#[derive(Debug)]
pub struct Database {
    path: PathBuf,
    mode: AccessMode,
    // sled: sled::Db,
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
        self.insert(hash.as_bytes(), &normalized).await?;
        Ok(hash)
    }

    async fn index_from_scan(&mut self, query: &sync::Query) -> Result<(String, usize)> {
        sync::index_from_scan(self, query).await
    }

    async fn scan_keys(&self, prefix: &[u8]) -> Result<Vec<sled::IVec>> {
        let mut out = Vec::new();
        for item in self.scan_prefix(prefix).await {
            let (hash, _data) = item.context("Failed to read from database")?;
            out.push(hash);
        }
        Ok(out)
    }

    async fn get_value(&self, key: &[u8]) -> Result<sled::IVec> {
        let value = self
            .get(key)
            .await
            .context("Failed to read from database")?;
        let value = value.context("Key not found in database")?;
        Ok(value)
    }

    async fn delete(&mut self, key: &[u8]) -> Result<()> {
        /*
        self.sled.remove(key)?;
        Ok(())
        */
        if self.mode != AccessMode::Exclusive {
            bail!("Tried to perform insert on readonly database");
        }
        todo!("sled(delete)")
    }

    async fn count(&mut self, prefix: &[u8]) -> Result<u64> {
        warn!(
            "Implementation of count is really bad: {:?}",
            BStr::new(prefix)
        );
        let out = self.scan_prefix(prefix).await;
        Ok(out.len() as u64)
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

        // TODO: assert mode

        /*
        let mut config = sled::Config::default()
            .path(path)
            .use_compression(true)
            // we don't really care about explicit flushing
            .flush_every_ms(Some(10_000));

        if let Some(db_cache_limit) = db_cache_limit {
            debug!("Setting sled cache capacity to {db_cache_limit:?}");
            config = config.cache_capacity(db_cache_limit);
        }

        let sled = config
            .open()
            .with_context(|| anyhow!("Failed to open database at {path:?}"))?;

        Ok(Database { sled })
        */
        Ok(Database { path, mode })
    }

    pub async fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<sled::IVec>> {
        warn!("get_value implementation is crazy inefficient");
        let out = self.scan_prefix(key.as_ref()).await;
        let Some(entry) = out.into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(entry?.1))
    }

    // TODO: this function should expect some fingerprint and CryptoHash argument (maybe?)
    // TODO: this function is only used in one place and can be easily changed
    pub async fn insert<K: AsRef<[u8]>>(&self, key: K, value: &[u8]) -> Result<()> {
        if self.mode != AccessMode::Exclusive {
            bail!("Tried to perform insert on readonly database");
        }

        // TODO
        let key = key.as_ref();

        if self.get(key).await?.is_some() {
            debug!("Skipping insert, document is already present");
            return Ok(());
        }

        let (fp, hash) = key
            .split_once_str(&"/")
            .with_context(|| anyhow!("Invalid insert key: {key:?}"))?;
        if !is_valid_key_fp(fp) {
            bail!("Key fingerprint contains invalid characters");
        }

        let idx = memchr::memchr(b':', hash)
            .with_context(|| anyhow!("Missing hash id in key: {key:?}"))?;

        let (shard, _) = hash
            .split_at_checked(idx + 1 + SHARD_ID_SIZE)
            .with_context(|| anyhow!("Key is too short: {key:?}"))?;

        let folder = self.path.join(OsStr::from_bytes(fp));
        fs::create_dir_all(&folder)
            .await
            .with_context(|| anyhow!("Failed to create folder: {folder:?}"))?;

        let path = folder.join(OsStr::from_bytes(shard));

        // TODO: this can be defered from the key + .len()
        // TODO: but also maybe the key shouldn't be so opaque
        let header = BlockHeader::calculate(value);

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
        file.write_all(value)
            .await
            .context("Failed to write block data")?;

        Ok(())
    }

    // TODO: rewrite this to be streaming again
    // TODO: this is a nightmare function, but works for now
    pub async fn scan_prefix(&self, prefix: &[u8]) -> Vec<Result<(sled::IVec, sled::IVec)>> {
        warn!("TODO: scan_prefix needs to be rewritten to streaming");
        let mut out = Vec::new();

        // TODO: this definitely needs to be rewritten
        // TODO: this should be sorted before processing
        match fs::read_dir(&self.path).await {
            Ok(mut dir) => loop {
                match dir.next_entry().await {
                    Ok(Some(folder)) => {
                        let folder_name = match folder.file_name().into_string() {
                            Ok(name) => name,
                            Err(err) => {
                                out.push(Err(anyhow!("Found invalid key directory: {err:?}")));
                                return out;
                            }
                        };

                        // TODO: optimize: skip directory if it can't match prefix
                        // TODO: this also needs sorting somehow
                        match fs::read_dir(folder.path()).await {
                            Ok(mut dir) => loop {
                                match dir.next_entry().await {
                                    Ok(Some(folder)) => {
                                        let path = folder.path();
                                        let file =
                                            match fs::File::open(&path).await.with_context(|| {
                                                anyhow!("Failed to open database file: {path:?}")
                                            }) {
                                                Ok(file) => file,
                                                Err(err) => {
                                                    out.push(Err(err));
                                                    return out;
                                                }
                                            };
                                        let mut reader = BufReader::new(file);
                                        // TODO: this also needs sorting(??)
                                        loop {
                                            // TODO: check if more data is available (somehow)
                                            match reader.fill_buf().await {
                                                Ok(buf) => {
                                                    if buf.is_empty() {
                                                        // reached EOF
                                                        break;
                                                    }
                                                }
                                                Err(err) => {
                                                    out.push(Err(err.into()));
                                                    return out;
                                                }
                                            }

                                            match BlockHeader::parse(&mut reader).await {
                                                Ok((header, _n)) => {
                                                    // TODO: if header eligible, add to list
                                                    debug!("Parsed block header: {header:?}");
                                                    // TODO: this shouldn't automatically read the value into memory
                                                    // TODO: this won't work correctly on 32 bit with very large files
                                                    let mut buf = vec![0u8; header.length as usize];
                                                    match reader.read_exact(&mut buf).await {
                                                        Ok(_) => {
                                                            let key = format!(
                                                                "{}/{}",
                                                                folder_name, header.hash.0
                                                            );
                                                            if BStr::new(key.as_bytes())
                                                                .starts_with(prefix)
                                                            {
                                                                out.push(Ok((
                                                                    key.into_bytes(),
                                                                    buf,
                                                                )));
                                                            }
                                                        }
                                                        Err(err) => {
                                                            out.push(Err(err.into()));
                                                            return out;
                                                        }
                                                    }
                                                }
                                                Err(err) => {
                                                    out.push(Err(err.into()));
                                                    return out;
                                                }
                                            }
                                        }
                                    }
                                    Ok(None) => break,
                                    Err(err) => {
                                        out.push(Err(err.into()));
                                        return out;
                                    }
                                }
                            },
                            Err(err) => {
                                out.push(Err(err.into()));
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        out.push(Err(err.into()));
                        return out;
                    }
                }
            },
            Err(err) => {
                if err.kind() != ErrorKind::NotFound {
                    out.push(Err(err).context("Failed to read storage directory"));
                }
            }
        }

        out.sort_by(|a, b| {
            if let (Ok(a), Ok(b)) = (a, b) {
                a.cmp(b)
            } else {
                unreachable!("when adding an error to `out`, we should also return");
            }
        });

        out
    }
}
