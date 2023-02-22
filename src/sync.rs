use crate::db::{Database, DatabaseClient};
use crate::errors::*;
use crate::keyring::Keyring;
use crate::signed::Signed;
use sequoia_openpgp::Fingerprint;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::fmt;
use std::str;
use std::str::FromStr;
use std::time::Duration;
use tokio::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time;

/// If the number of entries is greater than zero, but <= this threshold, send a dump instead of an index
pub const SPILL_THRESHOLD: usize = 1;

#[derive(Debug, Clone)]
pub struct Query {
    pub fp: Fingerprint,
    pub hash_algo: String,
    pub prefix: Option<String>,
}

impl Query {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let line = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        let line = str::from_utf8(line).context("Query contains invalid utf8")?;
        let query = line
            .parse()
            .with_context(|| anyhow!("Failed to parse input as query: {line:?}"))?;
        Ok(query)
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, mut tx: W) -> Result<()> {
        let mut out = format!("{:X} {}", self.fp, self.hash_algo);
        if let Some(prefix) = &self.prefix {
            out.push(' ');
            out.push_str(prefix);
        }
        out.push('\n');
        tx.write_all(out.as_bytes()).await?;
        Ok(())
    }

    /// Switch to the next shard
    pub fn increment(&mut self) -> bool {
        if let Some(prefix) = &mut self.prefix {
            if prefix.ends_with('f') {
                prefix.pop();
                true
            } else if let Some(c) = prefix.pop() {
                let c = match c {
                    '0'..='8' | 'a'..='e' => (c as u8 + 1) as char,
                    '9' => 'a',
                    _ => c,
                };
                prefix.push(c);
                false
            } else {
                // prefix is empty, keyspace has been traversed
                false
            }
        } else {
            debug!("Peers are already in sync, nothing to do here");
            self.prefix = Some(String::new());
            false
        }
    }

    /// Traverse into the first entry in this shard
    pub fn enter(&mut self) {
        if let Some(prefix) = &mut self.prefix {
            prefix.push('0');
        } else {
            self.prefix = Some("0".to_string());
        }
    }
}

impl fmt::Display for Query {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        let prefix = self.prefix.as_deref().unwrap_or("");
        write!(w, "{:X}/{}:{}", self.fp, self.hash_algo, prefix)?;
        Ok(())
    }
}

impl FromStr for Query {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut s = s.split(' ');
        let fp = Fingerprint::from_str(s.next().context("Missing fingerprint")?)
            .context("Invalid fingerprint")?;

        let hash_algo = s.next().context("Missing hash algo")?;
        if hash_algo != "sha256" {
            bail!("Only sha256 is supported at the moment");
        }

        let prefix = s.next().map(String::from);

        if let Some(garbage) = s.next() {
            bail!("Detected trailing data, rejecting as invalid: {garbage:?}");
        }

        Ok(Query {
            fp,
            hash_algo: hash_algo.to_string(),
            prefix,
        })
    }
}

#[derive(Debug)]
pub struct Response {
    pub index: String,
    pub count: usize,
}

impl Response {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let line = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        let line = str::from_utf8(line).context("Response contains invalid utf8")?;
        let response = line
            .parse()
            .with_context(|| anyhow!("Failed to parse input as response: {line:?}"))?;
        Ok(response)
    }
}

impl FromStr for Response {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut s = s.split(' ');
        let index = s.next().context("Missing index from response")?;
        let count = s.next().context("Failed to get number of children")?;
        let count = count
            .parse()
            .context("Number of children is not a number")?;

        Ok(Response {
            index: index.to_string(),
            count,
        })
    }
}

pub fn index_from_scan(db: &Database, query: &Query) -> Result<(String, usize)> {
    let prefix = query.to_string();

    let mut counter = 0;
    let mut hasher = Sha256::new();
    for item in db.scan_prefix(prefix.as_bytes()) {
        let (hash, _data) = item.context("Failed to read from database")?;
        hasher.update(&hash);
        hasher.update(b"\n");
        counter += 1;
    }

    let result = hasher.finalize();
    Ok((format!("sha256:{result:x}"), counter))
}

pub async fn sync_yield<D: DatabaseClient, R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    db: &D,
    rx: R,
    mut tx: W,
    timeout: Option<Duration>,
) -> Result<()> {
    let mut rx = io::BufReader::new(rx);
    loop {
        let mut line = Vec::new();
        let read = rx.read_until(b'\n', &mut line);

        let n = if let Some(timeout) = timeout {
            if let Ok(n) = time::timeout(timeout, read).await {
                n
            } else {
                break;
            }
        } else {
            read.await
        }?;

        if n == 0 {
            break;
        }

        let query = Query::from_bytes(&line)?;
        trace!("Received query: {:?}", query);
        let (index, count) = db.index_from_scan(&query).await?;
        debug!("Calculated index: {index:?}");

        if count > 0 && count <= SPILL_THRESHOLD {
            let prefix = query.to_string();
            debug!("Scanning with prefix: {:?}", prefix);
            for hash in db.scan_keys(prefix.as_bytes()).await? {
                let data = db.get_value(&hash).await?;
                trace!("Sending data packet to client: {:?}", hash);
                tx.write_all(format!(":{:x}\n", data.len()).as_bytes())
                    .await?;
                tx.write_all(&data).await?;
            }
            tx.write_all(b":0\n").await?;
        } else {
            tx.write_all(format!("{index} {count}\n").as_bytes())
                .await?;
        }
    }
    Ok(())
}

pub async fn sync_pull_key<D: DatabaseClient, R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    db: &D,
    keyring: &Keyring,
    fp: &Fingerprint,
    dry_run: bool,
    mut tx: W,
    rx: &mut io::BufReader<R>,
) -> Result<()> {
    let mut query = Query {
        fp: fp.clone(),
        hash_algo: "sha256".to_string(),
        prefix: None,
    };

    while query
        .prefix
        .as_ref()
        .map(|prefix| !prefix.is_empty())
        .unwrap_or(true)
    {
        info!("Requesting index for: {:?}", query.to_string());
        query.write_to(&mut tx).await?;

        let (our_index, _our_count) = db.index_from_scan(&query).await?;
        trace!("Our index: {our_index:?}");

        loop {
            let mut line = Vec::new();
            let n = rx
                .read_until(b'\n', &mut line)
                .await
                .context("Failed to read response")?;
            if n == 0 {
                bail!("Reached unexpected eof while enumerating service");
            }

            if let Some(line) = line.strip_prefix(b":") {
                let line = line.strip_suffix(b"\n").unwrap_or(line);
                let line = str::from_utf8(line).context("Length tag has invalid utf8")?;
                trace!("Received len tag: {:?}", line);
                let len = usize::from_str_radix(line, 16)
                    .with_context(|| anyhow!("Length tag is invalid number: {line:?}"))?;

                if len == 0 {
                    debug!("Received all releases from shard, moving to next one");
                    while query.increment() {
                        info!("Reached last entry in shard, returning to parent");
                    }
                    break;
                }

                // TODO: check this tag doesn't OOM us
                info!("Reading data packet from remote: {len:?} bytes");
                let mut buf = vec![0u8; len];
                rx.read_exact(&mut buf).await?;
                trace!("Finished reading data packet: {:?}", buf.len());

                let mut bytes = &buf[..];
                while !bytes.is_empty() {
                    let (signed, remaining) =
                        Signed::from_bytes(bytes).context("Failed to parse release file")?;

                    for (fp, variant) in signed.canonicalize(Some(keyring))? {
                        let fp = fp.context(
                            "Signature can't be imported because the signature is unverified",
                        )?;
                        if dry_run {
                            debug!("Skipping insert due to dry-run");
                        } else {
                            db.add_release(&fp, &variant).await?;
                        }
                    }

                    bytes = remaining;
                }
            } else {
                let response = Response::from_bytes(&line)?;
                let their_index = response.index;
                let their_count = response.count;
                trace!("Their index: {their_index:?}");

                if their_count == 0 {
                    debug!("No children in this shard, moving to next one");
                    while query.increment() {
                        info!("Reached last entry in shard, returning to parent");
                    }
                } else if their_index == our_index {
                    debug!("These shards are already in sync, moving to next one");
                    while query.increment() {
                        info!("Reached last entry in shard, returning to parent");
                    }
                } else {
                    debug!("Data to be found here, trying to enumerate");
                    query.enter();
                }

                break;
            }
        }
    }

    Ok(())
}

pub async fn sync_pull<D: DatabaseClient, R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    db: &D,
    keyring: &Keyring,
    selected_keys: &[Fingerprint],
    dry_run: bool,
    mut tx: W,
    rx: R,
) -> Result<()> {
    let selected_keys = if !selected_keys.is_empty() {
        Cow::Borrowed(selected_keys)
    } else {
        Cow::Owned(keyring.all_fingerprints())
    };

    let mut rx = io::BufReader::new(rx);
    for fp in selected_keys.iter() {
        sync_pull_key(db, keyring, fp, dry_run, &mut tx, &mut rx).await?;
    }

    Ok(())
}
