use crate::db::{Database, DatabaseClient};
use crate::errors::*;
use crate::keyring::Keyring;
use crate::signed::Signed;
use bstr::BStr;
use futures::StreamExt;
use indexmap::{IndexMap, IndexSet};
use sequoia_openpgp::Fingerprint;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::str;
use std::str::FromStr;
use std::time::Duration;
use tokio::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;
use tokio_socks::tcp::Socks5Stream;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const PROXY_TIMEOUT: Duration = Duration::from_secs(30);

pub const MAX_LINE_LENGTH: u64 = 512;

pub const SYNC_INDEX_TIMEOUT: Duration = Duration::from_secs(120);
pub const SYNC_READ_TIMEOUT: Duration = Duration::from_secs(30);

// We expect entries from 0-f
pub const BATCH_INDEX_MAX_SIZE: usize = 16;

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

#[derive(Debug, Default)]
pub struct BatchIndex {
    index: IndexMap<String, (String, usize)>,
}

impl BatchIndex {
    pub fn new() -> Self {
        BatchIndex::default()
    }

    pub fn add(&mut self, index: String, prefix: String, count: usize) -> Result<()> {
        if self.index.len() < BATCH_INDEX_MAX_SIZE {
            self.index.insert(prefix, (index, count));
            Ok(())
        } else {
            bail!(
                "Batch index is already at max capacity: {:?}",
                self.index.len()
            )
        }
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, mut sink: W) -> Result<()> {
        for (prefix, (index, count)) in &self.index {
            sink.write_all(format!("{index} {prefix} {count}\n").as_bytes())
                .await?;
        }
        Ok(())
    }

    pub fn parse_line(&mut self, line: &[u8]) -> Result<()> {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = str::from_utf8(line).context("Response contains invalid utf8")?;

        let mut s = line.split(' ');
        let index = s.next().context("Missing index from response")?;
        let prefix = s.next().context("Failed to get prefix for index")?;
        let count = s.next().context("Failed to get number of children")?;
        let count = count
            .parse()
            .context("Number of children is not a number")?;

        self.add(index.to_string(), prefix.to_string(), count)
    }

    pub fn get(&self, key: &str) -> Option<&(String, usize)> {
        self.index.get(key)
    }

    pub fn keys(&self) -> indexmap::map::Keys<String, (String, usize)> {
        self.index.keys()
    }

    pub fn clear(&mut self) {
        self.index.clear();
    }
}

pub async fn connect(addr: SocketAddr, proxy: Option<SocketAddr>) -> Result<TcpStream> {
    let target = proxy.unwrap_or(addr);

    debug!("Creating tcp connection to {target:?}");
    let sock = TcpStream::connect(target);
    let mut sock = time::timeout(CONNECT_TIMEOUT, sock)
        .await
        .with_context(|| anyhow!("Connecting to {target:?} timed out"))?
        .with_context(|| anyhow!("Failed to connect to {target:?}"))?;

    if let Some(proxy) = proxy {
        debug!("Requesting socks5 connection to {addr:?}");
        let connect = Socks5Stream::connect_with_socket(sock, addr);

        sock = time::timeout(PROXY_TIMEOUT, connect)
            .await
            .with_context(|| anyhow!("Connecting to {addr:?} (with socks5 {proxy:?}) timed out"))?
            .with_context(|| anyhow!("Failed to connect to {addr:?} (with socks5 {proxy:?})"))?
            .into_inner()
    }

    debug!("Connection has been established");

    Ok(sock)
}

pub async fn index_from_scan(db: &Database, query: &Query) -> Result<(String, usize)> {
    let prefix = query.to_string();

    let mut counter = 0;
    let mut hasher = Sha256::new();

    let stream = db.scan_prefix(prefix.as_bytes());
    tokio::pin!(stream);
    while let Some(item) = stream.next().await {
        let (hash, _data) = item.context("Failed to read from database (index_from_scan)")?;
        hasher.update(&hash);
        hasher.update(b"\n");
        counter += 1;
    }

    let result = hasher.finalize();
    Ok((format!("sha256:{result:x}"), counter))
}

pub async fn sync_yield<
    D: DatabaseClient + Sync + Send,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
>(
    db: &mut D,
    rx: R,
    mut tx: W,
    timeout: Option<Duration>,
) -> Result<()> {
    let mut rx = io::BufReader::new(rx);
    loop {
        let mut line = Vec::new();
        let mut rrx = (&mut rx).take(MAX_LINE_LENGTH);
        let read = rrx.read_until(b'\n', &mut line);

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

        if !line.ends_with(b"\n") {
            bail!(
                "Client sent invalid request, exceeding size limit: {:?}",
                BStr::new(&line)
            );
        }

        let mut query = Query::from_bytes(&line)?;
        trace!("Received query: {:?}", query);

        let (index, total) = db.batch_index_from_scan(&mut query).await?;

        if total > 0 && total <= SPILL_THRESHOLD {
            let prefix = query.to_string();
            debug!("Scanning with prefix: {prefix:?}");
            for hash in db.scan_keys(prefix.as_bytes()).await? {
                let data = db.get_value(&hash).await?;
                trace!("Sending data packet to client: {:?}", hash);
                tx.write_all(format!(":{:x}\n", data.len()).as_bytes())
                    .await?;
                tx.write_all(&data).await?;
            }
            tx.write_all(b":0\n").await?;
        } else {
            index.write_to(&mut tx).await?;
            tx.write_all(b"\n").await?;
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct SyncQueue {
    queues: BTreeMap<usize, VecDeque<Option<String>>>,
}

impl SyncQueue {
    pub fn push(&mut self, key: Option<String>) {
        let len = key.as_ref().map(|s| s.len()).unwrap_or(0);
        let queue = self.queues.entry(len).or_default();
        queue.push_back(key);
    }

    pub fn pop_next(&mut self) -> Option<Option<String>> {
        loop {
            if let Some(mut entry) = self.queues.last_entry() {
                let queue = entry.get_mut();
                if let Some(item) = queue.pop_front() {
                    return Some(item);
                } else {
                    entry.remove_entry();
                }
            } else {
                return None;
            }
        }
    }
}

pub async fn sync_pull_key<
    D: DatabaseClient + Sync + Send,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
>(
    db: &mut D,
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

    let mut queue = SyncQueue::default();
    queue.push(None);

    while let Some(item) = queue.pop_next() {
        query.prefix = item;
        info!("Requesting index for: {:?}", query.to_string());
        query.write_to(&mut tx).await?;

        let (our_index, _our_count) = db.batch_index_from_scan(&mut query).await?;
        trace!("Our index: {our_index:?}");

        let mut line = Vec::new();
        let mut their_index = BatchIndex::new();

        loop {
            line.clear();

            let mut rrx = rx.take(MAX_LINE_LENGTH);
            let read = rrx.read_until(b'\n', &mut line);
            let n = time::timeout(SYNC_INDEX_TIMEOUT, read)
                .await
                .context("Request for index timed out")?
                .context("Failed to receive response from peer")?;

            if n == 0 {
                bail!("Reached unexpected eof while enumerating service");
            }

            if !line.ends_with(b"\n") {
                bail!(
                    "Server sent invalid line, exceeding size limit: {:?}",
                    BStr::new(&line)
                );
            }

            if line == b"\n" {
                let keys = their_index
                    .keys()
                    .chain(our_index.keys())
                    .collect::<IndexSet<_>>();

                for key in keys {
                    match (their_index.get(key), our_index.get(key)) {
                        (Some(theirs), Some(ours)) => {
                            trace!("Comparing index shards for key={key:?}, theirs={theirs:?}, ours={ours:?}");

                            if theirs.1 == 0 {
                                trace!(
                                    "No children in this shard (key={key:?}), moving to next one"
                                );
                            } else if theirs == ours {
                                trace!("These shards are already in sync (key={key:?}), moving to next one");
                            } else {
                                trace!("Data to be found here (key={key:?}), trying to enumerate");
                                queue.push(Some(key.to_owned()));
                            }
                        }
                        _ => bail!("Some index shards are omitted, this is currently unsupported"),
                    }
                }

                their_index.clear();
                break;
            } else if let Some(line) = line.strip_prefix(b":") {
                let line = line.strip_suffix(b"\n").unwrap_or(line);
                let line = str::from_utf8(line).context("Length tag has invalid utf8")?;
                trace!("Received len tag: {:?}", line);
                let len = usize::from_str_radix(line, 16)
                    .with_context(|| anyhow!("Length tag is invalid number: {line:?}"))?;

                if len == 0 {
                    trace!("Received all releases from shard, moving to next one");
                    while query.increment() {
                        trace!("Reached last entry in shard, returning to parent");
                    }
                    break;
                }

                // TODO: check this tag doesn't OOM us
                info!("Reading data packet from remote: {len:?} bytes");

                let mut remaining = len;
                let mut buf = vec![0u8; len];
                while remaining > 0 {
                    let read = rx.read(&mut buf[len - remaining..]);

                    let n = time::timeout(SYNC_READ_TIMEOUT, read)
                        .await
                        .context("Read from remote timed out")?
                        .context("Failed to receive data from peer")?;

                    if n == 0 {
                        bail!("Unexpected end of file");
                    }

                    remaining -= n;
                    trace!("Read {}/{} bytes from remote", len - remaining, len);
                }
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
                their_index
                    .parse_line(&line)
                    .with_context(|| anyhow!("Failed to parse line of batch index: {line:?}"))?;
            }
        }
    }
    db.flush().await.context("Failed to flush database")?;

    Ok(())
}

pub async fn sync_pull<
    D: DatabaseClient + Sync + Send,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
>(
    db: &mut D,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::AccessMode;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    async fn open_temp_dbs() -> Result<(tempfile::TempDir, Database, Database)> {
        let dir = tempfile::tempdir()?;
        let db_a = Database::open_at(dir.path().join("a"), AccessMode::Exclusive).await?;
        let db_b = Database::open_at(dir.path().join("b"), AccessMode::Exclusive).await?;
        Ok((dir, db_a, db_b))
    }

    async fn run_sync(keyring: &Keyring, db_a: &mut Database, db_b: &mut Database) -> Result<()> {
        let (client, server) = tokio::io::duplex(64);
        let (client_rx, client_tx) = tokio::io::split(client);
        let (server_rx, server_tx) = tokio::io::split(server);
        let task_yield = sync_yield(db_a, server_rx, server_tx, None);
        let task_pull = sync_pull(db_b, keyring, &[], false, client_tx, client_rx);

        tokio::select! {
            ret = task_pull => ret?,
            ret = task_yield => bail!("Yield task was not expected to return: {ret:?}"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_sync_both_empty() -> Result<()> {
        init();

        let keyring = Keyring::new(include_bytes!("../contrib/signal-desktop-keyring.gpg"))?;
        let (_, mut db_a, mut db_b) = open_temp_dbs().await?;
        run_sync(&keyring, &mut db_a, &mut db_b).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_sync_full() -> Result<()> {
        init();

        let keyring = Keyring::new(include_bytes!("../contrib/signal-desktop-keyring.gpg"))?;
        let (_, mut db_a, mut db_b) = open_temp_dbs().await?;

        let data = [
        b"-----BEGIN PGP SIGNED MESSAGE-----

Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Thu, 23 Feb 2023 01:55:04 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 cdb20787f1556bb38ae3b6017ef51327   132984 main/binary-amd64/Packages
 001fc41d6c21eb85a43a13133584cbae    21567 main/binary-amd64/Packages.gz
 3fb4f1a0169c3b2fff2c43c2a2277b51    17923 main/binary-amd64/Packages.bz2
 c911b1bc4adf556f6fbd17c0c9cd8315     4794 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
SHA1:
 455673b692a697ad3ada91a875096365f8da1524   132984 main/binary-amd64/Packages
 e6a940039dcfc7f93f4a5501f15e75d1427b9464    21567 main/binary-amd64/Packages.gz
 b8447294816bb063c10d0ba35f48dd5d1980f795    17923 main/binary-amd64/Packages.bz2
 b6fd643edc8846c0914b44f3182dfc086877d944     4794 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
SHA256:
 989c22244106e44d789400d4da33d2ed64228ce94f48d1c2c37493118c992384   132984 main/binary-amd64/Packages
 c46198172d00d4e01388832b61186a888da47e2c119c1e9dd7378fea206b1237    21567 main/binary-amd64/Packages.gz
 b368e24d5c137448095f8940e3b371bff83e3e56159df6c58d4be83732a85554    17923 main/binary-amd64/Packages.bz2
 bb347cbc00e02d73fef513965f1cd9f9e73100cd34097c43fdd1414668ec8ed8     4794 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
-----BEGIN PGP SIGNATURE-----

wsFcBAEBCAAGBQJj9sd6AAoJENmAoXRX9vsGOQ0P/3S63ctKl7QyxmRQ4UVJl70S
hTxA90FbWp236nrEWw4EO/eVWiR/VbgFPacp/dyBpSmtTFl5cpOeyf2SYj5qfg5L
cemYgUbaxRl+PBFGm7A14y82Ym0MUzF9cNWVK8bDXH9BKSljKKerXr4giOwjTkgh
z2LoLxnrbhGkIWnSNiT0YvQrkxkSC5BjOInRiy/4Dr7LFAX/7KBzyPVwiDPxWQca
dwtmI6EoZQP+zHDTR6RwnYOB7oME8aYIruwF9Vhu/unfdC4LpbNJDGL7VwQKUp8h
ICupSwnRmHPV2raNBq58K6OunGvFO0oFaYUIQqbvGzu/5859YWhrdd7gBd9Fj4zI
Ff7fHC+ZigCNCk7op4LykJ/3uJF8NvFlNxiagO+1tRko3V4tNbeSrXEKDhr5RQJz
p/VdL1TXI/pVIobxbF5D/Lo8dCs5LjJsJ5rFlPgzjlREFn0hwKcDwB7M+rbPhuHV
1R3lgdhW01ZghwOdTMiX1cShQwE7bvGtskn2WIHyIhEawpotGNpBFG2K5TdxfXA1
m+wu4PLxfxOSb+VoQlH1enyDcR7m7XNtt692l++6nw3rq6Wv2zNc9DHRE+HNavJg
zwlfH3L9OOoGfPMfRxrKqFzcob2gnKjptlHt3XpUx5ZwS4hcKB2lETT9ORVxe1NI
rK5KKL67o5aLviVqo98l
=MI63
-----END PGP SIGNATURE-----
",
b"-----BEGIN PGP SIGNED MESSAGE-----

Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Wed, 15 Feb 2023 23:18:08 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 bea5a0f7c99209504f22d8faf10125fd   132287 main/binary-amd64/Packages
 1aa4c130945a3a076a9f16546ca17a83    21467 main/binary-amd64/Packages.gz
 f18c7f0779161104fed2aec72d9a44e2    17922 main/binary-amd64/Packages.bz2
 fdb168fb0b8f575585d917ca0ffd98bb     4783 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
SHA1:
 d01c164d99cf7c867b5f115770f58e4916d7a15f   132287 main/binary-amd64/Packages
 41e78c4c558567f4936d9952eb928a32911cc56c    21467 main/binary-amd64/Packages.gz
 8837bf2f3e2bad7c73712d003c1510c6171c53ee    17922 main/binary-amd64/Packages.bz2
 e800a4c83e8d9ef564f5869ad838962550799c5e     4783 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
SHA256:
 9f9178b66c4d1d31d7b2b741f0835c2140552cac68861beaf2ecc55f0364c620   132287 main/binary-amd64/Packages
 57386742060a0913236bafd5e8eb3b3334284e0d2ab8362a7c22c78175e9d89b    21467 main/binary-amd64/Packages.gz
 ec097b64b5e3a39760a9b5ea6b02e91d0401994464dd0ce3de2a0a26a62230e2    17922 main/binary-amd64/Packages.bz2
 e04d5fd71915c3003d55f3927e5af71a4831e30ffbb0efec6dceb36cd1b054fa     4783 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
-----BEGIN PGP SIGNATURE-----

wsFcBAABCAAGBQJj7WgwAAoJENmAoXRX9vsG69AQAJmvducnhHqCXQIsqjXrDMjU
QUAw56MRunn7rHTFpJY0ZPLgQ5gVBibouNZ9x78wuJ784Sl+MIHC7RWdQYBEbWQ5
haKjiI00BzDeXx4sUet1E+Ce5dhjK/UvoZIOy+ed5nv/HM7QFrvoxdADSDnYGy2o
djFUVWR5kzkb5Tv7bcjJQWWf6JvY1Z12CgsG85ECYv2PE+tGgQjSwbxRDvFFzY1O
Xy1EkjT+YDG6hy5CiKSZL7qPsjsLHeuRvat3oSlBWiFRnSuLOlsDozqzYMFqNx93
GPQiFNiYEmkxDxiKLOcds7+Plz2FjQdQwv2msllJ4jA9PxYRiEbfH14/ELk+/snE
66XID9dv91JbrwaI3NOoJZZmN+QYZ7WaAj3Uxl3cYnCGuIIt6z4KB2CYeyRa3f3K
HbPq0mBchPPmavaQEfaNDQ+dzMuazR0VMoKfHGEp44r+XU+JH/lNzlxgQEMgVv43
0B++zb4MYgheGUhu7Xdgd6XSQdZGxt4GieXLwIAXA0nmAFlZB7EAJcyHqz0hVo6m
Q/m8Ja8hBw6lmyM5uCduF61BhnQDfuDQetLgGzrvOp3m2qfTag3QGtEijwhH8L2O
3xuMqMjtJutTa557go0p+PLjAhMVQ0S7z+3aLn/368qnqlxSflDCPe4GMcaXmOCz
RdMJMk9txqB8GM5F2sO3
=gtrA
-----END PGP SIGNATURE-----
",
b"-----BEGIN PGP SIGNED MESSAGE-----

Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Fri, 10 Feb 2023 21:24:49 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 1044a9316b629fb7ea4b964ecaf1ccf3    21255 main/binary-amd64/Packages.gz
 6ee4dcbdb0c0e98e416b94f542f6cc1b    17584 main/binary-amd64/Packages.bz2
 fdb168fb0b8f575585d917ca0ffd98bb     4783 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
 b2f1f73fabd4acfaca43d05bee1debca   130864 main/binary-amd64/Packages
SHA1:
 1bcb7cd08c94a3519b2dce77f3f5f5e16c312067    21255 main/binary-amd64/Packages.gz
 61c0f6b35c7bd3a5f59094511ccd593dcb2b8c96    17584 main/binary-amd64/Packages.bz2
 e800a4c83e8d9ef564f5869ad838962550799c5e     4783 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
 4a7c86cb1c0caa36c92e1af844ebf0b7e2bf4cea   130864 main/binary-amd64/Packages
SHA256:
 481c1bf74f609fbf71eed01da98a05cbe884acc2efd6d0e2c1c65f9e72ddc2e6    21255 main/binary-amd64/Packages.gz
 d9f8cc2cc5b2aa854c509caf96d9e1457e6cb0fd55597ac49408a96afb8a727b    17584 main/binary-amd64/Packages.bz2
 e04d5fd71915c3003d55f3927e5af71a4831e30ffbb0efec6dceb36cd1b054fa     4783 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
 d0bec4d8f926383f3d61dc79b8d5d352f71adcf8befb59e8e02aeabe8c19eeba   130864 main/binary-amd64/Packages
-----BEGIN PGP SIGNATURE-----

wsFcBAEBCAAGBQJj5rYjAAoJENmAoXRX9vsG3wUP/2X7ufCo5nJkyHhzOtTEI4Pq
rz6P94r2S/OA7v99mVkKNyOYZ8hKMNccYumvkWaXBF+WkLemCPeJxaBbRUrulu3c
GXNPHht8dusQYIxS2VQVYbHgXfwQ+Y3+P1wVLPNT+9Ka0POkUT4YiM1G8Zx3fwTq
zUeCpV1TKgkrVQ4CF5DX8i9tcVmYUq8B+BouwQAFJxElM1cuYqGybG19H/od77nH
tkv3n43P0TCZ9KR48ZXWXF+6v26SRse2YkergbNOtJwRfdMHzvc8d/nb7T/Iv3jM
WmqUs6Ob4EioUTWYwi2H3y+LnzAPeSVEklfCS61LzlyFGelpxHGuTjaaMtCI2Bkb
f3XyNjeVwUYmnGWrBMCI38CUnY0J0oXLrVUxYZoT0O9SSO2bpql64T2Flqn10Djk
W8j7V9a5gNO69PkNEHWUylwolFvF/H8Zmc6QZbnnbFSpC4pMEeRhoI1v1CqPSMn8
APOGWa1xHN9hj9g4AZfXvO56BDveo9lbNOmFs2EAmBEEj2hCiroRtuCxxDmwerq3
MLtCJIkir3JdbefexXcbIoP5+tjl573nvKU+Kb4KhCJTBDEY6+6qZKTSBDESKTvq
T2L60YwfXZsj6WCS9roTz9llmze3YjURbHNZpf4BO3zONwNNeqFZw3qYWNCyzRS+
R4AjBHbzlyIGpU5BGNn3
=KMXz
-----END PGP SIGNATURE-----
"
];
        for data in data {
            let (signed, _) = Signed::from_bytes(data)?;
            db_a.add_release(
                &"DBA36B5181D0C816F630E889D980A17457F6FB06".parse()?,
                &signed,
            )
            .await?;
        }

        let keys_a = db_a.scan_keys(b"").await?;
        let keys_b = db_b.scan_keys(b"").await?;
        assert_eq!(keys_a.len(), 3);
        assert_eq!(keys_b.len(), 0);

        run_sync(&keyring, &mut db_a, &mut db_b).await?;

        let keys_a = db_a.scan_keys(b"").await?;
        let keys_b = db_b.scan_keys(b"").await?;
        assert_eq!(keys_a.len(), 3);
        assert_eq!(keys_b.len(), 3);

        Ok(())
    }

    #[tokio::test]
    async fn test_sync_from_partial() -> Result<()> {
        init();

        let keyring = Keyring::new(include_bytes!("../contrib/signal-desktop-keyring.gpg"))?;
        let (_, mut db_a, mut db_b) = open_temp_dbs().await?;

        let data = [
        b"-----BEGIN PGP SIGNED MESSAGE-----

Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Thu, 23 Feb 2023 01:55:04 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 cdb20787f1556bb38ae3b6017ef51327   132984 main/binary-amd64/Packages
 001fc41d6c21eb85a43a13133584cbae    21567 main/binary-amd64/Packages.gz
 3fb4f1a0169c3b2fff2c43c2a2277b51    17923 main/binary-amd64/Packages.bz2
 c911b1bc4adf556f6fbd17c0c9cd8315     4794 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
SHA1:
 455673b692a697ad3ada91a875096365f8da1524   132984 main/binary-amd64/Packages
 e6a940039dcfc7f93f4a5501f15e75d1427b9464    21567 main/binary-amd64/Packages.gz
 b8447294816bb063c10d0ba35f48dd5d1980f795    17923 main/binary-amd64/Packages.bz2
 b6fd643edc8846c0914b44f3182dfc086877d944     4794 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
SHA256:
 989c22244106e44d789400d4da33d2ed64228ce94f48d1c2c37493118c992384   132984 main/binary-amd64/Packages
 c46198172d00d4e01388832b61186a888da47e2c119c1e9dd7378fea206b1237    21567 main/binary-amd64/Packages.gz
 b368e24d5c137448095f8940e3b371bff83e3e56159df6c58d4be83732a85554    17923 main/binary-amd64/Packages.bz2
 bb347cbc00e02d73fef513965f1cd9f9e73100cd34097c43fdd1414668ec8ed8     4794 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
-----BEGIN PGP SIGNATURE-----

wsFcBAEBCAAGBQJj9sd6AAoJENmAoXRX9vsGOQ0P/3S63ctKl7QyxmRQ4UVJl70S
hTxA90FbWp236nrEWw4EO/eVWiR/VbgFPacp/dyBpSmtTFl5cpOeyf2SYj5qfg5L
cemYgUbaxRl+PBFGm7A14y82Ym0MUzF9cNWVK8bDXH9BKSljKKerXr4giOwjTkgh
z2LoLxnrbhGkIWnSNiT0YvQrkxkSC5BjOInRiy/4Dr7LFAX/7KBzyPVwiDPxWQca
dwtmI6EoZQP+zHDTR6RwnYOB7oME8aYIruwF9Vhu/unfdC4LpbNJDGL7VwQKUp8h
ICupSwnRmHPV2raNBq58K6OunGvFO0oFaYUIQqbvGzu/5859YWhrdd7gBd9Fj4zI
Ff7fHC+ZigCNCk7op4LykJ/3uJF8NvFlNxiagO+1tRko3V4tNbeSrXEKDhr5RQJz
p/VdL1TXI/pVIobxbF5D/Lo8dCs5LjJsJ5rFlPgzjlREFn0hwKcDwB7M+rbPhuHV
1R3lgdhW01ZghwOdTMiX1cShQwE7bvGtskn2WIHyIhEawpotGNpBFG2K5TdxfXA1
m+wu4PLxfxOSb+VoQlH1enyDcR7m7XNtt692l++6nw3rq6Wv2zNc9DHRE+HNavJg
zwlfH3L9OOoGfPMfRxrKqFzcob2gnKjptlHt3XpUx5ZwS4hcKB2lETT9ORVxe1NI
rK5KKL67o5aLviVqo98l
=MI63
-----END PGP SIGNATURE-----
",
b"-----BEGIN PGP SIGNED MESSAGE-----

Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Wed, 15 Feb 2023 23:18:08 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 bea5a0f7c99209504f22d8faf10125fd   132287 main/binary-amd64/Packages
 1aa4c130945a3a076a9f16546ca17a83    21467 main/binary-amd64/Packages.gz
 f18c7f0779161104fed2aec72d9a44e2    17922 main/binary-amd64/Packages.bz2
 fdb168fb0b8f575585d917ca0ffd98bb     4783 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
SHA1:
 d01c164d99cf7c867b5f115770f58e4916d7a15f   132287 main/binary-amd64/Packages
 41e78c4c558567f4936d9952eb928a32911cc56c    21467 main/binary-amd64/Packages.gz
 8837bf2f3e2bad7c73712d003c1510c6171c53ee    17922 main/binary-amd64/Packages.bz2
 e800a4c83e8d9ef564f5869ad838962550799c5e     4783 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
SHA256:
 9f9178b66c4d1d31d7b2b741f0835c2140552cac68861beaf2ecc55f0364c620   132287 main/binary-amd64/Packages
 57386742060a0913236bafd5e8eb3b3334284e0d2ab8362a7c22c78175e9d89b    21467 main/binary-amd64/Packages.gz
 ec097b64b5e3a39760a9b5ea6b02e91d0401994464dd0ce3de2a0a26a62230e2    17922 main/binary-amd64/Packages.bz2
 e04d5fd71915c3003d55f3927e5af71a4831e30ffbb0efec6dceb36cd1b054fa     4783 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
-----BEGIN PGP SIGNATURE-----

wsFcBAABCAAGBQJj7WgwAAoJENmAoXRX9vsG69AQAJmvducnhHqCXQIsqjXrDMjU
QUAw56MRunn7rHTFpJY0ZPLgQ5gVBibouNZ9x78wuJ784Sl+MIHC7RWdQYBEbWQ5
haKjiI00BzDeXx4sUet1E+Ce5dhjK/UvoZIOy+ed5nv/HM7QFrvoxdADSDnYGy2o
djFUVWR5kzkb5Tv7bcjJQWWf6JvY1Z12CgsG85ECYv2PE+tGgQjSwbxRDvFFzY1O
Xy1EkjT+YDG6hy5CiKSZL7qPsjsLHeuRvat3oSlBWiFRnSuLOlsDozqzYMFqNx93
GPQiFNiYEmkxDxiKLOcds7+Plz2FjQdQwv2msllJ4jA9PxYRiEbfH14/ELk+/snE
66XID9dv91JbrwaI3NOoJZZmN+QYZ7WaAj3Uxl3cYnCGuIIt6z4KB2CYeyRa3f3K
HbPq0mBchPPmavaQEfaNDQ+dzMuazR0VMoKfHGEp44r+XU+JH/lNzlxgQEMgVv43
0B++zb4MYgheGUhu7Xdgd6XSQdZGxt4GieXLwIAXA0nmAFlZB7EAJcyHqz0hVo6m
Q/m8Ja8hBw6lmyM5uCduF61BhnQDfuDQetLgGzrvOp3m2qfTag3QGtEijwhH8L2O
3xuMqMjtJutTa557go0p+PLjAhMVQ0S7z+3aLn/368qnqlxSflDCPe4GMcaXmOCz
RdMJMk9txqB8GM5F2sO3
=gtrA
-----END PGP SIGNATURE-----
",
b"-----BEGIN PGP SIGNED MESSAGE-----

Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Fri, 10 Feb 2023 21:24:49 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 1044a9316b629fb7ea4b964ecaf1ccf3    21255 main/binary-amd64/Packages.gz
 6ee4dcbdb0c0e98e416b94f542f6cc1b    17584 main/binary-amd64/Packages.bz2
 fdb168fb0b8f575585d917ca0ffd98bb     4783 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
 b2f1f73fabd4acfaca43d05bee1debca   130864 main/binary-amd64/Packages
SHA1:
 1bcb7cd08c94a3519b2dce77f3f5f5e16c312067    21255 main/binary-amd64/Packages.gz
 61c0f6b35c7bd3a5f59094511ccd593dcb2b8c96    17584 main/binary-amd64/Packages.bz2
 e800a4c83e8d9ef564f5869ad838962550799c5e     4783 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
 4a7c86cb1c0caa36c92e1af844ebf0b7e2bf4cea   130864 main/binary-amd64/Packages
SHA256:
 481c1bf74f609fbf71eed01da98a05cbe884acc2efd6d0e2c1c65f9e72ddc2e6    21255 main/binary-amd64/Packages.gz
 d9f8cc2cc5b2aa854c509caf96d9e1457e6cb0fd55597ac49408a96afb8a727b    17584 main/binary-amd64/Packages.bz2
 e04d5fd71915c3003d55f3927e5af71a4831e30ffbb0efec6dceb36cd1b054fa     4783 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
 d0bec4d8f926383f3d61dc79b8d5d352f71adcf8befb59e8e02aeabe8c19eeba   130864 main/binary-amd64/Packages
-----BEGIN PGP SIGNATURE-----

wsFcBAEBCAAGBQJj5rYjAAoJENmAoXRX9vsG3wUP/2X7ufCo5nJkyHhzOtTEI4Pq
rz6P94r2S/OA7v99mVkKNyOYZ8hKMNccYumvkWaXBF+WkLemCPeJxaBbRUrulu3c
GXNPHht8dusQYIxS2VQVYbHgXfwQ+Y3+P1wVLPNT+9Ka0POkUT4YiM1G8Zx3fwTq
zUeCpV1TKgkrVQ4CF5DX8i9tcVmYUq8B+BouwQAFJxElM1cuYqGybG19H/od77nH
tkv3n43P0TCZ9KR48ZXWXF+6v26SRse2YkergbNOtJwRfdMHzvc8d/nb7T/Iv3jM
WmqUs6Ob4EioUTWYwi2H3y+LnzAPeSVEklfCS61LzlyFGelpxHGuTjaaMtCI2Bkb
f3XyNjeVwUYmnGWrBMCI38CUnY0J0oXLrVUxYZoT0O9SSO2bpql64T2Flqn10Djk
W8j7V9a5gNO69PkNEHWUylwolFvF/H8Zmc6QZbnnbFSpC4pMEeRhoI1v1CqPSMn8
APOGWa1xHN9hj9g4AZfXvO56BDveo9lbNOmFs2EAmBEEj2hCiroRtuCxxDmwerq3
MLtCJIkir3JdbefexXcbIoP5+tjl573nvKU+Kb4KhCJTBDEY6+6qZKTSBDESKTvq
T2L60YwfXZsj6WCS9roTz9llmze3YjURbHNZpf4BO3zONwNNeqFZw3qYWNCyzRS+
R4AjBHbzlyIGpU5BGNn3
=KMXz
-----END PGP SIGNATURE-----
"
];
        for data in data {
            let (signed, _) = Signed::from_bytes(data)?;
            db_a.add_release(
                &"DBA36B5181D0C816F630E889D980A17457F6FB06".parse()?,
                &signed,
            )
            .await?;
        }

        let (signed, _) = Signed::from_bytes(b"-----BEGIN PGP SIGNED MESSAGE-----

Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Wed, 15 Feb 2023 23:18:08 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 bea5a0f7c99209504f22d8faf10125fd   132287 main/binary-amd64/Packages
 1aa4c130945a3a076a9f16546ca17a83    21467 main/binary-amd64/Packages.gz
 f18c7f0779161104fed2aec72d9a44e2    17922 main/binary-amd64/Packages.bz2
 fdb168fb0b8f575585d917ca0ffd98bb     4783 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
SHA1:
 d01c164d99cf7c867b5f115770f58e4916d7a15f   132287 main/binary-amd64/Packages
 41e78c4c558567f4936d9952eb928a32911cc56c    21467 main/binary-amd64/Packages.gz
 8837bf2f3e2bad7c73712d003c1510c6171c53ee    17922 main/binary-amd64/Packages.bz2
 e800a4c83e8d9ef564f5869ad838962550799c5e     4783 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
SHA256:
 9f9178b66c4d1d31d7b2b741f0835c2140552cac68861beaf2ecc55f0364c620   132287 main/binary-amd64/Packages
 57386742060a0913236bafd5e8eb3b3334284e0d2ab8362a7c22c78175e9d89b    21467 main/binary-amd64/Packages.gz
 ec097b64b5e3a39760a9b5ea6b02e91d0401994464dd0ce3de2a0a26a62230e2    17922 main/binary-amd64/Packages.bz2
 e04d5fd71915c3003d55f3927e5af71a4831e30ffbb0efec6dceb36cd1b054fa     4783 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
-----BEGIN PGP SIGNATURE-----

wsFcBAABCAAGBQJj7WgwAAoJENmAoXRX9vsG69AQAJmvducnhHqCXQIsqjXrDMjU
QUAw56MRunn7rHTFpJY0ZPLgQ5gVBibouNZ9x78wuJ784Sl+MIHC7RWdQYBEbWQ5
haKjiI00BzDeXx4sUet1E+Ce5dhjK/UvoZIOy+ed5nv/HM7QFrvoxdADSDnYGy2o
djFUVWR5kzkb5Tv7bcjJQWWf6JvY1Z12CgsG85ECYv2PE+tGgQjSwbxRDvFFzY1O
Xy1EkjT+YDG6hy5CiKSZL7qPsjsLHeuRvat3oSlBWiFRnSuLOlsDozqzYMFqNx93
GPQiFNiYEmkxDxiKLOcds7+Plz2FjQdQwv2msllJ4jA9PxYRiEbfH14/ELk+/snE
66XID9dv91JbrwaI3NOoJZZmN+QYZ7WaAj3Uxl3cYnCGuIIt6z4KB2CYeyRa3f3K
HbPq0mBchPPmavaQEfaNDQ+dzMuazR0VMoKfHGEp44r+XU+JH/lNzlxgQEMgVv43
0B++zb4MYgheGUhu7Xdgd6XSQdZGxt4GieXLwIAXA0nmAFlZB7EAJcyHqz0hVo6m
Q/m8Ja8hBw6lmyM5uCduF61BhnQDfuDQetLgGzrvOp3m2qfTag3QGtEijwhH8L2O
3xuMqMjtJutTa557go0p+PLjAhMVQ0S7z+3aLn/368qnqlxSflDCPe4GMcaXmOCz
RdMJMk9txqB8GM5F2sO3
=gtrA
-----END PGP SIGNATURE-----
")?;

        db_b.add_release(
            &"DBA36B5181D0C816F630E889D980A17457F6FB06".parse()?,
            &signed,
        )
        .await?;

        let keys_a = db_a.scan_keys(b"").await?;
        let keys_b = db_b.scan_keys(b"").await?;
        assert_eq!(keys_a.len(), 3);
        assert_eq!(keys_b.len(), 1);

        run_sync(&keyring, &mut db_a, &mut db_b).await?;

        let keys_a = db_a.scan_keys(b"").await?;
        let keys_b = db_b.scan_keys(b"").await?;
        assert_eq!(keys_a.len(), 3);
        assert_eq!(keys_b.len(), 3);

        Ok(())
    }
}
