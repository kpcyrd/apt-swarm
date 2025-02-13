#[cfg(feature = "git")]
pub mod git;
pub mod update;

use crate::args::{FileOrStdin, Plumbing};
use crate::config::Config;
#[cfg(unix)]
use crate::db::channel::DatabaseServer;
use crate::db::header::CryptoHash;
use crate::db::{AccessMode, Database, DatabaseClient};
use crate::errors::*;
use crate::keyring::Keyring;
use crate::p2p;
use crate::pgp;
use crate::signed::Signed;
use crate::sync;
use bstr::{BStr, BString};
use colored::Colorize;
use futures::StreamExt;
use std::borrow::Cow;
use std::sync::LazyLock;
use tokio::fs;
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

static FSCK_OK: LazyLock<String> = LazyLock::new(|| " OK\n".bold().green().to_string());
static FSCK_ERR: LazyLock<String> = LazyLock::new(|| " ERR\n".bold().red().to_string());

async fn fsck_doc(hash: &[u8], data: &[u8], keyring: Option<&Keyring>) -> Result<()> {
    let signed = Signed::from_reader(&mut &data[..])
        .await
        .context("Failed to parse release file")?;

    let canonicalized = signed.canonicalize(keyring)?;
    let mut canonicalized = canonicalized.into_iter();
    match canonicalized.next() {
        Some((Some(fp), variant)) => {
            let keyspace = format!("{fp:X}/");
            let Some(hash) = hash.strip_prefix(keyspace.as_bytes()) else {
                bail!(
                    "Signature is stored in incorrect fingerprint keyspace, expected: {keyspace}"
                );
            };
            let normalized = variant.to_clear_signed()?;
            if normalized != data {
                bail!("Data is not correctly canonicalized, byte mismatch");
            }

            let verified = CryptoHash::calculate(&normalized);
            if verified.as_str().as_bytes() != hash {
                bail!("Incorrect sha256, calculated: {:?}", verified.as_str());
            }
        }
        Some((None, _variant)) => {
            bail!("Signature can't be validated because the key is not in keyring");
        }
        None => {
            bail!("Could not find any signature packet");
        }
    }

    if let Some(_trailing) = canonicalized.next() {
        bail!("Document is not fully canonicalized, has multiple signatures");
    }

    Ok(())
}

pub async fn run(config: Result<Config>, args: Plumbing, quiet: u8) -> Result<()> {
    match args {
        Plumbing::Canonicalize(mut canonicalize) => {
            FileOrStdin::default_stdin(&mut canonicalize.paths);

            let keyring = if canonicalize.verify {
                let config = config?;
                Some(Keyring::load(&config)?)
            } else {
                None
            };

            let mut stdout = io::stdout();
            for path in canonicalize.paths {
                let reader = path.open().await?;
                let mut reader = io::BufReader::new(reader);

                while !reader.fill_buf().await?.is_empty() {
                    let signed = Signed::from_reader(&mut reader)
                        .await
                        .context("Failed to parse release file")?;

                    for (_fp, variant) in signed.canonicalize(keyring.as_ref())? {
                        let text = variant.to_clear_signed()?;
                        stdout.write_all(&text).await?;
                    }
                }
            }
        }
        Plumbing::Fingerprint(_fingerprint) => {
            let mut buf = Vec::new();

            let mut stdin = io::stdin();
            stdin.read_to_end(&mut buf).await?;

            pgp::load(&buf)?;
        }
        Plumbing::Paths(_paths) => {
            let config = config?;
            let config_path = if let Some(path) = &config.config_path {
                Cow::Owned(format!("{:?}", path))
            } else {
                Cow::Borrowed("-")
            };
            println!("config path:   {}", config_path);
            println!("database path: {:?}", config.database_path()?);
        }
        Plumbing::Config(_config) => {
            let config = config?;
            let config = serde_json::to_string_pretty(&config.data)?;
            println!("{config}");
        }
        Plumbing::Index(query) => {
            let config = config?;
            let mut db = Database::open(&config, AccessMode::Relaxed).await?;

            let mut q = sync::TreeQuery {
                fp: query.fingerprint,
                hash_algo: query.hash_algo,
                prefix: query.prefix,
            };

            if query.batch {
                let (index, _) = db.batch_index_from_scan(&mut q).await?;
                index.write_to(io::stdout()).await?;
            } else {
                let (index, counter) = db.index_from_scan(&q).await?;

                println!("{index}  {counter}");
            }
        }
        Plumbing::SyncYield(_sync_yield) => {
            let config = config?;
            let mut db = Database::open(&config, AccessMode::Relaxed).await?;
            sync::sync_yield(&mut db, io::stdin(), &mut io::stdout(), None).await?;
        }
        Plumbing::SyncPull(sync_pull) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;
            let mut db = Database::open(&config, AccessMode::Exclusive).await?;
            sync::sync_pull(
                &mut db,
                &keyring,
                &sync_pull.keys,
                sync_pull.dry_run,
                io::stdout(),
                io::stdin(),
            )
            .await?;
        }
        Plumbing::ContainerUpdateCheck(update) => match update::check(&update).await? {
            update::Updates::AlreadyLatest { commit } => {
                info!(
                    "We're running the latest version of {:?} (commit={:?})",
                    update.image, commit
                );
            }
            update::Updates::Available { current, latest } => {
                info!(
                    "We're running an outdated version of {:?} (current={:?}, latest={:?})",
                    update.image, current, latest
                );
            }
        },
        #[cfg(feature = "git")]
        Plumbing::GitObject(git) => {
            for path in &git.paths {
                let mut buf = Vec::new();
                let mut reader = path.open().await?;
                reader.read_to_end(&mut buf).await?;

                let signed = git::convert(git.kind, &buf)?;
                let normalized = signed.to_clear_signed()?;

                io::stdout().write_all(&normalized).await?;
            }
        }
        #[cfg(feature = "git")]
        Plumbing::GitScrape(git) => {
            use gix::object::Kind;

            let mut stdout = io::stdout();
            for path in git.paths {
                info!("Opening git repository: {:?}", path);
                let repo = gix::open(&path)
                    .with_context(|| anyhow!("Failed to open git repo: {:?}", path))?;

                for obj in repo.objects.iter()? {
                    let obj = obj.context("Failed to read git object list")?;

                    trace!("Accessing git object: {}", obj);
                    let obj = repo
                        .find_object(obj)
                        .context("Failed to access git object")?;

                    let Ok(signed) = (match obj.kind {
                        Kind::Commit => {
                            trace!("Found git commit: {:?}", obj);
                            git::convert(Some(git::Kind::Commit), &obj.data)
                        }
                        Kind::Tag => {
                            trace!("Found git tag: {:?}", obj);
                            git::convert(Some(git::Kind::Tag), &obj.data)
                        }
                        _ => continue,
                    }) else {
                        continue;
                    };

                    debug!("Found signed git object: {:?}", obj.id);
                    let normalized = signed.to_clear_signed()?;

                    stdout.write_all(&normalized).await?;
                }
            }
        }
        Plumbing::AttachSig(attach) => {
            let content = fs::read(&attach.content).await.with_context(|| {
                anyhow!("Failed to read content from file: {:?}", attach.content)
            })?;
            let content = BString::new(content);

            for sig_path in &attach.signatures {
                let signature = fs::read(&sig_path).await.with_context(|| {
                    anyhow!("Failed to read signature from file: {:?}", sig_path)
                })?;

                let signed = Signed {
                    content: content.clone(),
                    signature,
                };

                let mut stdout = io::stdout();
                let text = signed.to_clear_signed()?;
                stdout.write_all(&text).await?;
            }
        }
        Plumbing::DnsBootstrap(bootstrap) => {
            for dns in bootstrap.dns {
                for addr in p2p::dns::resolve(&dns).await? {
                    if bootstrap.ipv4_only && !addr.is_ipv4() {
                        continue;
                    }
                    if bootstrap.ipv6_only && !addr.is_ipv6() {
                        continue;
                    }
                    println!("{addr}");
                }
            }
        }
        #[cfg(unix)]
        Plumbing::DbServer(_server) => {
            let config = config?;
            let db = Database::open_directly(&config, AccessMode::Exclusive).await?;

            let (mut db_server, db_client) = DatabaseServer::new(db);
            let db_socket_path = config.db_socket_path()?;

            tokio::select! {
                _ = db_server.run() => bail!("Database server has terminated"),
                ret = p2p::db::spawn_unix_db_server(&db_client, db_socket_path) => ret,
            }?;
        }
        Plumbing::Migrate(_migrate) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;

            let new_path = config.database_path()?;
            let migrate_path = config.database_migrate_path()?;
            let delete_path = config.database_delete_path()?;

            for path in [&migrate_path, &delete_path] {
                if fs::metadata(&path).await.is_ok() {
                    warn!("Previous migration has failed, removing {path:?}...");
                    fs::remove_dir_all(&path).await.with_context(|| {
                        anyhow!("Failed to delete failed migration at {path:?}")
                    })?;
                }
            }

            info!("Moving database from {new_path:?} to {migrate_path:?}...");
            fs::rename(&new_path, &migrate_path)
                .await
                .with_context(|| {
                    anyhow!("Failed to rename directory from {new_path:?} to {migrate_path:?}")
                })?;

            {
                let mut new_db = Database::open_at(new_path, AccessMode::Exclusive).await?;
                let migrate_db =
                    Database::open_at(migrate_path.clone(), AccessMode::Exclusive).await?;

                let stream = migrate_db.scan_values(&[]);
                tokio::pin!(stream);
                while let Some(item) = stream.next().await {
                    let (_key, value) = item?;

                    let (signed, _remaining) =
                        Signed::from_bytes(&value).context("Failed to parse release file")?;

                    for (fp, variant) in signed.canonicalize(Some(&keyring))? {
                        let fp = fp.context(
                            "Signature can't be imported because the signature is unverified",
                        )?;
                        new_db.add_release(&fp, &variant).await?;
                    }
                }
            }

            info!("Moving database from {migrate_path:?} to {delete_path:?} for deletion...");
            fs::rename(&migrate_path, &delete_path)
                .await
                .with_context(|| {
                    anyhow!("Failed to rename directory from {migrate_path:?} to {delete_path:?}")
                })?;

            info!("Migration completed, removing migration folder...");
            fs::remove_dir_all(&delete_path).await?;
        }
        Plumbing::Fsck(fsck) => {
            let config = config?;
            let keyring = Some(Keyring::load(&config)?);
            let db = Database::open_directly(&config, AccessMode::Relaxed).await?;

            let prefix = if let Some(prefix) = &fsck.prefix {
                prefix.as_bytes()
            } else {
                &[]
            };

            let mut errors = vec![];

            let mut stdout = io::stdout();
            let stream = db.scan_values(prefix);
            tokio::pin!(stream);
            while let Some(item) = stream.next().await {
                let (hash, data) = item.context("Failed to read from database (fsck)")?;
                if quiet == 0 {
                    stdout.write_all(&hash).await?;
                    stdout.write_all(b"... ").await?;
                    stdout.flush().await?;
                }

                match fsck_doc(&hash, &data, keyring.as_ref()).await {
                    Ok(_) => {
                        if quiet == 0 {
                            stdout.write_all(FSCK_OK.as_bytes()).await?;
                            stdout.flush().await?;
                        }
                    }
                    Err(err) => {
                        if quiet == 0 {
                            stdout.write_all(FSCK_ERR.as_bytes()).await?;
                            stdout.flush().await?;
                        }
                        error!("{}: {:#}", BStr::new(&hash), err);
                        errors.push((hash, err));
                    }
                }
            }

            if !errors.is_empty() {
                for (hash, err) in &errors {
                    println!("{}: {:#}", BStr::new(&hash), err);
                }
                bail!("Fsck failed ({} errors occured)", errors.len());
            }
        }
        Plumbing::Completions(completions) => completions.generate()?,
    }

    Ok(())
}
