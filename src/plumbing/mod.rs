pub mod git;
pub mod update;

use crate::args::{self, FileOrStdin, Plumbing};
use crate::config::Config;
use crate::db::{Database, DatabaseClient};
use crate::errors::*;
use crate::keyring::Keyring;
use crate::pgp;
use crate::signed::Signed;
use crate::sync;
use bstr::BString;
use gix::object::Kind;
use std::borrow::Cow;
use std::os::unix::ffi::OsStrExt;
use tokio::fs;
use tokio::io;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

pub async fn run(config: Result<Config>, args: Plumbing) -> Result<()> {
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
        Plumbing::Delete(remove) => {
            let config = config?;
            let mut db = Database::open(&config).await?;

            for key in remove.keys {
                debug!("Deleting key {:?}", key);
                db.delete(key.as_bytes()).await?;
            }
        }
        Plumbing::Index(query) => {
            let config = config?;
            let db = Database::open(&config).await?;

            let mut q = sync::Query {
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
            let db = Database::open(&config).await?;
            sync::sync_yield(&db, io::stdin(), &mut io::stdout(), None).await?;
        }
        Plumbing::SyncPull(sync_pull) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;
            let mut db = Database::open(&config).await?;
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
        Plumbing::GitScrape(git) => {
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
                    }) else { continue };

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
        Plumbing::Completions(completions) => {
            args::gen_completions(&completions)?;
        }
    }

    Ok(())
}
