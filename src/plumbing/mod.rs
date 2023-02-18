pub mod update;

use crate::args::{self, FileOrStdin, Plumbing};
use crate::config::Config;
use crate::db::Database;
use crate::errors::*;
use crate::keyring::Keyring;
use crate::pgp;
use crate::signed::Signed;
use crate::sync;
use sha2::{Digest, Sha256};
use std::os::unix::ffi::OsStrExt;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
                let buf = path.read().await?;
                let mut bytes = &buf[..];
                while !bytes.is_empty() {
                    let (signed, remaining) =
                        Signed::from_bytes(bytes).context("Failed to parse release file")?;

                    for (_fp, variant) in signed.canonicalize(keyring.as_ref())? {
                        let text = variant.to_clear_signed()?;
                        stdout.write_all(&text).await?;
                    }

                    bytes = remaining;
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
            println!("database path: {:?}", config.database_path()?);
        }
        Plumbing::Config(_config) => {
            let config = config?;
            let config = serde_json::to_string_pretty(&config)?;
            println!("{config}");
        }
        Plumbing::Delete(remove) => {
            let config = config?;
            let db = Database::open(&config)?;

            for key in remove.keys {
                debug!("Deleting key {:?}", key);
                db.delete(key.as_bytes())?;
            }
        }
        Plumbing::Index(query) => {
            let config = config?;
            let db = Database::open(&config)?;

            let prefix = query.prefix.as_deref().unwrap_or("");
            let prefix = format!("{:X}/{}:{}", query.fingerprint, query.hash_algo, prefix);

            let mut counter = 0;
            let mut hasher = Sha256::new();
            for item in db.scan_prefix(prefix.as_bytes()) {
                let (hash, _data) = item.context("Failed to read from database")?;
                hasher.update(&hash);
                hasher.update(b"\n");
                counter += 1;
            }

            let result = hasher.finalize();
            println!("sha256:{result:x}  {counter}");
        }
        Plumbing::SyncYield(_sync_yield) => {
            let config = config?;
            let db = Database::open(&config)?;
            sync::sync_yield(&db, io::stdin(), io::stdout()).await?;
        }
        Plumbing::SyncPull(sync_pull) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;
            let db = Database::open(&config)?;
            sync::sync_pull(
                &db,
                &keyring,
                &sync_pull.keys,
                sync_pull.dry_run,
                io::stdout(),
                io::stdin(),
            )
            .await?;
        }
        Plumbing::ContainerUpdateCheck(update) => {
            update::check(&update).await?;
        }
        Plumbing::Completions(completions) => {
            args::gen_completions(&completions)?;
        }
    }

    Ok(())
}
