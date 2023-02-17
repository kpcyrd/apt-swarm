use apt_swarm::args::{self, Args, FileOrStdin, Plumbing, SubCommand};
use apt_swarm::config;
use apt_swarm::db::Database;
use apt_swarm::errors::*;
use apt_swarm::fetch;
use apt_swarm::keyring::Keyring;
use apt_swarm::p2p;
use apt_swarm::pgp;
use apt_swarm::signed::Signed;
use apt_swarm::sync;
use clap::Parser;
use colored::Colorize;
use env_logger::Env;
use num_format::{Locale, ToFormattedString};
use sequoia_openpgp::KeyHandle;
use sha2::{Digest, Sha256};
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match (args.quiet, args.verbose) {
        (0, 0) => "warn,apt_swarm=info",
        (1, 0) => "warn",
        (_, 0) => "error",
        (_, 1) => "info,apt_swarm=debug",
        (_, 2) => "debug",
        (_, 3) => "debug,apt_swarm=trace",
        _ => "trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    let config = config::Config::load_with_args(&args).await;

    match args.subcommand {
        SubCommand::Import(mut import) => {
            let config = config?;
            let keyring = Some(Keyring::load(&config)?);
            let db = Database::open(&config)?;

            FileOrStdin::default_stdin(&mut import.paths);
            for path in import.paths {
                let buf = path.read().await?;

                let mut bytes = &buf[..];
                while !bytes.is_empty() {
                    let (signed, remaining) =
                        Signed::from_bytes(bytes).context("Failed to parse release file")?;

                    for (fp, variant) in signed.canonicalize(keyring.as_ref())? {
                        let fp = fp.context(
                            "Signature can't be imported because the signature is unverified",
                        )?;
                        db.add_release(&fp, &variant)?;
                    }

                    bytes = remaining;
                }
            }

            db.flush().await?;
        }
        SubCommand::Export(export) => {
            let config = config?;
            let db = Database::open(&config)?;

            let mut stdout = io::stdout();
            if export.release_hashes.is_empty() {
                for item in db.scan_prefix(&[]) {
                    let (_hash, data) = item.context("Failed to read from database")?;
                    stdout.write_all(&data).await?;
                }
            } else {
                for hash in &export.release_hashes {
                    if export.scan {
                        for item in db.scan_prefix(hash.as_bytes()) {
                            let (_hash, data) = item.context("Failed to read from database")?;
                            stdout.write_all(&data).await?;
                        }
                    } else {
                        let data = db
                            .get(hash)
                            .context("Failed to read database")?
                            .with_context(|| anyhow!("Failed to find key in database: {hash:?}"))?;
                        stdout.write_all(&data).await?;
                    }
                }
            }
        }
        SubCommand::Fetch(fetch) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;
            let db = Database::open(&config)?;

            let keyring = Arc::new(Some(keyring));
            fetch::fetch_updates(&db, keyring, fetch.concurrency, config.repositories).await?;
        }
        SubCommand::Ls(ls) => {
            let config = config?;
            let db = Database::open(&config)?;

            let prefix = if let Some(prefix) = &ls.prefix {
                prefix.as_bytes()
            } else {
                &[]
            };

            let mut stdout = io::stdout();
            let mut count = 0;
            for item in db.scan_prefix(prefix) {
                if ls.count {
                    count += 1;
                    continue;
                }
                let (hash, _data) = item.context("Failed to read from database")?;
                stdout.write_all(&hash).await?;
                stdout.write_all(b"\n").await?;
            }

            if ls.count {
                println!("{count}");
            }
        }
        SubCommand::Keyring(args) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;
            let db = Database::open(&config)?;

            if args.json {
                let keyring = keyring.generate_report()?;
                let keyring = serde_json::to_string_pretty(&keyring)
                    .context("Failed to encode keyring as json")?;
                println!("{keyring}");
            } else {
                for key in keyring.keys.values() {
                    let hex = key.hex_fingerprint();
                    for uid in &key.uids {
                        println!("{}  {}", hex.green(), uid.yellow());
                    }
                    for (handle, _fp) in &key.key_handles {
                        if let KeyHandle::Fingerprint(fp) = handle {
                            let subkey = format!("Subkey {fp:X}");

                            let stats = if args.stats {
                                let prefix = format!("{fp:X}/");
                                let count = db.scan_prefix(prefix.as_bytes()).count();
                                if count > 0 {
                                    let count = count.to_formatted_string(&Locale::en);
                                    Some(format!("  ({count} known signatures)"))
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            let stats = stats.as_deref().unwrap_or("");
                            println!("{}  {}{}", hex.green(), subkey.purple(), stats.cyan());
                        }
                    }
                }
            }
        }
        SubCommand::P2p(_p2p) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;
            let db = Database::open(&config)?;
            p2p::spawn(&db, keyring, config.repositories).await?;
        }
        SubCommand::Plumbing(Plumbing::Canonicalize(mut canonicalize)) => {
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
        SubCommand::Plumbing(Plumbing::Fingerprint(_fingerprint)) => {
            let mut buf = Vec::new();

            let mut stdin = io::stdin();
            stdin.read_to_end(&mut buf).await?;

            pgp::load(&buf)?;
        }
        SubCommand::Plumbing(Plumbing::Paths(_paths)) => {
            let config = config?;
            println!("database path: {:?}", config.database_path()?);
        }
        SubCommand::Plumbing(Plumbing::Config(_config)) => {
            let config = config?;
            let config = serde_json::to_string_pretty(&config)?;
            println!("{config}");
        }
        SubCommand::Plumbing(Plumbing::Delete(remove)) => {
            let config = config?;
            let db = Database::open(&config)?;

            for key in remove.keys {
                debug!("Deleting key {:?}", key);
                db.delete(key.as_bytes())?;
            }
        }
        SubCommand::Plumbing(Plumbing::Index(query)) => {
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
        SubCommand::Plumbing(Plumbing::SyncYield(_sync_yield)) => {
            let config = config?;
            let db = Database::open(&config)?;
            sync::sync_yield(&db, io::stdin(), io::stdout()).await?;
        }
        SubCommand::Plumbing(Plumbing::SyncPull(sync_pull)) => {
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
        SubCommand::Completions(completions) => {
            args::gen_completions(&completions)?;
        }
    }

    Ok(())
}
