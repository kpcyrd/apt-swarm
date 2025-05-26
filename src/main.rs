use apt_swarm::args::{Args, FileOrStdin, SubCommand};
use apt_swarm::config;
use apt_swarm::db::{AccessMode, Database, DatabaseClient};
use apt_swarm::errors::*;
use apt_swarm::fetch;
use apt_swarm::keyring::Keyring;
use apt_swarm::latest;
use apt_swarm::net;
use apt_swarm::p2p;
use apt_swarm::plumbing;
use apt_swarm::signed::Signed;
use apt_swarm::sync;
use chrono::{DateTime, Utc};
use clap::Parser;
use colored::Colorize;
use env_logger::Env;
use futures::StreamExt;
use num_format::{Locale, ToFormattedString};
use sequoia_openpgp::KeyHandle;
use std::borrow::Cow;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(target_os = "openbsd")]
    pledge::pledge("stdio dns inet rpath wpath cpath flock unix", "")
        .context("Failed to setup pledge sandbox")?;

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

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("Failed to install rustls ring CryptoProvider"))?;

    let config = config::Config::load_with_args(&args).await;

    if args.colors {
        colored::control::set_override(true);
    }

    match args.subcommand {
        SubCommand::Import(mut import) => {
            let config = config?;
            let keyring = Some(Keyring::load(&config)?);
            let mut db = Database::open(&config, AccessMode::Exclusive).await?;

            FileOrStdin::default_stdin(&mut import.paths);
            for path in import.paths {
                let reader = path.open().await?;
                let mut reader = io::BufReader::new(reader);

                while !reader.fill_buf().await?.is_empty() {
                    let signed = Signed::from_reader(&mut reader)
                        .await
                        .context("Failed to parse release file")?;

                    for (fp, variant) in signed.canonicalize(keyring.as_ref())? {
                        let fp = fp.context(
                            "Signature can't be imported because the signature is unverified",
                        )?;
                        db.add_release(&fp, &variant).await?;
                    }
                }
            }
        }
        SubCommand::Export(export) => {
            let config = config?;
            let db = Database::open_directly(&config, AccessMode::Relaxed).await?;

            let mut stdout = io::stdout();
            if export.release_hashes.is_empty() {
                let stream = db.scan_values(&[]);
                tokio::pin!(stream);
                while let Some(item) = stream.next().await {
                    let (_hash, data) = item.context("Failed to read from database")?;
                    stdout.write_all(&data).await?;
                }
            } else {
                for hash in &export.release_hashes {
                    if export.scan {
                        let stream = db.scan_values(hash.as_bytes());
                        tokio::pin!(stream);
                        while let Some(item) = stream.next().await {
                            let (_hash, data) = item.context("Failed to read from database")?;
                            stdout.write_all(&data).await?;
                        }
                    } else {
                        let data = db
                            .get(hash)
                            .await
                            .context("Failed to read database")?
                            .with_context(|| anyhow!("Failed to find key in database: {hash:?}"))?;
                        stdout.write_all(&data).await?;
                    }
                }
            }
            // https://github.com/tokio-rs/tokio/issues/7174
            stdout.flush().await?;
        }
        SubCommand::Fetch(fetch) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;
            let mut db = Database::open_directly(&config, AccessMode::Exclusive).await?;

            let keyring = Arc::new(Some(keyring));
            fetch::fetch_updates(
                &mut db,
                keyring,
                fetch.concurrency,
                config.data.repositories,
                args.proxy,
                &fetch.fingerprints,
            )
            .await?;
        }
        SubCommand::Latest(latest) => {
            let config = config?;
            let db = Database::open_directly(&config, AccessMode::Relaxed).await?;

            let max_allowed_datetime = if latest.allow_future_dates {
                DateTime::<Utc>::MAX_UTC
            } else {
                Utc::now()
            };

            if let Some((date, mut key, signed, content, idx)) =
                latest::find(&db, latest.fingerprint, max_allowed_datetime).await?
            {
                let mut stdout = io::stdout();
                let value: Cow<'_, [u8]> = if latest.key {
                    key.push(b'\n');
                    Cow::Owned(key)
                } else if latest.date {
                    let mut date = date.to_rfc3339();
                    date.push('\n');
                    Cow::Owned(date.into_bytes())
                } else if latest.body {
                    Cow::Borrowed(&content)
                } else if latest.header {
                    Cow::Borrowed(&content[..idx])
                } else if latest.attachment {
                    Cow::Borrowed(&content[idx..])
                } else {
                    Cow::Borrowed(&signed)
                };
                stdout.write_all(&value).await?;
                // https://github.com/tokio-rs/tokio/issues/7174
                stdout.flush().await?;
            }
        }
        SubCommand::Ls(ls) => {
            let config = config?;
            // TODO: this should call open(), but needs to be rewritten because
            // .scan_keys is not available over unix domain socket
            let db = Database::open_directly(&config, AccessMode::Relaxed).await?;

            let prefix = if let Some(prefix) = &ls.prefix {
                prefix.as_bytes()
            } else {
                &[]
            };

            let mut stdout = io::stdout();
            let mut count = 0;

            let stream = db.scan_keys(prefix);
            tokio::pin!(stream);
            while let Some(item) = stream.next().await {
                if ls.count {
                    count += 1;
                    continue;
                }
                let hash = item.context("Failed to read from database (ls)")?;
                stdout.write_all(&hash).await?;
                stdout.write_all(b"\n").await?;
            }
            // https://github.com/tokio-rs/tokio/issues/7174
            stdout.flush().await?;

            if ls.count {
                println!("{count}");
            }
        }
        SubCommand::Keyring(args) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;
            let mut db = Database::open(&config, AccessMode::Relaxed).await?;

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
                                let count = db.count(prefix.as_bytes()).await?;
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
        SubCommand::Pull(pull) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;
            let mut db = Database::open(&config, AccessMode::Exclusive).await?;

            let mut sock = net::connect(&pull.addr, args.proxy).await?;
            let (rx, mut tx) = sock.split();

            let result =
                sync::sync_pull(&mut db, &keyring, &pull.keys, pull.dry_run, &mut tx, rx).await;

            tx.shutdown().await.ok();
            result?;
        }
        SubCommand::P2p(p2p) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;

            // Explicitly open database, do not test for unix domain socket
            let db = Database::open_directly(&config, AccessMode::Exclusive).await?;

            p2p::spawn(db, keyring, config, p2p, args.proxy).await?;
        }
        SubCommand::Plumbing(plumbing) => {
            plumbing::run(config, plumbing, args.quiet, args.proxy).await?
        }
    }

    Ok(())
}
