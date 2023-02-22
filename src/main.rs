use apt_swarm::args::{Args, FileOrStdin, SubCommand};
use apt_swarm::config;
use apt_swarm::db::Database;
use apt_swarm::db::DatabaseClient;
use apt_swarm::errors::*;
use apt_swarm::fetch;
use apt_swarm::keyring::Keyring;
use apt_swarm::p2p;
use apt_swarm::plumbing;
use apt_swarm::signed::Signed;
use clap::Parser;
use colored::Colorize;
use env_logger::Env;
use num_format::{Locale, ToFormattedString};
use sequoia_openpgp::KeyHandle;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use tokio::io::{self, AsyncWriteExt};

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
                        db.add_release(&fp, &variant).await?;
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
            fetch::fetch_updates(&db, keyring, fetch.concurrency, config.data.repositories).await?;
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
        SubCommand::P2p(p2p) => {
            let config = config?;
            let keyring = Keyring::load(&config)?;
            let db = Database::open(&config)?;
            p2p::spawn(db, keyring, p2p, config.data.repositories).await?;
        }
        SubCommand::Plumbing(plumbing) => plumbing::run(config, plumbing).await?,
    }

    Ok(())
}
