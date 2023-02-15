use apt_swarm::args::{self, Args, FileOrStdin, Plumbing, SubCommand};
use apt_swarm::config;
use apt_swarm::db::Database;
use apt_swarm::errors::*;
use apt_swarm::keyring::Keyring;
use apt_swarm::pgp;
use apt_swarm::signed::Signed;
use clap::Parser;
use colored::Colorize;
use env_logger::Env;
use sequoia_openpgp::Fingerprint;
use sequoia_openpgp::KeyHandle;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;

const DEFAULT_FETCH_CONCURRENCY: usize = 4;

async fn fetch_repository_updates(
    client: &reqwest::Client,
    keyring: &Option<Keyring>,
    repository: &config::Repository,
) -> Result<Vec<(Option<Fingerprint>, Signed)>> {
    let mut out = Vec::new();

    for url in &repository.urls {
        info!("Fetching url {:?}...", url);
        let r = client
            .get(url)
            .send()
            .await
            .context("Failed to send request")?
            .error_for_status()
            .context("Received http error")?;
        let body = r
            .bytes()
            .await
            .context("Failed to download http response")?;

        let (signed, _remaining) =
            Signed::from_bytes(&body).context("Failed to parse http response as release")?;

        for item in signed.canonicalize(keyring)? {
            out.push(item);
        }
    }

    Ok(out)
}

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

                    for (fp, variant) in signed.canonicalize(&keyring)? {
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
            let keyring = Arc::new(Some(Keyring::load(&config)?));
            let db = Database::open(&config)?;

            let concurrency = fetch.concurrency.unwrap_or(DEFAULT_FETCH_CONCURRENCY);
            let mut queue = config.repositories.into_iter();
            let mut pool = JoinSet::new();
            let client = reqwest::Client::new();

            loop {
                while pool.len() < concurrency {
                    if let Some(repository) = queue.next() {
                        let client = client.clone();
                        let keyring = keyring.clone();
                        pool.spawn(async move {
                            fetch_repository_updates(&client, &keyring, &repository).await
                        });
                    } else {
                        // no more tasks to schedule
                        break;
                    }
                }
                if let Some(join) = pool.join_next().await {
                    match join.context("Failed to join task")? {
                        Ok(list) => {
                            for (fp, variant) in list {
                                let fp = fp.context(
                                    "Signature can't be imported because the signature is unverified",
                                )?;
                                db.add_release(&fp, &variant)?;
                            }
                        }
                        Err(err) => error!("Error fetching latest release: {err:#}"),
                    }
                } else {
                    // no more tasks in pool
                    break;
                }
            }
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
            if args.json {
                let keyring = keyring.generate_report()?;
                let keyring = serde_json::to_string_pretty(&keyring)
                    .context("Failed to encode keyring as json")?;
                println!("{}", keyring);
            } else {
                for key in keyring.keys.values() {
                    let hex = key.hex_fingerprint();
                    for uid in &key.uids {
                        println!("{}  {}", hex.green(), uid);
                    }
                    for (handle, _fp) in &key.key_handles {
                        if let KeyHandle::Fingerprint(fp) = handle {
                            let fp = format!("Subkey {fp:X}");
                            println!("{}  {}", hex.green(), fp.yellow());
                        }
                    }
                }
            }
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

                    for (_fp, variant) in signed.canonicalize(&keyring)? {
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
        SubCommand::Completions(completions) => {
            args::gen_completions(&completions)?;
        }
    }

    Ok(())
}
