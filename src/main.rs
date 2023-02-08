use apt_swarm::args::{self, Args, FileOrStdin, Plumbing, SubCommand};
use apt_swarm::config;
use apt_swarm::db::Database;
use apt_swarm::errors::*;
use apt_swarm::pgp;
use apt_swarm::signed;
use clap::Parser;
use env_logger::Env;
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
            let db = Database::open(&config)?;

            FileOrStdin::default_stdin(&mut import.paths);
            for path in import.paths {
                let buf = path.read().await?;

                let mut bytes = &buf[..];
                while !bytes.is_empty() {
                    let (normalized, remaining) =
                        signed::canonicalize(bytes).context("Failed to canonicalize release")?;
                    // TODO: verify signature
                    db.add_release(&normalized)?;
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
                    let data = db
                        .get(hash)
                        .context("Failed to read database")?
                        .with_context(|| anyhow!("Failed to find key in database: {hash:?}"))?;
                    stdout.write_all(&data).await?;
                }
            }
        }
        SubCommand::Fetch(_fetch) => {
            let config = config?;
            let db = Database::open(&config)?;

            let client = reqwest::Client::new();
            for repository in &config.repositories {
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
                    db.add_release(&body)?;
                }
            }
        }
        SubCommand::Ls(_ls) => {
            let config = config?;
            let db = Database::open(&config)?;

            let mut stdout = io::stdout();
            for item in db.scan_prefix(&[]) {
                let (hash, _data) = item.context("Failed to read from database")?;
                stdout.write_all(&hash).await?;
                stdout.write_all(b"\n").await?;
            }
        }
        SubCommand::Plumbing(Plumbing::Canonicalize(mut canonicalize)) => {
            FileOrStdin::default_stdin(&mut canonicalize.paths);

            let mut stdout = io::stdout();
            for path in canonicalize.paths {
                let buf = path.read().await?;
                let mut cur = &buf[..];
                while !cur.is_empty() {
                    let (normalized, remaining) = signed::canonicalize(cur)?;
                    stdout.write_all(&normalized).await?;
                    cur = remaining;
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
