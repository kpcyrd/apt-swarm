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

    match args.subcommand {
        SubCommand::Import(mut import) => {
            let config = config::Config {};
            let db = Database::open(&config)?;

            FileOrStdin::default_stdin(&mut import.paths);
            for path in import.paths {
                let buf = path.read().await?;
                // TODO: verify signature
                db.add_release(&buf)?;
            }

            db.flush().await?;
        }
        SubCommand::Plumbing(Plumbing::Canonicalize(mut canonicalize)) => {
            FileOrStdin::default_stdin(&mut canonicalize.paths);

            let mut stdout = io::stdout();
            for path in canonicalize.paths {
                let buf = path.read().await?;
                let normalized = signed::canonicalize(&buf)?;
                stdout.write_all(&normalized).await?;
            }
        }
        SubCommand::Plumbing(Plumbing::Fingerprint(_fingerprint)) => {
            let mut buf = Vec::new();

            let mut stdin = io::stdin();
            stdin.read_to_end(&mut buf).await?;

            pgp::load(&buf)?;
        }
        SubCommand::Plumbing(Plumbing::Paths(_paths)) => {
            let config = config::Config {};
            println!("database path: {:?}", config.database_path()?);
        }
        SubCommand::Completions(completions) => {
            args::gen_completions(&completions)?;
        }
        _ => todo!("Subcommand is not implemented yet"),
    }

    Ok(())
}
