use crate::errors::*;
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use std::ffi::OsString;
use std::io::stdout;
use std::path::PathBuf;
use tokio::fs;
use tokio::io;
use tokio::io::AsyncReadExt;

#[derive(Debug, Clone)]
pub enum FileOrStdin {
    File(PathBuf),
    Stdin,
}

impl FileOrStdin {
    /// If the given list is empty, select stdin as input
    pub fn default_stdin(list: &mut Vec<Self>) {
        if list.is_empty() {
            list.push(Self::Stdin);
        }
    }

    pub async fn read(&self) -> Result<Vec<u8>> {
        let buf = match self {
            Self::File(path) => fs::read(&path)
                .await
                .with_context(|| anyhow!("Failed to read file at path: {path:?}"))?,
            Self::Stdin => {
                let mut buf = Vec::new();
                let mut stdin = io::stdin();
                stdin.read_to_end(&mut buf).await?;
                buf
            }
        };
        Ok(buf)
    }
}

impl From<OsString> for FileOrStdin {
    fn from(s: OsString) -> Self {
        if s.to_str() == Some("-") {
            Self::Stdin
        } else {
            Self::File(s.into())
        }
    }
}

#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    /// Increase logging output (can be used multiple times)
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    /// Reduce logging output (can be used multiple times)
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub quiet: u8,
    /// Path to config file to use
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,
    /// Configure the path where persistent data should be stored
    #[arg(long, global = true, env = "APT_SWARM_DATA_PATH")]
    pub data_path: Option<PathBuf>,
    #[command(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Subcommand)]
pub enum SubCommand {
    Import(Import),
    Export(Export),
    Fetch(Fetch),
    Ls(Ls),
    Keyring(Keyring),
    P2p(P2p),
    #[command(subcommand)]
    Plumbing(Plumbing),
}

/// Import signed InRelease files
#[derive(Debug, Parser)]
pub struct Import {
    /// The input files to read (- for stdin)
    pub paths: Vec<FileOrStdin>,
}

/// Export all known InRelease files
#[derive(Debug, Parser)]
pub struct Export {
    pub release_hashes: Vec<String>,
    /// Instead of exact matches, scan with the given prefix(es)
    #[arg(long)]
    pub scan: bool,
}

/// Fetch the latest InRelease files and import them
#[derive(Debug, Parser)]
pub struct Fetch {
    /// Number of concurrent requests
    #[arg(short = 'j', long)]
    pub concurrency: Option<usize>,
}

/// List hashes of all known releases
#[derive(Debug, Parser)]
pub struct Ls {
    /// Use a specific prefix to filter by
    pub prefix: Option<OsString>,
    /// Count keys present in database instead of listing them
    #[arg(short = 'C', long)]
    pub count: bool,
}

/// List all keys currently configured for monitoring
#[derive(Debug, Parser)]
pub struct Keyring {
    /// Output keyring as json
    #[arg(long)]
    pub json: bool,
    /// Show the number of known signatures for a given subkey
    #[arg(short, long)]
    pub stats: bool,
}

/// Run in p2p swarm mode
#[derive(Debug, Parser)]
pub struct P2p {
    /// Do not connect to irc for peer discovery
    #[arg(long)]
    pub no_irc: bool,
    /// Do not actively fetch updates from the configured repositories
    #[arg(long)]
    pub no_fetch: bool,
    /// Monitor a container registry for updates and terminate if an update is available (eg. ghcr.io/kpcyrd/apt-swarm:edge)
    #[arg(long, value_name = "IMAGE")]
    pub check_container_updates: Option<String>,
    /// The VCS commit to assume for our currently running image
    #[arg(long, value_name = "COMMIT", env = "UPDATE_CHECK_COMMIT")]
    pub update_assume_commit: Option<String>,
}

/// Access to low-level features
#[derive(Debug, Subcommand)]
pub enum Plumbing {
    Canonicalize(Canonicalize),
    Fingerprint(Fingerprint),
    Paths(Paths),
    Config(Config),
    Delete(Delete),
    Index(Index),
    SyncYield(SyncYield),
    SyncPull(SyncPull),
    ContainerUpdateCheck(ContainerUpdateCheck),
    Completions(Completions),
}

/// Transform a signed InRelease file into a canonical representation
#[derive(Debug, Parser)]
pub struct Canonicalize {
    /// The input files to read (- for stdin)
    pub paths: Vec<FileOrStdin>,
    /// Verify signatures belong to trusted key in keyring
    #[arg(long)]
    pub verify: bool,
}

/// Extract the fingerprint of a pgp key
#[derive(Debug, Parser)]
pub struct Fingerprint {
    /// The input files to read (- for stdin)
    pub paths: Vec<FileOrStdin>,
}

/// Print configured paths
#[derive(Debug, Parser)]
pub struct Paths {}

/// Print applied configuration
#[derive(Debug, Parser)]
pub struct Config {}

/// Delete keys from the database
#[derive(Debug, Parser)]
pub struct Delete {
    pub keys: Vec<OsString>,
}

/// Scan the database and calculate the requested index
#[derive(Debug, Parser)]
pub struct Index {
    /// The signing key to index
    pub fingerprint: sequoia_openpgp::Fingerprint,
    /// Only entries with this hash algorithm
    pub hash_algo: String,
    /// Calculate an inex based on a specific prefix
    pub prefix: Option<String>,
}

#[derive(Debug, Parser)]
pub struct SyncYield {}

#[derive(Debug, Parser)]
pub struct SyncPull {
    pub keys: Vec<sequoia_openpgp::Fingerprint>,
    /// Run the sync but do not import
    #[arg(short = 'n', long)]
    pub dry_run: bool,
}

#[derive(Debug, Parser)]
pub struct ContainerUpdateCheck {
    /// The image to monitor for updates (eg. ghcr.io/kpcyrd/apt-swarm:edge)
    #[arg(long)]
    pub image: String,
    /// The commit to assume for our currently running image
    #[arg(long, env = "UPDATE_CHECK_COMMIT")]
    pub commit: String,
}

/// Generate shell completions
#[derive(Debug, Parser)]
pub struct Completions {
    pub shell: Shell,
}

pub fn gen_completions(args: &Completions) -> Result<()> {
    clap_complete::generate(args.shell, &mut Args::command(), "apt-swarm", &mut stdout());
    Ok(())
}
