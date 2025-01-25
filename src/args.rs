use crate::errors::*;
use crate::p2p;
use crate::p2p::proto::{PeerAddr, PeerFilter};
#[cfg(feature = "git")]
use crate::plumbing;
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use std::ffi::OsString;
use std::io::stdout;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use tokio::fs::File;
use tokio::io;
use tokio::io::AsyncRead;

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

    pub async fn open(&self) -> Result<OpenFileOrStdin> {
        match self {
            Self::File(path) => {
                debug!("Opening file {path:?}...");
                let file = File::open(&path)
                    .await
                    .with_context(|| anyhow!("Failed to open file at path: {path:?}"))?;
                Ok(OpenFileOrStdin::File(file))
            }
            Self::Stdin => Ok(OpenFileOrStdin::Stdin(io::stdin())),
        }
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

#[derive(Debug)]
pub enum OpenFileOrStdin {
    File(File),
    Stdin(io::Stdin),
}

impl AsyncRead for OpenFileOrStdin {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        ctx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::File(file) => Pin::new(file).poll_read(ctx, buf),
            Self::Stdin(stdin) => Pin::new(stdin).poll_read(ctx, buf),
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
    /// Configure a socks5 proxy for outgoing connections
    #[arg(long, global = true)]
    pub proxy: Option<SocketAddr>,
    /// Configure the path where persistent data should be stored
    #[arg(long, global = true, env = "APT_SWARM_DATA_PATH")]
    pub data_path: Option<PathBuf>,
    /// Always enable colored output
    #[arg(short = 'C', long, global = true)]
    pub colors: bool,
    #[command(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Subcommand)]
pub enum SubCommand {
    Import(Import),
    Export(Export),
    Fetch(Fetch),
    Latest(Latest),
    Ls(Ls),
    Keyring(Keyring),
    Pull(Pull),
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

/// Query the latest release for a given key
#[derive(Debug, Parser)]
pub struct Latest {
    /// The signing key to query
    pub fingerprint: sequoia_openpgp::Fingerprint,
    /// Print only the key
    #[arg(short = 'K', long, group = "print")]
    pub key: bool,
    /// Print only the date
    #[arg(short = 'D', long, group = "print")]
    pub date: bool,
    /// Print only the body (with the signature stripped)
    #[arg(short = 'B', long, group = "print")]
    pub body: bool,
    /// Print only the header (everything before the first empty line)
    #[arg(short = 'H', long, group = "print")]
    pub header: bool,
    /// Print only the attachment (everything after the first empty line)
    #[arg(short = 'A', long, group = "print")]
    pub attachment: bool,
    /// Permit dates from the future
    #[arg(short = 'F', long)]
    pub allow_future_dates: bool,
}

/// List hashes of all known releases
#[derive(Debug, Parser)]
pub struct Ls {
    /// Use a specific prefix to filter by
    pub prefix: Option<String>,
    /// Count keys present in database instead of listing them
    #[arg(short = 's', long)]
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

/// Connect to a remote node and sync from them
#[derive(Debug, Parser)]
pub struct Pull {
    /// The address to connect to
    pub addr: PeerAddr,
    /// Only sync data for specific keys, identified by their fingerprint
    #[arg(long = "key")]
    pub keys: Vec<sequoia_openpgp::Fingerprint>,
    /// Run the sync but do not import
    #[arg(short = 'n', long)]
    pub dry_run: bool,
}

/// Run in p2p swarm mode
#[derive(Debug, Parser)]
pub struct P2p {
    #[cfg(feature = "irc")]
    #[command(flatten)]
    pub irc: P2pIrc,
    #[command(flatten)]
    pub dns: P2pDns,
    /// Do not use any bootstrapping mechanism, initial peers need to be added manually
    #[arg(long)]
    pub no_bootstrap: bool,
    /// Do not actively fetch updates from the configured repositories
    #[arg(long)]
    pub no_fetch: bool,
    #[cfg(feature = "onions")]
    /// Setup a hidden service and support outbound onion connections
    #[arg(long)]
    pub onions: bool,
    /// Do not bind a sync port for p2p traffic
    #[arg(long)]
    pub no_bind: bool,
    /// The addresses to bind a sync port for p2p traffic (if not disabled)
    #[arg(short = 'B', long, default_values = &["0.0.0.0:16169", "[::]:16169"])]
    pub bind: Vec<SocketAddr>,
    /// Configure addresses to announce if somebody wants to sync from us
    #[arg(short = 'A', long)]
    pub announce: Vec<SocketAddr>,
    /// Monitor a container registry for updates and terminate if an update is available (eg. ghcr.io/kpcyrd/apt-swarm:edge)
    #[arg(long, value_name = "IMAGE")]
    pub check_container_updates: Option<String>,
    /// The VCS commit to assume for our currently running image
    #[arg(long, value_name = "COMMIT", env = "UPDATE_CHECK_COMMIT")]
    pub update_assume_commit: Option<String>,
}

#[cfg(feature = "irc")]
#[derive(Debug, Parser)]
pub struct P2pIrc {
    /// Do not connect to irc for peer discovery
    #[arg(long)]
    pub no_irc: bool,
    /// The irc server and channel to connect to
    #[arg(long, default_value = "ircs://irc.hackint.org/##apt-swarm-p2p")]
    pub irc_channel: String,
}

#[derive(Debug, Parser)]
pub struct P2pDns {
    /// Do not query any configured dnsseeds
    #[arg(long)]
    pub no_dns: bool,
    /// The dns names to query for bootstrapping
    #[arg(long, default_values = p2p::dns::DNS_SEEDS)]
    pub dns: Vec<String>,
}

/// Access to low-level features
#[derive(Debug, Subcommand)]
pub enum Plumbing {
    AttachSig(AttachSig),
    Canonicalize(Canonicalize),
    Completions(Completions),
    Config(Config),
    ContainerUpdateCheck(ContainerUpdateCheck),
    #[cfg(unix)]
    DbServer(DbServer),
    DnsBootstrap(DnsBootstrap),
    Fetch(PlumbingFetch),
    Fingerprint(Fingerprint),
    Fsck(Fsck),
    #[cfg(feature = "git")]
    GitObject(GitObject),
    #[cfg(feature = "git")]
    GitScrape(GitScrape),
    Index(Index),
    Migrate(Migrate),
    #[cfg(feature = "onions")]
    OnionConnect(OnionConnect),
    #[cfg(feature = "onions")]
    OnionService(OnionService),
    Paths(Paths),
    PeerdbAdd(PeerdbAdd),
    PeerdbList(PeerdbList),
    PeerdbGc(PeerdbGc),
    #[cfg(feature = "onions")]
    ResetArti(ResetArti),
    SyncPull(SyncPull),
    SyncYield(SyncYield),
}

/// Create a clear-signed document from a detached signature
#[derive(Debug, Parser)]
pub struct AttachSig {
    pub content: PathBuf,
    pub signatures: Vec<PathBuf>,
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

/// Generate shell completions
#[derive(Debug, Parser)]
pub struct Completions {
    pub shell: Shell,
}

impl Completions {
    pub fn generate(&self) -> Result<()> {
        clap_complete::generate(self.shell, &mut Args::command(), "apt-swarm", &mut stdout());
        Ok(())
    }
}

/// Print applied configuration
#[derive(Debug, Parser)]
pub struct Config {}

/// Query a container registry for a more recent release of a given image
#[derive(Debug, Parser)]
pub struct ContainerUpdateCheck {
    /// The image to monitor for updates (eg. ghcr.io/kpcyrd/apt-swarm:edge)
    #[arg(long)]
    pub image: String,
    /// The commit to assume for our currently running image
    #[arg(long, env = "UPDATE_CHECK_COMMIT")]
    pub commit: String,
}

/// Bind a unix domain socket and allow abstract database access from multiple processes
#[derive(Debug, Parser)]
pub struct DbServer {}

/// Run dns bootstrap query, print results
#[derive(Debug, Parser)]
pub struct DnsBootstrap {
    /// Only print ipv4 records
    #[arg(short = '4', long, group = "proto")]
    pub ipv4_only: bool,
    /// Only print ipv6 records
    #[arg(short = '6', long, group = "proto")]
    pub ipv6_only: bool,
    /// The dns name to query
    #[arg(default_values = p2p::dns::DNS_SEEDS)]
    pub dns: Vec<String>,
}

/// Fetch a link and write response to stdout
#[derive(Debug, Parser)]
pub struct PlumbingFetch {
    /// The resource to fetch
    pub url: String,
}

/// Extract the fingerprint of a pgp key
#[derive(Debug, Parser)]
pub struct Fingerprint {
    /// The input files to read (- for stdin)
    pub paths: Vec<FileOrStdin>,
}

/// Verify stored objects
#[derive(Debug, Parser)]
pub struct Fsck {
    pub prefix: Option<String>,
}

#[cfg(feature = "git")]
/// Convert signed git objects into signature format used by apt-swarm
#[derive(Debug, Parser)]
pub struct GitObject {
    pub paths: Vec<FileOrStdin>,
    #[arg(short, long)]
    pub kind: Option<plumbing::git::Kind>,
}

#[cfg(feature = "git")]
/// Attempt to export all signed objects from a git repo
#[derive(Debug, Parser)]
pub struct GitScrape {
    pub paths: Vec<PathBuf>,
}

/// Scan the database and calculate the requested index
#[derive(Debug, Parser)]
pub struct Index {
    /// The signing key to index
    pub fingerprint: sequoia_openpgp::Fingerprint,
    /// Only entries with this hash algorithm
    pub hash_algo: String,
    /// Calculate an index based on a specific prefix
    pub prefix: Option<String>,
    /// Calculate a batch index, they are bigger but allow syncs with fewer round-trips
    #[arg(short, long)]
    pub batch: bool,
}

/// Open a fresh database and re-import the old data
#[derive(Debug, Parser)]
pub struct Migrate {}

/// Connect to hidden service
#[derive(Debug, Parser)]
pub struct OnionConnect {
    pub onion: String,
    pub port: u16,
}

/// Bind and run hidden service
#[derive(Debug, Parser)]
pub struct OnionService {}

/// Print configured paths
#[derive(Debug, Parser)]
pub struct Paths {}

/// Add a peerdb entry
#[derive(Debug, Parser)]
pub struct PeerdbAdd {
    pub addrs: Vec<PeerAddr>,
}

/// Read and print peerdb file
#[derive(Debug, Parser)]
pub struct PeerdbList {
    /// Filter by ip address or network (without port)
    pub filters: Vec<PeerFilter>,
}

/// Remove old peerdb entries
#[derive(Debug, Parser)]
pub struct PeerdbGc {}

/// Delete all data related to the Tor network
#[derive(Debug, Parser)]
pub struct ResetArti {}

/// Fetch all available signatures over stdio (use with sync-yield)
#[derive(Debug, Parser)]
pub struct SyncPull {
    pub keys: Vec<sequoia_openpgp::Fingerprint>,
    /// Run the sync but do not import
    #[arg(short = 'n', long)]
    pub dry_run: bool,
}

/// Provide access to our signatures over stdio (use with sync-pull)
#[derive(Debug, Parser)]
pub struct SyncYield {
    /// Enable access to peer-exchange queries
    #[arg(long)]
    pub pex: bool,
}
