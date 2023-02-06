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
    #[command(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Subcommand)]
pub enum SubCommand {
    Import(Import),
    Export(Export),
    #[command(subcommand)]
    Plumbing(Plumbing),
    Completions(Completions),
}

/// Import signed InRelease files
#[derive(Debug, Parser)]
pub struct Import {
    pub paths: Vec<FileOrStdin>,
}

/// Export all known InRelease files
#[derive(Debug, Parser)]
pub struct Export {}

/// Access to low-level features
#[derive(Debug, Subcommand)]
pub enum Plumbing {
    Canonicalize(Canonicalize),
    Fingerprint(Fingerprint),
}

/// Transform a signed InRelease file into a canonical representation
#[derive(Debug, Parser)]
pub struct Canonicalize {
    pub paths: Vec<FileOrStdin>,
}

/// Extract the fingerprint of a pgp key
#[derive(Debug, Parser)]
pub struct Fingerprint {
    pub paths: Vec<FileOrStdin>,
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
