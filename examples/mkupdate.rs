use apt_swarm::errors::*;
use apt_swarm::signed::Signed;
use chrono::Utc;
use clap::Parser;
use env_logger::Env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    #[arg(long)]
    pub date: Option<String>,
    #[arg(long)]
    pub commit: Option<String>,
    #[arg(long)]
    pub secret_key: PathBuf,
    /// The binary file to issue as update
    pub path: PathBuf,
}

fn get_commit() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .stdout(Stdio::piped())
        .spawn()
        .context("Failed to run git binary")?
        .wait_with_output()
        .context("Failed to wait for git child")?;
    if !output.status.success() {
        bail!("Git did not exit successfully");
    }
    let mut output =
        String::from_utf8(output.stdout).context("Git output contains invalid utf8")?;
    output.truncate(output.find('\n').unwrap_or(output.len()));
    Ok(output)
}

fn sign(data: &[u8], secret_key: &Path) -> Result<Vec<u8>> {
    let mut child = Command::new("sh4d0wup")
        .args([
            OsStr::new("sign"),
            OsStr::new("pgp-detached"),
            OsStr::new("--binary"),
            OsStr::new("--secret-key"),
            secret_key.as_os_str(),
            OsStr::new("/dev/stdin"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("Failed to run sh4d0wup binary")?;

    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(data)?;
    stdin.flush()?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .context("Failed to wait for sh4d0wup child")?;
    if !output.status.success() {
        bail!("Git did not exit successfully");
    }
    Ok(output.stdout)
}

fn mkupdate(date: &str, commit: &str, data: &[u8]) -> Result<Vec<u8>> {
    let header = format!("Date: {date}\nCommit: {commit}\n\n");
    info!("Generated header: {header:?}");
    let mut buf = header.into_bytes();
    buf.extend(data);
    if !buf.ends_with(b"\n") {
        buf.push(b'\n');
    }
    Ok(buf)
}

fn normalize(data: Vec<u8>, signature: Vec<u8>) -> Result<Vec<u8>> {
    let signed = Signed {
        content: data.into(),
        signature,
    };
    signed.to_clear_signed()
}

fn main() -> Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let args = Args::parse();

    let date = args
        .date
        .unwrap_or_else(|| Utc::now().format("%a, %d %b %Y %T %Z").to_string());
    let commit = args.commit.map(Ok).unwrap_or_else(get_commit)?;

    let content = fs::read(&args.path)
        .with_context(|| anyhow!("Failed to read content from file: {:?}", args.path))?;

    let buf = mkupdate(&date, &commit, &content)?;
    info!("Full update: {} bytes", buf.len());

    info!("Generating signature...");
    let signature = sign(&buf, &args.secret_key)?;
    info!("Signature generated successfully");

    let mut stdout = io::stdout();
    let buf = normalize(buf, signature)?;
    stdout.write_all(&buf)?;

    Ok(())
}
