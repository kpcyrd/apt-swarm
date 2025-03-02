use apt_swarm::errors::*;
use clap::{ArgAction, Parser};
use env_logger::Env;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::fs;
use tokio::io::{self, AsyncWriteExt};
use tokio::process::{self, Command};
use tokio::time;

const LATEST_CHECK_INTERVAL: Duration = Duration::from_secs(180);

#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    /// Increase logging output
    #[arg(short, long, action(ArgAction::Count))]
    verbose: u8,
    /// Path to executable to run and maintain
    exe: PathBuf,
    /// Signing key to query for
    fp: String,
    /// Arguments to pass to apt-swarm
    args: Vec<String>,
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

async fn query_latest_exe(exe: &Path, fp: &str) -> Result<Vec<u8>> {
    debug!("Checking `apt-swarm latest` output");
    let output = Command::new(exe)
        .args(["latest", "-A", fp])
        .stdout(Stdio::piped())
        .output()
        .await
        .context("Failed to execute apt-swarm binary")?;
    if !output.status.success() {
        bail!("apt-swarm did not exit successfully");
    }
    Ok(output.stdout)
}

async fn random_suffix(path: &Path) -> Result<(PathBuf, fs::File)> {
    let dir = path
        .parent()
        .context("Failed to determine parent directory")?;
    let filename = path.file_name().context("Failed to determine filename")?;

    loop {
        let rand = fastrand::u16(..);
        let new_filename = format!("{}.{rand}", filename.to_string_lossy());
        let new_path = dir.join(new_filename);
        debug!("Trying path for new file: {new_path:?}");

        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o750)
            .open(&new_path)
            .await
        {
            Ok(file) => return Ok((new_path, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => (),
            Err(err) => return Err(err.into()),
        }
    }
}

async fn update_if_needed(exe: &Path, fp: &str, current: &str) -> Result<Option<String>> {
    let latest_exe = query_latest_exe(exe, fp).await?;
    if latest_exe.is_empty() {
        debug!("Could not find any exe yet, keep using what we have for now");
        return Ok(None);
    }

    let new_sha256 = sha256(&latest_exe);
    if new_sha256 == current {
        debug!("Already at most recent exe");
        return Ok(None);
    }

    let exe = fs::canonicalize(exe).await?;
    let (new_exe, mut file) = random_suffix(&exe)
        .await
        .context("Failed to create new file for exe update")?;
    info!("Using path for new file: {new_exe:?}");
    file.write_all(&latest_exe).await?;
    file.flush().await?;
    drop(file);

    fs::rename(new_exe, exe)
        .await
        .context("Failed to move new exe into place")?;

    Ok(Some(new_sha256))
}

async fn run(
    args: &Args,
    mut current_exe: String,
    child_slot: &mut Option<process::Child>,
) -> Result<Infallible> {
    info!("Started with current exe = {current_exe}");

    let mut interval = time::interval(LATEST_CHECK_INTERVAL);
    interval.reset();
    loop {
        if let Some(update) = update_if_needed(&args.exe, &args.fp, &current_exe).await? {
            info!("Updated to new exe = {update}");
            current_exe = update;
            if let Some(mut child) = child_slot.take() {
                child.kill().await?;
            }
        }

        let child = if let Some(child) = child_slot {
            child
        } else {
            let mut argv = vec!["p2p"];
            argv.extend(args.args.iter().map(|a| a.as_str()));
            info!("Spawning new p2p child process: {:?} {:?}", args.exe, argv);
            child_slot.insert(
                Command::new(&args.exe)
                    .args(argv)
                    .spawn()
                    .context("Failed to execute apt-swarm binary")?,
            )
        };

        tokio::select! {
            exit = child.wait() => {
                info!("Background child has exited: {exit:?}");
                *child_slot = None;
            }
            _ = interval.tick() => (),
        }
    }
}

#[tokio::main]
async fn main() -> Result<Infallible> {
    let args = Args::parse();
    env_logger::init_from_env(Env::default().default_filter_or(match args.verbose {
        0 => "info",
        _ => "debug",
    }));

    debug!("Reading current exe...");
    let current_exe = sha256(&fs::read(&args.exe).await?);

    let mut child_slot = None;
    let exit = run(&args, current_exe, &mut child_slot).await;
    if let Some(mut child) = child_slot {
        child.kill().await.ok();
    }
    exit
}
