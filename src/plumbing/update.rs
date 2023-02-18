use crate::args::ContainerUpdateCheck;
use crate::errors::*;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct CraneOutput {
    pub config: ContainerConfig,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ContainerConfig {
    #[serde(rename = "Env")]
    pub env: Vec<String>,
}

pub async fn check(update: &ContainerUpdateCheck) -> Result<()> {
    debug!("Checking updates for container image: {:?}", update.image);

    if update.commit.is_empty() {
        bail!("The currently running commit is not configured: {:?}", update.commit);
    }

    let output = Command::new("crane")
        .arg("config")
        .arg("--")
        .arg(&update.image)
        .output()
        .await
        .context("Failed to execute crane")?;

    if !output.stderr.is_empty() {
        let error = String::from_utf8_lossy(&output.stderr);
        warn!("Crane stderr was non-emtpy: {:?}", error);
    }

    if !output.status.success() {
        bail!("Crane exited with error: {:?}", output.status);
    }

    let output = serde_json::from_slice::<CraneOutput>(&output.stdout)
        .context("Failed to deserialize crane output")?;

    for env in &output.config.env {
        trace!("Found environment variable in container image: {:?}", env);
        if let Some(commit) = env.strip_prefix("UPDATE_CHECK_COMMIT=") {
            debug!("Found commit in container image: {commit:?}");
            if commit == update.commit {
                info!(
                    "We're running the latest version according to {:?} (commit={:?})",
                    update.image, commit
                );
            } else {
                info!(
                    "We're running an outdated version (current={:?}, latest={:?})",
                    update.commit, commit
                );
            }
        }
    }
    Ok(())
}
