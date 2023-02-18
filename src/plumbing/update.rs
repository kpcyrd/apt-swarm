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

pub enum Updates {
    Available { current: String, latest: String },
    AlreadyLatest { commit: String },
}

pub async fn check(update: &ContainerUpdateCheck) -> Result<Updates> {
    debug!("Checking updates for container image: {:?}", update.image);

    if update.commit.is_empty() {
        bail!(
            "The currently running commit is not configured: {:?}",
            update.commit
        );
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
                debug!(
                    "Update check detected we're running the latest version of {:?} (commit={:?}",
                    update.image, commit
                );
                return Ok(Updates::AlreadyLatest {
                    commit: commit.to_string(),
                });
            } else {
                debug!("Update check detected we're running an outdated version of {:?} (current={:?}, latest={:?})",
                    update.image,
                    update.commit, commit
                );
                return Ok(Updates::Available {
                    current: update.commit.to_string(),
                    latest: commit.to_string(),
                });
            }
        }
    }

    bail!(
        "Failed to detect commit id in specified container image: {:?}",
        update.image
    );
}
