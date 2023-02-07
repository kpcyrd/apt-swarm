use crate::args::Args;
use crate::errors::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "repository", default)]
    pub repositories: Vec<Repository>,
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Repository {
    pub urls: Vec<String>,
    pub keyring: String,
}

impl Config {
    pub async fn load_config_from(path: &Path) -> Result<Self> {
        let buf = fs::read_to_string(&path).await?;
        let config = toml::from_str(&buf)?;
        Ok(config)
    }

    pub async fn load_with_args(args: &Args) -> Result<Self> {
        let config = if let Some(path) = &args.config {
            Self::load_config_from(path)
                .await
                .with_context(|| anyhow!("Failed to load configuration from {:?}", path))?
        } else {
            Config::default()
        };

        Ok(config)
    }

    pub fn apt_swarm_path(&self) -> Result<PathBuf> {
        let data_dir = dirs::data_dir().context("Failed to detect data directory")?;
        let path = data_dir.join("apt-swarm");
        Ok(path)
    }

    pub fn database_path(&self) -> Result<PathBuf> {
        let data_dir = self.apt_swarm_path()?;
        let path = data_dir.join("db");
        Ok(path)
    }
}
