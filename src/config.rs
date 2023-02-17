use crate::args::Args;
use crate::errors::*;
use crate::signed::Signed;
use bstr::BString;
use bytes::Bytes;
use sequoia_openpgp::armor;
use serde::{Deserialize, Serialize};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "repository", default)]
    pub repositories: Vec<Repository>,
}

impl Config {
    pub fn load_config_from_str(buf: &str) -> Result<Self> {
        let config = toml::from_str(buf)?;
        Ok(config)
    }

    pub async fn load_config_from(path: &Path) -> Result<Self> {
        if path.to_str() == Some("#") {
            debug!("Config loading has been explicitly disabled, using default config");
            Ok(Config::default())
        } else {
            let buf = fs::read_to_string(&path).await?;
            Self::load_config_from_str(&buf)
        }
    }

    pub async fn load_with_args(args: &Args) -> Result<Self> {
        let config = if let Some(path) = &args.config {
            Self::load_config_from(path)
                .await
                .with_context(|| anyhow!("Failed to load configuration from {:?}", path))?
        } else {
            for path in [Self::config_path(), Ok("/etc/apt-swarm.conf".into())]
                .into_iter()
                .flatten()
            {
                match fs::read_to_string(&path).await {
                    Ok(buf) => {
                        debug!("Using configuration from {:?}", path);
                        return Self::load_config_from_str(&buf);
                    }
                    Err(err) => {
                        debug!("Attempt to read config from {path:?} failed: {err:#}");
                    }
                }
            }
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
        let path = data_dir.join("storage");
        Ok(path)
    }

    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir().context("Failed to detect config directory")?;
        let path = config_dir.join("apt-swarm.conf");
        Ok(path)
    }
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Repository {
    pub urls: Vec<UrlSource>,
    pub keyring: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UrlSource {
    Url(String),
    Detached { content: String, sig: String },
}

impl UrlSource {
    pub async fn fetch(&self, client: &reqwest::Client) -> Result<Signed> {
        match self {
            UrlSource::Url(url) => {
                let body = Self::fetch_data(client, url).await?;

                let (signed, _remaining) = Signed::from_bytes(&body)
                    .context("Failed to parse http response as release")?;

                Ok(signed)
            }
            UrlSource::Detached { content, sig } => {
                let content = Self::fetch_data(client, content).await?;
                if !content.ends_with(b"\n") {
                    bail!("Detached signatures are currently only supported if the signed data ends with a newline");
                }
                let sig = Self::fetch_data(client, sig).await?;

                let mut reader = armor::Reader::from_bytes(
                    &sig,
                    armor::ReaderMode::Tolerant(Some(armor::Kind::Signature)),
                );

                let mut signature = Vec::new();
                reader.read_to_end(&mut signature)?;

                Ok(Signed {
                    content: BString::new(content.into()),
                    signature,
                })
            }
        }
    }

    async fn fetch_data(client: &reqwest::Client, url: &str) -> Result<Bytes> {
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
        Ok(body)
    }
}
