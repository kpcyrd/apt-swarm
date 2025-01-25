use crate::args::Args;
use crate::errors::*;
use crate::signed::Signed;
use bstr::BString;
use bytes::Bytes;
use sequoia_openpgp::armor;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug, PartialEq, Default)]
pub struct Config {
    pub data: ConfigData,
    pub config_path: Option<PathBuf>,
    pub data_path: Option<PathBuf>,
}

impl Config {
    pub async fn load_with_args(args: &Args) -> Result<Self> {
        let (config_path, data) = if let Some(path) = &args.config {
            if path.to_str() == Some("#") {
                debug!("Config loading has been explicitly disabled, using default config");
                (None, ConfigData::default())
            } else {
                let data = ConfigData::load_config_from(path)
                    .await
                    .with_context(|| anyhow!("Failed to load configuration from {:?}", path))?;
                (Some(path.to_owned()), data)
            }
        } else if let Some((path, buf)) = Self::find_config().await {
            debug!("Using configuration from {:?}", path);
            let data = ConfigData::load_config_from_str(&buf)?;
            (Some(path), data)
        } else {
            (None, ConfigData::default())
        };

        Ok(Config {
            data,
            config_path,
            data_path: args.data_path.clone(),
        })
    }

    async fn find_config() -> Option<(PathBuf, String)> {
        for path in [
            Self::default_config_path(),
            Ok("/etc/apt-swarm.conf".into()),
        ]
        .into_iter()
        .flatten()
        {
            match fs::read_to_string(&path).await {
                Ok(buf) => return Some((path, buf)),
                Err(err) => {
                    debug!("Attempt to read config from {path:?} failed: {err:#}");
                }
            }
        }

        None
    }

    pub fn apt_swarm_path(&self) -> Result<Cow<PathBuf>> {
        let path = if let Some(path) = &self.data_path {
            Cow::Borrowed(path)
        } else {
            let data_dir = dirs::data_dir().context("Failed to detect data directory")?;
            let path = data_dir.join("apt-swarm");
            Cow::Owned(path)
        };

        Ok(path)
    }

    pub fn arti_path(&self) -> Result<PathBuf> {
        let data_dir = self.apt_swarm_path()?;
        let path = data_dir.join("arti");
        Ok(path)
    }

    pub fn database_path(&self) -> Result<PathBuf> {
        let data_dir = self.apt_swarm_path()?;
        let path = data_dir.join("storage");
        Ok(path)
    }

    pub fn database_migrate_path(&self) -> Result<PathBuf> {
        let data_dir = self.apt_swarm_path()?;
        let path = data_dir.join("storage~");
        Ok(path)
    }

    pub fn database_delete_path(&self) -> Result<PathBuf> {
        let data_dir = self.apt_swarm_path()?;
        let path = data_dir.join("storage=");
        Ok(path)
    }

    pub fn db_socket_path(&self) -> Result<PathBuf> {
        let data_dir = self.apt_swarm_path()?;
        let path = data_dir.join("db.sock");
        Ok(path)
    }

    fn default_config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir().context("Failed to detect config directory")?;
        let path = config_dir.join("apt-swarm.conf");
        Ok(path)
    }

    pub fn peerdb_path(&self) -> Result<PathBuf> {
        let data_dir = self.apt_swarm_path()?;
        let path = data_dir.join("peerdb.json");
        Ok(path)
    }

    pub fn peerdb_new_path(&self) -> Result<PathBuf> {
        let data_dir = self.apt_swarm_path()?;
        let path = data_dir.join("peerdb.json-");
        Ok(path)
    }
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct ConfigData {
    #[serde(rename = "repository", default)]
    pub repositories: Vec<Repository>,
}

impl ConfigData {
    pub fn load_config_from_str(buf: &str) -> Result<Self> {
        let config = toml::from_str(buf)?;
        Ok(config)
    }

    pub async fn load_config_from(path: &Path) -> Result<Self> {
        let buf = fs::read_to_string(&path).await?;
        Self::load_config_from_str(&buf)
    }
}

#[derive(Debug, PartialEq, Default, Clone, Serialize, Deserialize)]
pub struct Repository {
    #[serde(default)]
    pub urls: Vec<UrlSource>,
    pub keyring: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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
