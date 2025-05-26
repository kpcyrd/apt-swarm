use crate::args::Args;
use crate::errors::*;
use crate::keyring::Keyring;
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

impl Repository {
    pub fn contains_fingerprint(&self, fingerprints: &[sequoia_openpgp::Fingerprint]) -> bool {
        let Ok(keyring) = Keyring::new(self.keyring.as_bytes()) else {
            return false;
        };
        fingerprints.iter().any(|fp| keyring.get(fp).is_some())
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UrlSource {
    Url(String),
    Detached { content: String, sig: String },
}

impl UrlSource {
    pub async fn fetch(&self, client: &reqwest::Client) -> Result<Vec<Signed>> {
        match self {
            UrlSource::Url(url) => {
                let body = Self::fetch_data(client, url).await?;

                let signed = Signed::find_all_in_text(&body)
                    .context("Failed to parse signed message from http response")?;

                if signed.is_empty() {
                    bail!("Failed to find any signed data in http response");
                }

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

                Ok(vec![Signed {
                    content: BString::new(content.into()),
                    signature,
                }])
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEYRING: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBFjlSicBEACgho//0EzxuvuCn01LwFqGAgwPKcSSl4L+AWws5/YbsZZvmTBk
ggIiVOCIMh+d3cmGu5W3ydaeUbWbFGNsxO44EB5YBZcuLa5EzRKbNPVaOXKXmhp+
w0mEbkoKbF+3mz3lifwBnzcBpukyJDgcJSq8cXfq5JsDPR1KAL6ph/kwKeiDNg+8
oFgqfboukK56yPTYc9iM8hkTFdx9L6JCJaZGaDMfihoQm2caKAmqc+TlpgtKbBL0
t5hrzDpCPpJvCddu1NRysTcqfACSSocvoqY0dlbNPMN8j04LH8hcKGFipuLdI8qx
BFqlMIQJCVJhr05E8rEsI4nYEyG44YoPopTFLuQa+wewZsQkLwcfYeCecU1KxlpE
OI3xRtALJjA/C/AzUXVXsWn7Xpcble8i3CKkm5LgX5zvR6OxTbmBUmpNgKQiyxD6
TrP3uADm+0P6e8sJQtA7DlxZLA6HuSi+SQ2WNcuyLL3Q/lJE0qBRWVJ08nI9vvxR
vAs20LKxq+D1NDhZ2jfG2+5agY661fkx66CZNFdz5OgxJih1UXlwiHpn6qhP7Rub
OJ54CFb+EwyzDVVKj3EyIZ1FeN/0I8a0WZV6+Y/p08DsDLcKgqcDtK01ydWYP0tA
o1S2Z7Jsgya50W7ZuP/VkobDqhOmE0HDPggX3zEpXrZKuMnRAcz6Bgi6lwARAQAB
tDFPcGVuIFdoaXNwZXIgU3lzdGVtcyA8c3VwcG9ydEB3aGlzcGVyc3lzdGVtcy5v
cmc+iQI3BBMBCgAhBQJY5UonAhsDBQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJ
ENmAoXRX9vsGU00P/RBPPc5qx1EljTW3nnTtgugORrJhYl1CxNvrohVovAF4oP1b
UIGT5/3FoDsxJHSEIvorPFSaG2+3CBhMB1k950Ig2c2n+PTnNk6D0YIUbbEI0KTX
nLbCskdpy/+ICiaLfJZMe11wcQpkoNbG587JdQwnGegbQoo580CTSsYMdnvGzC8A
l1F7r37RVZToJMGgfMKK3oz8xIDXqOe5oiiKcV36tZ5V/PCDAu0hXYBRchtqHlHP
cKWeRTb1aDkbQ7SPlJ2bSvUjFdB6KahlSGJl3nIU5zAH2LA/tUQY16Z1QaJmfkEb
RY61B/LPv1TaA1SIUW32ej0NmeF09Ze4Cggdkacxv6E+CaBVbz5rLh6m91acBibm
pJdGWdZyQU90wYFRbSsqdDNB+0DvJy6AUg4e5f79JYDWT/Szdr0TLKmdPXOxa1Mb
i34UebYI7WF7q22e7AphpO/JbHcD+N6yYtN6FkUAmJskGkkgYzsM/G8OEbBRS7A+
eg3+NdQRFhKa7D7nIuufXDOTMUUkUqNYLC+qvZVPJrWnK9ZsGKsP0EUZTfEGkmEN
UzmASxyMMe6JHmm5Alk4evJeQ31U5jy7ntZSWEV1pSGmSEJLRNJtycciFJpsEp/p
LkL0iFb30R9bHBp6cg7gjXbqZ9ZpEsxtZMBuqS70ZZyQdu2yGDQCBk7eLKCjuQIN
BFjlSicBEACsxCLVUE7UuxsEjNblTpSEysoTD6ojc2nWP/eCiII5g6SwA/tQKiQI
ZcGZsTZB9kTbCw4T3hVEmzPl6u2G6sY9Kh1NHKMR3jXvMC+FHODhOGyAOPERjHCJ
g20XF2/Gg462iW8e3lS7CQBzbplUCW/oMajj2Qkc61NLtxxzsssXjCKExub2HxCQ
AYtenuDtLU73G75BoghWJ19dIkodnEI0/fzccsgiP5xeVgmkWJPo9xKJtrBS5gcS
s7yaGY9YYo71RFzkpJpeAeLrJJqt+2KqH1u0EJUbs8YVGXKlnYeSNisg4OaRsldW
JmDDCD5WUdFq2LNdVisfwirgjmwYpLrzVMbmzPvdmxQ1NYzJsX4ARSL/wuKCvEub
gh1AR5oV7mUEA9I3KRH0TIDOnH4nGG3kqArzrV2E1WtnNzFII0IN9/48xY7Vkxs7
Oil+E+wCpzUv/tF4ALx5TAXoPd66ddEOxzDrtBpEzsouszt7uUyncyT3X6ip5l9f
mI4uxbsjwkLVfd1WpD1uvp869oyx6wtHluswr1VY/cbnHO8J6J35JVMhYQdMOaTZ
rX6npe/YOHJ4a7YzLMfdrxyzK1wq5xu/9LgclMTdIhAKvnaXBg41jsid5n0GdIeW
ek8WAVNyvuvoTwm3GG6+/pkTwu0J79lAMD1mhJsuSca6SFNgYnd+PQARAQABiQIf
BBgBCgAJBQJY5UonAhsMAAoJENmAoXRX9vsGvRgQAJ4tWnK2TncCpu5nTCxYMXjW
LuvwORq8EBWczHS6SjLdwmSVKGKSYtl2n6nCkloVY6tONMoiCWmtcq7SJMJoyZw3
XIf82Z39tzn/conjQcP0aIOFzww1XG7YiaTAhsDZ62kchukI52jUYm2w8cTZMEZB
oIwIWBpmLlyaDhjIM5neY5RuL7IbIpS/fdk2lwfAwcNq6z/ri2E5RWl3AEINdLUO
gAiVMagNJaJ+ap7kMcwOLoI2GD84mmbtDWemdUZ3HnqLHv0mb1djsWL6LwjCuOgK
l2GDrWCh18mE+9mVB1Lo7jzYXNSHXQP6FlDE6FhGO1nNBs2IJzDvmewpnO+a/0pw
dCerATHWtrCKwMOHrbGLSiTKEjnNt/74gKjXxdFKQkpaEfMFCeiAOFP93tKjRRhP
5wf1JHBZ1r1+pgfZlS5F20XnM2+f/K1dWmgh+4Grx8pEHGQGLP+A22O7iWjg9pS+
LD3yikgyGGyQxgcN3sJBQ4yxakOUDZiljm3uNyklUMCiMjTvT/F02PalQMapvA5w
7Gwg5mSI8NDs3RtiG1rKl9Ytpdq7uHaStlHwGXBVfvayDDKnlpmndee2GBiU/hc2
ZsYHzEWKXME/ru6EZofUFxeVdev5+9ztYJBBZCGMug5Xp3Gxh/9JUWi6F1+9qAyz
N+O606NOXLwcmq5KZL0g
=zyVo
-----END PGP PUBLIC KEY BLOCK-----
";

    #[test]
    fn test_contains_fingerprint() {
        let repo = Repository {
            urls: vec![],
            keyring: KEYRING.to_string(),
        };

        // Test with matching fingerprint
        let fingerprints = vec!["DBA36B5181D0C816F630E889D980A17457F6FB06"
            .parse::<sequoia_openpgp::Fingerprint>()
            .unwrap()];
        assert!(repo.contains_fingerprint(&fingerprints));

        // Test with non-matching fingerprint (Debian bookworm keys)
        let fingerprints = vec![
            "4D64FEC119C2029067D6E791F8D2585B8783D481"
                .parse::<sequoia_openpgp::Fingerprint>()
                .unwrap(),
            "05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0"
                .parse::<sequoia_openpgp::Fingerprint>()
                .unwrap(),
        ];
        assert!(!repo.contains_fingerprint(&fingerprints));

        // Test with matching and non-matching fingerprints
        let fingerprints = vec![
            "4D64FEC119C2029067D6E791F8D2585B8783D481"
                .parse::<sequoia_openpgp::Fingerprint>()
                .unwrap(),
            "DBA36B5181D0C816F630E889D980A17457F6FB06"
                .parse::<sequoia_openpgp::Fingerprint>()
                .unwrap(),
            "05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0"
                .parse::<sequoia_openpgp::Fingerprint>()
                .unwrap(),
        ];
        assert!(repo.contains_fingerprint(&fingerprints));

        // Test with an empty fingerprint list
        assert!(!repo.contains_fingerprint(&[]));
    }
}
