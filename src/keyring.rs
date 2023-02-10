use crate::errors::*;
use crate::config::Config;
use crate::pgp;

#[derive(Debug, Default)]
pub struct Keyring {
    pub keys: Vec<pgp::SigningKey>,
}

impl Keyring {
    pub fn load(config: &Config) -> Result<Self> {
        let mut keyring = Keyring::default();
        for repository in &config.repositories {
            let keys = pgp::load(repository.keyring.as_bytes())?;
            keyring.keys.extend(keys);
        }
        Ok(keyring)
    }
}
