use crate::config::Config;
use crate::errors::*;
use crate::pgp;
use sequoia_openpgp::{Fingerprint, KeyID};
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct Keyring {
    pub keys: BTreeMap<Fingerprint, pgp::SigningKey>,
    pub identifiers: BTreeMap<String, Fingerprint>,
}

impl Keyring {
    pub fn load(config: &Config) -> Result<Self> {
        let mut keyring = Keyring::default();
        for repository in &config.repositories {
            let keys = pgp::load(repository.keyring.as_bytes())?;
            for key in keys {
                let fingerprint = key.fingerprint.clone();
                keyring.register_fingerprint(&fingerprint);
                keyring.keys.insert(fingerprint, key);
            }
        }
        Ok(keyring)
    }

    pub fn register_fingerprint(&mut self, fp: &Fingerprint) {
        self.identifiers
            .insert(KeyID::from(fp).to_string(), fp.clone());
        self.identifiers.insert(fp.to_string(), fp.clone());
    }
}
