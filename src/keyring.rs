use crate::config::Config;
use crate::errors::*;
use crate::pgp;
use crate::pgp::SigningKey;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::Fingerprint;
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
                keyring.register_identifiers(&key);
                let fingerprint = key.fingerprint.clone();
                keyring.keys.insert(fingerprint, key);
            }
        }
        Ok(keyring)
    }

    pub fn register_identifiers(&mut self, key: &SigningKey) {
        for id in &key.key_handles {
            let id = id.to_string();
            debug!("Linking identifier for key {:X}: {id:?}", key.fingerprint);
            self.identifiers
                .insert(id, key.fingerprint.clone());
        }
    }

    pub fn find_key(&self, sig: &Signature) -> Result<&SigningKey> {
        for issuer in sig.get_issuers() {
            debug!("Found issuer in signature packet: {issuer:?}");
            if let Some(fp) = self.identifiers.get(&issuer.to_string()) {
                debug!("Found fingerprint for given issuer: {fp:?}");
                let key = self
                    .keys
                    .get(fp)
                    .with_context(|| anyhow!("Failed to get signing key by fingerprint: {fp:?}"))?;
                return Ok(key);
            }
        }
        bail!("Could not find key for given signature")
    }

    pub fn verify(&self, data: &[u8], sig: &Signature) -> Result<()> {
        let key = self.find_key(sig)?;
        for key in &key.keys {
            let mut sig = sig.clone();
            if let Ok(()) = sig.verify_message(key, data) {
                debug!("Successfully verified signature with key {:?}", key);
                return Ok(());
            }
        }
        bail!("Signature could not be verified with any of the pgp certificates public keys")
    }
}
