use crate::config::Config;
use crate::errors::*;
use crate::pgp;
use crate::pgp::SigningKey;
use memchr::memchr;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::types::SignatureType;
use sequoia_openpgp::Fingerprint;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Subkey {
    pub parent: Fingerprint,
    pub fingerprint: Fingerprint,
}

#[derive(Debug, Default, Clone)]
pub struct Keyring {
    pub keys: BTreeMap<Fingerprint, pgp::SigningKey>,
    pub identifiers: BTreeMap<String, Subkey>,
}

impl Keyring {
    pub fn load(config: &Config) -> Result<Self> {
        let mut keyring = Keyring::default();
        for repository in &config.data.repositories {
            keyring.add_keyring(repository.keyring.as_bytes())?;
        }
        Ok(keyring)
    }

    pub fn new(keyring: &[u8]) -> Result<Self> {
        let mut k = Keyring::default();
        k.add_keyring(keyring)?;
        Ok(k)
    }

    pub fn add_keyring(&mut self, keyring: &[u8]) -> Result<()> {
        let keys = pgp::load(keyring)?;
        for key in keys {
            self.register_identifiers(&key);
            let fingerprint = key.fingerprint.clone();
            self.keys.insert(fingerprint, key);
        }
        Ok(())
    }

    pub fn register_identifiers(&mut self, key: &SigningKey) {
        for (id, fp) in &key.key_handles {
            let id = id.to_string();
            trace!("Linking identifier for key {:X}: {id:?}", key.fingerprint);
            self.identifiers.insert(
                id,
                Subkey {
                    parent: key.fingerprint.clone(),
                    fingerprint: fp.clone(),
                },
            );
        }
    }

    pub fn find_signing_key(&self, sig: &Signature) -> Result<(&Fingerprint, &SigningKey)> {
        for issuer in sig.get_issuers() {
            debug!("Found issuer in signature packet: {issuer:?}");
            if let Some(subkey) = self.identifiers.get(&issuer.to_string()) {
                debug!("Found fingerprint for given issuer: {:?}", subkey.parent);
                let key = self.keys.get(&subkey.parent).with_context(|| {
                    anyhow!(
                        "Failed to get signing key by fingerprint: {:?}",
                        subkey.parent
                    )
                })?;
                return Ok((&subkey.fingerprint, key));
            }
        }
        bail!("Could not find key for given signature")
    }

    // TODO: this function normalizes data, this should be taken into account
    pub fn verify(&self, data: &[u8], sig: &Signature) -> Result<Fingerprint> {
        let (signer_fp, signing_key) = self.find_signing_key(sig)?;

        let body: Cow<[u8]> = match sig.typ() {
            SignatureType::Binary => Cow::Borrowed(data),
            SignatureType::Text => {
                let mut out = Vec::new();

                let mut bytes = data;
                while !bytes.is_empty() {
                    if let Some(idx) = memchr(b'\n', bytes) {
                        let line = &bytes[..idx];
                        // TODO: this could be a `\r\n` newline, do we need to check for `\r`?
                        bytes = &bytes[idx + 1..];

                        out.extend(line);
                        if !bytes.is_empty() {
                            out.extend(b"\r\n");
                        }
                    } else {
                        out.extend(bytes);
                        bytes = &[];
                    }
                }

                Cow::Owned(out)
            }
            unsupported => bail!("Unsupported signature type: {unsupported:?}"),
        };

        for key in signing_key.cert.keys() {
            let key = key.key();

            // TODO: are we sure the issuer fingerprint is always pointing to the right key?
            let key_fp = key.fingerprint();
            debug!("Attempting verification with {:X}", key_fp);
            if key_fp != *signer_fp {
                debug!("This key was not the issuer, skipping: {:?}", key_fp);
                continue;
            }

            sig.clone()
                .verify_message(key, &body)
                .context("Failed to verify message")?;
            debug!("Successfully verified signature");
            return Ok(key_fp);
        }

        bail!("Signature could not be verified with any of the pgp certificates public keys")
    }

    pub fn generate_report(&self) -> Result<KeyringReport> {
        Ok(KeyringReport {
            keys: self.keys.values().map(KeyReport::generate).collect(),
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyringReport {
    pub keys: Vec<KeyReport>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyReport {
    pub primary_fingerprint: String,
    pub uids: Vec<String>,
    pub subkeys: Vec<SubkeyReport>,
}

impl KeyReport {
    pub fn generate(key: &pgp::SigningKey) -> Self {
        KeyReport {
            primary_fingerprint: format!("{:X}", key.fingerprint),
            uids: key.uids.clone(),
            subkeys: key.subkeys.iter().map(SubkeyReport::generate).collect(),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SubkeyReport {
    pub fingerprint: String,
    pub is_primary: bool,
    pub for_authentication: bool,
    pub for_certification: bool,
    pub for_signing: bool,
    pub for_storage_encryption: bool,
    pub for_transport_encryption: bool,
}

impl SubkeyReport {
    pub fn generate(key: &pgp::Subkey) -> Self {
        SubkeyReport {
            fingerprint: format!("{:X}", key.fingerprint),
            is_primary: key.is_primary,
            for_authentication: key.for_authentication,
            for_certification: key.for_certification,
            for_signing: key.for_signing,
            for_storage_encryption: key.for_storage_encryption,
            for_transport_encryption: key.for_transport_encryption,
        }
    }
}
