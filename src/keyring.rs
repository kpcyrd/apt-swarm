use crate::config::Config;
use crate::errors::*;
use crate::pgp;
use crate::pgp::SigningKey;
use memchr::memchr;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::types::SignatureType;
use sequoia_openpgp::Fingerprint;
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct Subkey {
    pub parent: Fingerprint,
    pub fingerprint: Fingerprint,
}

#[derive(Debug, Default)]
pub struct Keyring {
    pub keys: BTreeMap<Fingerprint, pgp::SigningKey>,
    pub identifiers: BTreeMap<String, Subkey>,
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
    pub fn verify(&self, data: &[u8], sig: &Signature) -> Result<()> {
        let (fp, signing_key) = self.find_signing_key(sig)?;

        let body: Vec<u8> = match sig.typ() {
            SignatureType::Binary => {
                bail!("Signatures over binary data are not supported yet");
            }
            SignatureType::Text => {
                let mut out = Vec::new();
                let mut past_headers = false;

                let mut bytes = data;
                while !bytes.is_empty() {
                    if let Some(idx) = memchr(b'\n', bytes) {
                        let line = &bytes[..idx];
                        // TODO: this could be a `\r\n` newline, do we need to check for `\r`?
                        bytes = &bytes[idx + 1..];

                        if !past_headers {
                            if line.is_empty() {
                                past_headers = true;
                            }
                            continue;
                        }

                        out.extend(line);
                        if !bytes.is_empty() {
                            out.extend(b"\r\n");
                        }
                    } else {
                        out.extend(bytes);
                        bytes = &[];
                    }
                }

                out
            }
            unsupported => bail!("Unsupported signature type: {unsupported:?}"),
        };

        for key in signing_key.cert.keys() {
            let key = key.key();

            // TODO: are we sure the issuer fingerprint is always pointing to the right key?
            let key_fingerprint = key.fingerprint();
            debug!("Attempting verification with {:X}", key_fingerprint);
            if key_fingerprint != *fp {
                debug!(
                    "This key was not the issuer, skipping: {:?}",
                    key_fingerprint
                );
                continue;
            }

            sig.clone()
                .verify_message(key, &body)
                .context("Failed to verify message")?;
            debug!("Successfully verified signature");
            return Ok(());
        }

        bail!("Signature could not be verified with any of the pgp certificates public keys")
    }
}
