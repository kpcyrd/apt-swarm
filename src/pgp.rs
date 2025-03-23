use crate::errors::*;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::parse::{PacketParser, Parse};
use sequoia_openpgp::policy::NullPolicy;
use sequoia_openpgp::{Cert, Fingerprint, KeyHandle, KeyID};

#[derive(Debug, Clone)]
pub struct Subkey {
    pub fingerprint: sequoia_openpgp::Fingerprint,
    pub is_primary: bool,
    pub for_authentication: bool,
    pub for_certification: bool,
    pub for_signing: bool,
    pub for_storage_encryption: bool,
    pub for_transport_encryption: bool,
}

#[derive(Debug, Clone)]
pub struct SigningKey {
    pub fingerprint: sequoia_openpgp::Fingerprint,
    pub cert: Cert,
    pub uids: Vec<String>,
    pub key_handles: Vec<(KeyHandle, Fingerprint)>,
    pub subkeys: Vec<Subkey>,
}

impl SigningKey {
    pub fn hex_fingerprint(&self) -> String {
        format!("{:X}", self.fingerprint)
    }

    pub fn register_keyhandles(&mut self, fp: Fingerprint) {
        let keyid = KeyID::from(&fp);
        self.key_handles.push((KeyHandle::KeyID(keyid), fp.clone()));
        self.key_handles
            .push((KeyHandle::Fingerprint(fp.clone()), fp));
    }
}

pub fn load(keyring: &[u8]) -> Result<Vec<SigningKey>> {
    let ppr = PacketParser::from_bytes(&keyring)?;

    let mut out = Vec::new();
    for certo in CertParser::from(ppr) {
        let cert = certo.context("Error reading pgp key")?;

        let fingerprint = cert.fingerprint();

        let mut signing_key = SigningKey {
            fingerprint,
            cert: cert.clone(),
            uids: Vec::new(),
            key_handles: Vec::new(),
            subkeys: Vec::new(),
        };

        let p = unsafe { &NullPolicy::new() };
        for key in cert.keys().with_policy(p, None) {
            let fingerprint = key.key().fingerprint();

            // TODO: we should probably also track and display encryption-only keys, for transparency
            if key.for_signing() {
                signing_key.register_keyhandles(fingerprint.clone());
            }

            signing_key.subkeys.push(Subkey {
                fingerprint,
                is_primary: key.primary(),
                for_authentication: key.for_authentication(),
                for_certification: key.for_certification(),
                for_signing: key.for_signing(),
                for_storage_encryption: key.for_storage_encryption(),
                for_transport_encryption: key.for_transport_encryption(),
            });
        }

        for ua in cert.userids() {
            signing_key.uids.push(ua.userid().to_string());
        }

        out.push(signing_key);
    }

    Ok(out)
}
