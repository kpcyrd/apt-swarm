use crate::errors::*;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::packet::key::{PrimaryRole, PublicParts};
use sequoia_openpgp::parse::{PacketParser, Parse};
use sequoia_openpgp::{Fingerprint, KeyHandle, KeyID};

#[derive(Debug)]
pub struct SigningKey {
    pub fingerprint: sequoia_openpgp::Fingerprint,
    pub uids: Vec<String>,
    pub key_handles: Vec<KeyHandle>,
    pub keys: Vec<sequoia_openpgp::packet::Key<PublicParts, PrimaryRole>>,
}

impl SigningKey {
    pub fn hex_fingerprint(&self) -> String {
        format!("{:X}", self.fingerprint)
    }

    pub fn register_keyhandles(&mut self, fp: Fingerprint) {
        let keyid = KeyID::from(&fp);
        self.key_handles.push(KeyHandle::KeyID(keyid));
        self.key_handles.push(KeyHandle::Fingerprint(fp));
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
            uids: Vec::new(),
            keys: Vec::new(),
            key_handles: Vec::new(),
        };

        // TODO: this is missing subkeys
        signing_key.keys.push(cert.primary_key().key().to_owned());

        for key in cert.keys() {
            signing_key.register_keyhandles(key.fingerprint());
        }

        for ua in cert.userids() {
            signing_key.uids.push(ua.userid().to_string());
        }

        out.push(signing_key);
    }

    Ok(out)
}
