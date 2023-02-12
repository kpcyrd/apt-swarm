use crate::errors::*;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::parse::{PacketParser, Parse};
use sequoia_openpgp::{Cert, Fingerprint, KeyHandle, KeyID};

#[derive(Debug, Clone)]
pub struct SigningKey {
    pub fingerprint: sequoia_openpgp::Fingerprint,
    pub cert: Cert,
    pub uids: Vec<String>,
    pub key_handles: Vec<(KeyHandle, Fingerprint)>,
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
        };

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
