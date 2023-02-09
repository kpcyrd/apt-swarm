use crate::errors::*;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::parse::PacketParser;
use sequoia_openpgp::parse::Parse;

#[derive(Debug)]
pub struct SigningKey {
    pub fingerprint: String,
    pub uids: Vec<String>,
}

pub fn load(keyring: &[u8]) -> Result<Vec<SigningKey>> {
    let ppr = PacketParser::from_bytes(&keyring)?;

    let mut keys = Vec::new();
    for certo in CertParser::from(ppr) {
        let cert = certo.context("Error reading pgp key")?;

        let fingerprint = cert.fingerprint().to_string();
        let mut uids = Vec::new();
        for ua in cert.userids() {
            uids.push(ua.userid().to_string());
        }
        keys.push(SigningKey { fingerprint, uids });
    }

    Ok(keys)
}
