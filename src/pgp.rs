use crate::errors::*;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::packet::key::{PrimaryRole, PublicParts};
use sequoia_openpgp::parse::{PacketParser, Parse};
use sequoia_openpgp::KeyID;

#[derive(Debug)]
pub struct SigningKey {
    pub fingerprint: sequoia_openpgp::Fingerprint,
    pub keyid: KeyID,
    pub hex_fingerprint: String,
    pub uids: Vec<String>,
    pub keys: Vec<sequoia_openpgp::packet::Key<PublicParts, PrimaryRole>>,
}

pub fn load(keyring: &[u8]) -> Result<Vec<SigningKey>> {
    let ppr = PacketParser::from_bytes(&keyring)?;

    let mut out = Vec::new();
    for certo in CertParser::from(ppr) {
        let cert = certo.context("Error reading pgp key")?;

        let fingerprint = cert.fingerprint();
        let keyid = KeyID::from(&fingerprint);
        let hex_fingerprint = format!("{:X}", fingerprint);
        let keys = vec![cert.primary_key().key().to_owned()];

        let mut uids = Vec::new();
        for ua in cert.userids() {
            uids.push(ua.userid().to_string());
        }
        out.push(SigningKey {
            fingerprint,
            keyid,
            hex_fingerprint,
            uids,
            keys,
        });
    }

    Ok(out)
}
