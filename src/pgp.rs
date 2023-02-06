use crate::errors::*;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::parse::PacketParser;
use sequoia_openpgp::parse::Parse;

pub fn load(keyring: &[u8]) -> Result<()> {
    let ppr = PacketParser::from_bytes(&keyring)?;

    for certo in CertParser::from(ppr) {
        match certo {
            Ok(cert) => {
                println!("Key: {}", cert.fingerprint());
                for ua in cert.userids() {
                    println!("  User ID: {}", ua.userid());
                }
            }
            Err(err) => {
                eprintln!("Error reading keyring: {err:#}");
            }
        }
    }

    Ok(())
}
