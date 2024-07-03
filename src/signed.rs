use crate::errors::*;
use crate::keyring::Keyring;
use bstr::BString;
use memchr::memchr;
use sequoia_openpgp::armor;
use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};
use sequoia_openpgp::serialize::Serialize as _;
use sequoia_openpgp::Fingerprint;
use sequoia_openpgp::Packet;
use serde::{Deserialize, Serialize};
use std::io::prelude::*;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signed {
    pub content: bstr::BString,
    pub signature: Vec<u8>,
}

impl Signed {
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let mut bytes = bytes
            .strip_prefix(b"-----BEGIN PGP SIGNED MESSAGE-----\n")
            .context("InRelease is expected to start with `-----BEGIN PGP SIGNED MESSAGE-----`")?;

        loop {
            let pos = 1 + memchr(b'\n', bytes)
                .context("Failed to find end of cleartext signed message headers")?;
            let line = &bytes[..pos];
            bytes = &bytes[pos..];

            // if the line was empty it's the end of headers
            if line == b"\n" {
                break;
            }
        }

        let mut content = Vec::new();
        while !bytes.starts_with(b"-----BEGIN PGP SIGNATURE-----\n") {
            let pos = 1 + memchr(b'\n', bytes).context("Failed to find end of signed message")?;

            let line = &bytes[..pos];
            let line = line.strip_prefix(b"- ").unwrap_or(line);
            content.extend(line);

            bytes = &bytes[pos..];
        }

        let signature_start = bytes;
        let remaining = {
            let mut bytes = bytes;
            loop {
                if let Some(bytes) = bytes.strip_prefix(b"-----END PGP SIGNATURE-----\n") {
                    break bytes;
                } else if bytes == b"-----END PGP SIGNATURE-----" {
                    break b"";
                } else {
                    let pos =
                        1 + memchr(b'\n', bytes).context("Failed to find end of signed message")?;
                    bytes = &bytes[pos..];
                }
            }
        };
        let signature = &signature_start[..signature_start.len() - remaining.len()];

        let mut reader = armor::Reader::from_bytes(
            signature,
            armor::ReaderMode::Tolerant(Some(armor::Kind::Signature)),
        );

        let mut signature = Vec::new();
        reader.read_to_end(&mut signature)?;

        Ok((
            Signed {
                content: BString::from(content),
                signature,
            },
            remaining,
        ))
    }

    pub async fn from_reader<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut line = Vec::new();
        while line != b"-----BEGIN PGP SIGNED MESSAGE-----\n" {
            line.clear();
            let read = reader.read_until(b'\n', &mut line).await?;
            if read == 0 {
                bail!("Unexpected end of document: Failed to find `BEGIN PGP SIGNED MESSAGE`");
            }
        }

        while line != b"\n" {
            line.clear();
            let read = reader.read_until(b'\n', &mut line).await?;
            if read == 0 {
                bail!("Unexpected end of document: Failed to find end of clear-signed headers");
            }
        }

        let mut content = Vec::new();
        loop {
            line.clear();
            let read = reader.read_until(b'\n', &mut line).await?;
            if read == 0 {
                bail!("Unexpected end of document: Failed to find end of signed message");
            }

            if line == b"-----BEGIN PGP SIGNATURE-----\n" {
                break;
            }

            let line = line.strip_prefix(b"- ").unwrap_or(&line);
            content.extend(line);
        }

        let mut signature = line.to_vec();
        while line != b"-----END PGP SIGNATURE-----\n" {
            line.clear();
            let read = reader.read_until(b'\n', &mut line).await?;
            if read == 0 {
                // if we reached EOF, also accept `END PGP SIGNATURE` with no final newline
                if line != b"-----END PGP SIGNATURE-----" {
                    bail!("Unexpected end of document: Failed to find end of signature");
                }
            }

            signature.extend(&line);
        }

        let mut reader = armor::Reader::from_bytes(
            &signature,
            armor::ReaderMode::Tolerant(Some(armor::Kind::Signature)),
        );

        let mut signature = Vec::new();
        reader
            .read_to_end(&mut signature)
            .context("Failed to decode signature")?;

        Ok(Signed {
            content: BString::from(content),
            signature,
        })
    }

    pub fn to_clear_signed(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend(b"-----BEGIN PGP SIGNED MESSAGE-----\n\n");

        let mut bytes = self.content.as_slice();
        while let Some(mut pos) = memchr(b'\n', bytes) {
            pos += 1;

            let line = &bytes[..pos];
            if line.starts_with(b"-") {
                out.extend(b"- ");
            }

            out.extend(line);
            bytes = &bytes[pos..];
        }

        if !bytes.is_empty() {
            bail!("Message didn't end with \\n and that's currently not supported");
        }

        let mut writer = armor::Writer::new(&mut out, armor::Kind::Signature)?;
        writer.write_all(&self.signature)?;
        writer.finalize()?;

        Ok(out)
    }

    pub fn canonicalize(
        &self,
        keyring: Option<&Keyring>,
    ) -> Result<Vec<(Option<Fingerprint>, Signed)>> {
        let mut out = Vec::new();

        let mut ppr = PacketParser::from_bytes(&self.signature)?;
        while let PacketParserResult::Some(pp) = ppr {
            let (packet, next_ppr) = pp.recurse()?;
            ppr = next_ppr;
            debug!("Found packet in signature block: {packet:?}");
            if let Packet::Signature(sig) = &packet {
                let fingerprint = if let Some(keyring) = keyring {
                    match keyring.verify(&self.content, sig) {
                        Ok(fingerprint) => Some(fingerprint),
                        Err(err) => {
                            debug!(
                                "Signature could not be verified, dismissing signature packet: {err:#}"
                            );
                            continue;
                        }
                    }
                } else {
                    None
                };

                let mut signature = Vec::new();
                packet
                    .serialize(&mut signature)
                    .context("Failed to serialize OpenPGP packet")?;

                out.push((
                    fingerprint,
                    Signed {
                        content: self.content.clone(),
                        signature,
                    },
                ));
            } else {
                debug!("Unknown openpgp packet in signature block, dismissing: {packet:?}");
            }
        }

        if out.is_empty() {
            warn!("Failed to find any trusted signatures in input data");
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bstr::BStr;

    const IN_RELEASE: &[u8] = b"-----BEGIN PGP SIGNED MESSAGE-----

Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Thu, 2 Feb 2023 21:39:16 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 8550d0ce5fda03a2f3eb8c735a571bd5     4778 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
 2951333500c011d2b22c01de46d43223   128744 main/binary-amd64/Packages
 444ef6562bb0ffef2b40af15d2a1e10d    20921 main/binary-amd64/Packages.gz
 69ac9fed864b2f51c2a5fec9f8584724    17345 main/binary-amd64/Packages.bz2
SHA1:
 56bddab49c82340b09c4e83e469e4042061bffa4     4778 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
 c8be9dfb45580a4ff22f5afb0bff311458ae9dd7   128744 main/binary-amd64/Packages
 0c82b553b566704273b4be3e3e08326f9ce7f936    20921 main/binary-amd64/Packages.gz
 56e0d8810a31b18c6ae46001e08948fbffb20ebb    17345 main/binary-amd64/Packages.bz2
SHA256:
 138a02cd93856c8e8ee0bfd3c558e9306607a7f0fb84609f70c566dcfe65c918     4778 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
 1e1b1c2e00f0beda7787e81a4b9f838a6ff9cb9866d8f0060adfe066805e1963   128744 main/binary-amd64/Packages
 50e12a9696e82d0126328341b6e44b6fdad4459e8a53d94beb5d619d1b80c262    20921 main/binary-amd64/Packages.gz
 3498ef94ef0967a7384014c6930aea9e3604595435e3f3baf579d3388f89ad26    17345 main/binary-amd64/Packages.bz2
-----BEGIN PGP SIGNATURE-----

iQIcBAEBCAAGBQJj3C2FAAoJENmAoXRX9vsGtugP/Rzx0JWWASJJU8Ki7NC3B725
VuwHoW7tup+LEn0RdaIfVrPPAC0fRmbg4hju7nnQofeq9NEwrCsytHDqnQCvEvp4
zz3pK7PDUW18AdYZvnI5CX4iGx7PX2hPbBUnGCRs0OY8netMVqBJbRW43hsjvkaW
ZOIl330mxXAGEC2ajRWlzef6stYILGVxuLOUunraIk+jDAU+lGZMaZHO9pqBuJ9p
MFwGCb/TR5v9f/ORtX/nl5RII59ryFoVmOdLc18d/p72zIREwCY4P4mLxDZzQMRe
EZf1RFhm/F6wl+rJx5ZVa30AmY5L9O1C7Uc/chO6hceNoJEbe9FxMumrX66yFTIv
zGTl43pZCqLFyrKzucKeW8+mljrDkoplN8K+Y33JAGTNqrQHbp+ApD4Ls40Wg7hq
KVqadABJ7W0Xiq3dF33LJYQ0raEkrEz5hEU1QCN6k+pB2FTEmDIB8AhP5wfn3C6a
3hbHljSr6DX45kIRNrLGqYv08GpglQqcNC0TNUcZpzouyW/PNsu32i66f9Uiscrk
hHJwJ3vE26AQEhNc27ghV1gkYX1ap3TkFCgg6SomZWvOkqwqdbFxtJgUWATckVqV
eE0Z2U8qNQ1V9YBouHdcVLcAEtprRSuTe5RQDohQuzoXrl6SsGgvVLATAmb/D1nu
Aee63sxMlmRBCwC+QKeH
=zXvj
-----END PGP SIGNATURE-----
";

    #[test]
    fn test_parse_signed() -> Result<()> {
        let (signed, remaining) = Signed::from_bytes(IN_RELEASE)?;
        assert_eq!(remaining, b"");
        assert_eq!(
            signed,
            Signed {
                content: BString::from(b"Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Thu, 2 Feb 2023 21:39:16 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 8550d0ce5fda03a2f3eb8c735a571bd5     4778 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
 2951333500c011d2b22c01de46d43223   128744 main/binary-amd64/Packages
 444ef6562bb0ffef2b40af15d2a1e10d    20921 main/binary-amd64/Packages.gz
 69ac9fed864b2f51c2a5fec9f8584724    17345 main/binary-amd64/Packages.bz2
SHA1:
 56bddab49c82340b09c4e83e469e4042061bffa4     4778 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
 c8be9dfb45580a4ff22f5afb0bff311458ae9dd7   128744 main/binary-amd64/Packages
 0c82b553b566704273b4be3e3e08326f9ce7f936    20921 main/binary-amd64/Packages.gz
 56e0d8810a31b18c6ae46001e08948fbffb20ebb    17345 main/binary-amd64/Packages.bz2
SHA256:
 138a02cd93856c8e8ee0bfd3c558e9306607a7f0fb84609f70c566dcfe65c918     4778 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
 1e1b1c2e00f0beda7787e81a4b9f838a6ff9cb9866d8f0060adfe066805e1963   128744 main/binary-amd64/Packages
 50e12a9696e82d0126328341b6e44b6fdad4459e8a53d94beb5d619d1b80c262    20921 main/binary-amd64/Packages.gz
 3498ef94ef0967a7384014c6930aea9e3604595435e3f3baf579d3388f89ad26    17345 main/binary-amd64/Packages.bz2
".to_vec()),
                signature: vec![137, 2, 28, 4, 1, 1, 8, 0, 6, 5, 2, 99, 220, 45, 133, 0, 10, 9, 16, 217, 128, 161, 116, 87, 246, 251, 6, 182, 232, 15, 253, 28, 241, 208, 149, 150, 1, 34, 73, 83, 194, 162, 236, 208, 183, 7, 189, 185, 86, 236, 7, 161, 110, 237, 186, 159, 139, 18, 125, 17, 117, 162, 31, 86, 179, 207, 0, 45, 31, 70, 102, 224, 226, 24, 238, 238, 121, 208, 161, 247, 170, 244, 209, 48, 172, 43, 50, 180, 112, 234, 157, 0, 175, 18, 250, 120, 207, 61, 233, 43, 179, 195, 81, 109, 124, 1, 214, 25, 190, 114, 57, 9, 126, 34, 27, 30, 207, 95, 104, 79, 108, 21, 39, 24, 36, 108, 208, 230, 60, 157, 235, 76, 86, 160, 73, 109, 21, 184, 222, 27, 35, 190, 70, 150, 100, 226, 37, 223, 125, 38, 197, 112, 6, 16, 45, 154, 141, 21, 165, 205, 231, 250, 178, 214, 8, 44, 101, 113, 184, 179, 148, 186, 122, 218, 34, 79, 163, 12, 5, 62, 148, 102, 76, 105, 145, 206, 246, 154, 129, 184, 159, 105, 48, 92, 6, 9, 191, 211, 71, 155, 253, 127, 243, 145, 181, 127, 231, 151, 148, 72, 35, 159, 107, 200, 90, 21, 152, 231, 75, 115, 95, 29, 254, 158, 246, 204, 132, 68, 192, 38, 56, 63, 137, 139, 196, 54, 115, 64, 196, 94, 17, 151, 245, 68, 88, 102, 252, 94, 176, 151, 234, 201, 199, 150, 85, 107, 125, 0, 153, 142, 75, 244, 237, 66, 237, 71, 63, 114, 19, 186, 133, 199, 141, 160, 145, 27, 123, 209, 113, 50, 233, 171, 95, 174, 178, 21, 50, 47, 204, 100, 229, 227, 122, 89, 10, 162, 197, 202, 178, 179, 185, 194, 158, 91, 207, 166, 150, 58, 195, 146, 138, 101, 55, 194, 190, 99, 125, 201, 0, 100, 205, 170, 180, 7, 110, 159, 128, 164, 62, 11, 179, 141, 22, 131, 184, 106, 41, 90, 154, 116, 0, 73, 237, 109, 23, 138, 173, 221, 23, 125, 203, 37, 132, 52, 173, 161, 36, 172, 76, 249, 132, 69, 53, 64, 35, 122, 147, 234, 65, 216, 84, 196, 152, 50, 1, 240, 8, 79, 231, 7, 231, 220, 46, 154, 222, 22, 199, 150, 52, 171, 232, 53, 248, 230, 66, 17, 54, 178, 198, 169, 139, 244, 240, 106, 96, 149, 10, 156, 52, 45, 19, 53, 71, 25, 167, 58, 46, 201, 111, 207, 54, 203, 183, 218, 46, 186, 127, 213, 34, 177, 202, 228, 132, 114, 112, 39, 123, 196, 219, 160, 16, 18, 19, 92, 219, 184, 33, 87, 88, 36, 97, 125, 90, 167, 116, 228, 20, 40, 32, 233, 42, 38, 101, 107, 206, 146, 172, 42, 117, 177, 113, 180, 152, 20, 88, 4, 220, 145, 90, 149, 120, 77, 25, 217, 79, 42, 53, 13, 85, 245, 128, 104, 184, 119, 92, 84, 183, 0, 18, 218, 107, 69, 43, 147, 123, 148, 80, 14, 136, 80, 187, 58, 23, 174, 94, 146, 176, 104, 47, 84, 176, 19, 2, 102, 255, 15, 89, 238, 1, 231, 186, 222, 204, 76, 150, 100, 65, 11, 0, 190, 64, 167, 135],
            }
        );
        Ok(())
    }

    #[test]
    fn test_canonicalize_already_canonical() -> Result<()> {
        let (canonical, remaining) = Signed::from_bytes(IN_RELEASE)?;
        let canonical = canonical.to_clear_signed()?;
        assert_eq!(remaining, b"");
        assert_eq!(BStr::new(&canonical), BStr::new(IN_RELEASE));
        Ok(())
    }

    #[test]
    fn test_canonicalize_strip_version() -> Result<()> {
        let (canonical, remaining) = Signed::from_bytes(b"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Thu, 2 Feb 2023 21:39:16 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 8550d0ce5fda03a2f3eb8c735a571bd5     4778 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
 2951333500c011d2b22c01de46d43223   128744 main/binary-amd64/Packages
 444ef6562bb0ffef2b40af15d2a1e10d    20921 main/binary-amd64/Packages.gz
 69ac9fed864b2f51c2a5fec9f8584724    17345 main/binary-amd64/Packages.bz2
SHA1:
 56bddab49c82340b09c4e83e469e4042061bffa4     4778 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
 c8be9dfb45580a4ff22f5afb0bff311458ae9dd7   128744 main/binary-amd64/Packages
 0c82b553b566704273b4be3e3e08326f9ce7f936    20921 main/binary-amd64/Packages.gz
 56e0d8810a31b18c6ae46001e08948fbffb20ebb    17345 main/binary-amd64/Packages.bz2
SHA256:
 138a02cd93856c8e8ee0bfd3c558e9306607a7f0fb84609f70c566dcfe65c918     4778 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
 1e1b1c2e00f0beda7787e81a4b9f838a6ff9cb9866d8f0060adfe066805e1963   128744 main/binary-amd64/Packages
 50e12a9696e82d0126328341b6e44b6fdad4459e8a53d94beb5d619d1b80c262    20921 main/binary-amd64/Packages.gz
 3498ef94ef0967a7384014c6930aea9e3604595435e3f3baf579d3388f89ad26    17345 main/binary-amd64/Packages.bz2
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iQIcBAEBCAAGBQJj3C2FAAoJENmAoXRX9vsGtugP/Rzx0JWWASJJU8Ki7NC3B725
VuwHoW7tup+LEn0RdaIfVrPPAC0fRmbg4hju7nnQofeq9NEwrCsytHDqnQCvEvp4
zz3pK7PDUW18AdYZvnI5CX4iGx7PX2hPbBUnGCRs0OY8netMVqBJbRW43hsjvkaW
ZOIl330mxXAGEC2ajRWlzef6stYILGVxuLOUunraIk+jDAU+lGZMaZHO9pqBuJ9p
MFwGCb/TR5v9f/ORtX/nl5RII59ryFoVmOdLc18d/p72zIREwCY4P4mLxDZzQMRe
EZf1RFhm/F6wl+rJx5ZVa30AmY5L9O1C7Uc/chO6hceNoJEbe9FxMumrX66yFTIv
zGTl43pZCqLFyrKzucKeW8+mljrDkoplN8K+Y33JAGTNqrQHbp+ApD4Ls40Wg7hq
KVqadABJ7W0Xiq3dF33LJYQ0raEkrEz5hEU1QCN6k+pB2FTEmDIB8AhP5wfn3C6a
3hbHljSr6DX45kIRNrLGqYv08GpglQqcNC0TNUcZpzouyW/PNsu32i66f9Uiscrk
hHJwJ3vE26AQEhNc27ghV1gkYX1ap3TkFCgg6SomZWvOkqwqdbFxtJgUWATckVqV
eE0Z2U8qNQ1V9YBouHdcVLcAEtprRSuTe5RQDohQuzoXrl6SsGgvVLATAmb/D1nu
Aee63sxMlmRBCwC+QKeH
=zXvj
-----END PGP SIGNATURE-----
")?;
        let canonical = canonical.to_clear_signed()?;
        assert_eq!(remaining, b"");
        assert_eq!(canonical, IN_RELEASE);
        Ok(())
    }

    #[test]
    fn test_check_signature() -> Result<()> {
        let (signed, remaining) = Signed::from_bytes(IN_RELEASE)?;
        assert_eq!(remaining, b"");
        let keyring = Keyring::new(include_bytes!("../contrib/signal-desktop-keyring.gpg"))?;
        let canonical = signed.canonicalize(Some(&keyring))?;
        assert_eq!(canonical, &[("DBA36B5181D0C816F630E889D980A17457F6FB06".parse().ok(), Signed {
            content: BString::from(b"Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Thu, 2 Feb 2023 21:39:16 UTC
Architectures: amd64
Components: main
Description: Generated by aptly
MD5Sum:
 8550d0ce5fda03a2f3eb8c735a571bd5     4778 main/Contents-amd64.gz
 d8c35b55bc8e48e267b9ccdaf383976d       85 main/binary-amd64/Release
 2951333500c011d2b22c01de46d43223   128744 main/binary-amd64/Packages
 444ef6562bb0ffef2b40af15d2a1e10d    20921 main/binary-amd64/Packages.gz
 69ac9fed864b2f51c2a5fec9f8584724    17345 main/binary-amd64/Packages.bz2
SHA1:
 56bddab49c82340b09c4e83e469e4042061bffa4     4778 main/Contents-amd64.gz
 992cb9cd8a0af2d9ad81d2b45342656d41157202       85 main/binary-amd64/Release
 c8be9dfb45580a4ff22f5afb0bff311458ae9dd7   128744 main/binary-amd64/Packages
 0c82b553b566704273b4be3e3e08326f9ce7f936    20921 main/binary-amd64/Packages.gz
 56e0d8810a31b18c6ae46001e08948fbffb20ebb    17345 main/binary-amd64/Packages.bz2
SHA256:
 138a02cd93856c8e8ee0bfd3c558e9306607a7f0fb84609f70c566dcfe65c918     4778 main/Contents-amd64.gz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9       85 main/binary-amd64/Release
 1e1b1c2e00f0beda7787e81a4b9f838a6ff9cb9866d8f0060adfe066805e1963   128744 main/binary-amd64/Packages
 50e12a9696e82d0126328341b6e44b6fdad4459e8a53d94beb5d619d1b80c262    20921 main/binary-amd64/Packages.gz
 3498ef94ef0967a7384014c6930aea9e3604595435e3f3baf579d3388f89ad26    17345 main/binary-amd64/Packages.bz2
".to_vec()),
            signature: vec![194, 193, 92, 4, 1, 1, 8, 0, 6, 5, 2, 99, 220, 45, 133, 0, 10, 9, 16, 217, 128, 161, 116, 87, 246, 251, 6, 182, 232, 15, 253, 28, 241, 208, 149, 150, 1, 34, 73, 83, 194, 162, 236, 208, 183, 7, 189, 185, 86, 236, 7, 161, 110, 237, 186, 159, 139, 18, 125, 17, 117, 162, 31, 86, 179, 207, 0, 45, 31, 70, 102, 224, 226, 24, 238, 238, 121, 208, 161, 247, 170, 244, 209, 48, 172, 43, 50, 180, 112, 234, 157, 0, 175, 18, 250, 120, 207, 61, 233, 43, 179, 195, 81, 109, 124, 1, 214, 25, 190, 114, 57, 9, 126, 34, 27, 30, 207, 95, 104, 79, 108, 21, 39, 24, 36, 108, 208, 230, 60, 157, 235, 76, 86, 160, 73, 109, 21, 184, 222, 27, 35, 190, 70, 150, 100, 226, 37, 223, 125, 38, 197, 112, 6, 16, 45, 154, 141, 21, 165, 205, 231, 250, 178, 214, 8, 44, 101, 113, 184, 179, 148, 186, 122, 218, 34, 79, 163, 12, 5, 62, 148, 102, 76, 105, 145, 206, 246, 154, 129, 184, 159, 105, 48, 92, 6, 9, 191, 211, 71, 155, 253, 127, 243, 145, 181, 127, 231, 151, 148, 72, 35, 159, 107, 200, 90, 21, 152, 231, 75, 115, 95, 29, 254, 158, 246, 204, 132, 68, 192, 38, 56, 63, 137, 139, 196, 54, 115, 64, 196, 94, 17, 151, 245, 68, 88, 102, 252, 94, 176, 151, 234, 201, 199, 150, 85, 107, 125, 0, 153, 142, 75, 244, 237, 66, 237, 71, 63, 114, 19, 186, 133, 199, 141, 160, 145, 27, 123, 209, 113, 50, 233, 171, 95, 174, 178, 21, 50, 47, 204, 100, 229, 227, 122, 89, 10, 162, 197, 202, 178, 179, 185, 194, 158, 91, 207, 166, 150, 58, 195, 146, 138, 101, 55, 194, 190, 99, 125, 201, 0, 100, 205, 170, 180, 7, 110, 159, 128, 164, 62, 11, 179, 141, 22, 131, 184, 106, 41, 90, 154, 116, 0, 73, 237, 109, 23, 138, 173, 221, 23, 125, 203, 37, 132, 52, 173, 161, 36, 172, 76, 249, 132, 69, 53, 64, 35, 122, 147, 234, 65, 216, 84, 196, 152, 50, 1, 240, 8, 79, 231, 7, 231, 220, 46, 154, 222, 22, 199, 150, 52, 171, 232, 53, 248, 230, 66, 17, 54, 178, 198, 169, 139, 244, 240, 106, 96, 149, 10, 156, 52, 45, 19, 53, 71, 25, 167, 58, 46, 201, 111, 207, 54, 203, 183, 218, 46, 186, 127, 213, 34, 177, 202, 228, 132, 114, 112, 39, 123, 196, 219, 160, 16, 18, 19, 92, 219, 184, 33, 87, 88, 36, 97, 125, 90, 167, 116, 228, 20, 40, 32, 233, 42, 38, 101, 107, 206, 146, 172, 42, 117, 177, 113, 180, 152, 20, 88, 4, 220, 145, 90, 149, 120, 77, 25, 217, 79, 42, 53, 13, 85, 245, 128, 104, 184, 119, 92, 84, 183, 0, 18, 218, 107, 69, 43, 147, 123, 148, 80, 14, 136, 80, 187, 58, 23, 174, 94, 146, 176, 104, 47, 84, 176, 19, 2, 102, 255, 15, 89, 238, 1, 231, 186, 222, 204, 76, 150, 100, 65, 11, 0, 190, 64, 167, 135],
        })]);
        Ok(())
    }

    #[test]
    fn test_check_multiple_signatures() -> Result<()> {
        let (signed, remaining) = Signed::from_bytes(b"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Origin: Debian
Label: Debian
Suite: stable
Version: 11.6
Codename: bullseye
Changelogs: https://metadata.ftp-master.debian.org/changelogs/@CHANGEPATH@_changelog
Date: Sat, 17 Dec 2022 10:14:37 UTC
Acquire-By-Hash: yes
No-Support-for-Architecture-all: Packages
Architectures: all amd64 arm64 armel armhf i386 mips64el mipsel ppc64el s390x
Components: main contrib non-free
Description: Debian 11.6 Released 17 December 2022
MD5Sum:
 7fdf4db15250af5368cc52a91e8edbce   738242 contrib/Contents-all
 cbd7bc4d3eb517ac2b22f929dfc07b47    57319 contrib/Contents-all.gz
 6e4ef0f159fa08f5ba74067e0a94b5e6   787321 contrib/Contents-amd64
 98583d055424774c060fdf4b02291da5    54668 contrib/Contents-amd64.gz
 61e10f1703d718d584f381a943bfe4d7   370915 contrib/Contents-arm64
 86a145a0d8d7346449f2cf62098a5553    29596 contrib/Contents-arm64.gz
 b6d2673f17fbdb3a5ce92404a62c2d7e   359292 contrib/Contents-armel
 d02d94be587d56a1246b407669d2a24c    28039 contrib/Contents-armel.gz
 d272ba9da0f302b6c09a36899e738115   367655 contrib/Contents-armhf
 317aa67ea34d625837d245f6fb00bdc4    29236 contrib/Contents-armhf.gz
 ccb13401b0f48dded08ed089f8074765   407328 contrib/Contents-i386
 e496015d7e6e8d5a91cec31fc4bde74c    33556 contrib/Contents-i386.gz
 44384de1db64f592fc69693b355a0ec7   359402 contrib/Contents-mips64el
 a2abf38d14c1c7e3aafcb21881b0fe7d    27962 contrib/Contents-mips64el.gz
 457feed233db5ce7db62cc69e7a8a5c6   360549 contrib/Contents-mipsel
 90ec76d0dca539a4c4aa33404de4c633    27942 contrib/Contents-mipsel.gz
 02985cbbdd1e790b29a9911ba00b5650   370025 contrib/Contents-ppc64el
 b34b90df14207eafe94313e6d466b28e    29381 contrib/Contents-ppc64el.gz
 e2089c91540f7adb693675935dacf9e5   357860 contrib/Contents-s390x
 bb90fb42e72d39da53b3e1e2c2f46bc3    27518 contrib/Contents-s390x.gz
 ba62d5cf69ffc155d75fa9e16228b039  6722669 contrib/Contents-source
 fec97c652e41904e73f17cc5f7b0b2ff   469817 contrib/Contents-source.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-all
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-all.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-amd64
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-amd64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-arm64
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-arm64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-armel
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-armel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-armhf
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-armhf.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-i386
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-i386.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-mips64el
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-mips64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-mipsel
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-mipsel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-ppc64el
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-ppc64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-s390x
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-s390x.gz
 73d0ad5df01464248f578fb7d7ba10b0   103239 contrib/binary-all/Packages
 6848b84ab94b0624ad15f5afea5f49bd    27385 contrib/binary-all/Packages.gz
 a9e21972669e0355e9a875ea31f25c63    23916 contrib/binary-all/Packages.xz
 3c9131b20395850cbf9735dfbc0cd6a7      117 contrib/binary-all/Release
 b6541899bd7907d9dc5afe604d26a719   231878 contrib/binary-amd64/Packages
 7cb1a35df9e7ef744685d28932cc1ef2    60884 contrib/binary-amd64/Packages.gz
 4ee4184e78f4b0d06e981706a6118dc7    50588 contrib/binary-amd64/Packages.xz
 7edd7af81aa30d5a929cad55b259de23      119 contrib/binary-amd64/Release
 4b9c68a7d2d23357dc171d29a03565c6   180884 contrib/binary-arm64/Packages
 c2d2253fb81e2a397e4a42d4d475bd24    48958 contrib/binary-arm64/Packages.gz
 f57a0a52945226cc76c241ce57c182be    40964 contrib/binary-arm64/Packages.xz
 34b661285be33d5dd033de35b00b0b52      119 contrib/binary-arm64/Release
 1636c115e53ef208266fcc6b024f7b34   163042 contrib/binary-armel/Packages
 ed80c2afd00562cee8543a3835ed0907    44389 contrib/binary-armel/Packages.gz
 ef8175333695e1554eeb8766d74c4795    37452 contrib/binary-armel/Packages.xz
 f5908602701eedda3f627be810655de2      119 contrib/binary-armel/Release
 900f4a8949a535dfd1af4326b43e6fa4   175566 contrib/binary-armhf/Packages
 11db111d1dd40616866a8b6d4e59ca8d    47805 contrib/binary-armhf/Packages.gz
 512198b43afc25d9da1e078b44f5b4a8    40220 contrib/binary-armhf/Packages.xz
 7271fc19a10e612fcdc17bfc361a4805      119 contrib/binary-armhf/Release
 feb05a736bdfbd41bfdd4d87fd34f72a   203514 contrib/binary-i386/Packages
 89a79f0c9d4bb2df7d3dc3d165f02242    54100 contrib/binary-i386/Packages.gz
 130d6b77d3b32c1ec94097e694d66718    45340 contrib/binary-i386/Packages.xz
 8dc8ab0c142d7166f1a8cb8ef5c8dcaa      118 contrib/binary-i386/Release
 825bc5698936bc26f5bb28c20287aeb1   163507 contrib/binary-mips64el/Packages
 190dd8f6a3e97c3ebe8ab216e79ed867    44652 contrib/binary-mips64el/Packages.gz
 9302a32bad830648c066bfb13a35b6b9    37496 contrib/binary-mips64el/Packages.xz
 268c4243d0a655c886c9533779085b8e      122 contrib/binary-mips64el/Release
 4e717be16d235fb7e6e118c898ac80af   164647 contrib/binary-mipsel/Packages
 f73fd75fc0a6371ae7e6b709a4d8d939    44883 contrib/binary-mipsel/Packages.gz
 9c8d77e03dcdc178465c28095f4e8d64    37816 contrib/binary-mipsel/Packages.xz
 5e4a6cc21b9343c50ab7eeb20be00166      120 contrib/binary-mipsel/Release
 1343f3307bbeea9f0b04dd64e8d23d62   180387 contrib/binary-ppc64el/Packages
 831c14a6428bbe7b05d290e9aa225785    48843 contrib/binary-ppc64el/Packages.gz
 8daa347dc96d3f69e7510c0d3f51916e    40808 contrib/binary-ppc64el/Packages.xz
 44eda0cdaff945cc2cb4f8bdfad50371      121 contrib/binary-ppc64el/Release
 1a2b7365b25b44a4304271198bda5094   162250 contrib/binary-s390x/Packages
 103b59f69a5c230eab05d06289ad7c9b    44334 contrib/binary-s390x/Packages.gz
 e4109e4637f7b1c233130da040451fd9    37244 contrib/binary-s390x/Packages.xz
 aa08c18b750a7efa1a4c3f23650132a4      119 contrib/binary-s390x/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-all/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-all/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-all/Packages.xz
 3c9131b20395850cbf9735dfbc0cd6a7      117 contrib/debian-installer/binary-all/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-amd64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-amd64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-amd64/Packages.xz
 7edd7af81aa30d5a929cad55b259de23      119 contrib/debian-installer/binary-amd64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-arm64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-arm64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-arm64/Packages.xz
 34b661285be33d5dd033de35b00b0b52      119 contrib/debian-installer/binary-arm64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-armel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-armel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-armel/Packages.xz
 f5908602701eedda3f627be810655de2      119 contrib/debian-installer/binary-armel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-armhf/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-armhf/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-armhf/Packages.xz
 7271fc19a10e612fcdc17bfc361a4805      119 contrib/debian-installer/binary-armhf/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-i386/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-i386/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-i386/Packages.xz
 8dc8ab0c142d7166f1a8cb8ef5c8dcaa      118 contrib/debian-installer/binary-i386/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-mips64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-mips64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-mips64el/Packages.xz
 268c4243d0a655c886c9533779085b8e      122 contrib/debian-installer/binary-mips64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-mipsel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-mipsel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-mipsel/Packages.xz
 5e4a6cc21b9343c50ab7eeb20be00166      120 contrib/debian-installer/binary-mipsel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-ppc64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-ppc64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-ppc64el/Packages.xz
 44eda0cdaff945cc2cb4f8bdfad50371      121 contrib/debian-installer/binary-ppc64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-s390x/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-s390x/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-s390x/Packages.xz
 aa08c18b750a7efa1a4c3f23650132a4      119 contrib/debian-installer/binary-s390x/Release
 fc412a0e8fed50416ae55ca3a34c2654   119152 contrib/dep11/Components-amd64.yml
 7473c932902284e9c636636a5ff0587b    15579 contrib/dep11/Components-amd64.yml.gz
 751b272121122fce4882d17a9d099c44    13564 contrib/dep11/Components-amd64.yml.xz
 49911a9d2f76ed13124c7cff0081266b   113437 contrib/dep11/Components-arm64.yml
 ee72e145d0e71d94c0d418d36dabfd8c    14251 contrib/dep11/Components-arm64.yml.gz
 65f48dc9acec772076e60ce35239703f    12480 contrib/dep11/Components-arm64.yml.xz
 b1f970bbcdd889ccff5c2646bc2835ba   113437 contrib/dep11/Components-armel.yml
 d2a414b1147562c0ecfa1aab53fc0260    14029 contrib/dep11/Components-armel.yml.gz
 b450a677c3a5d4a52d2a0df274c222cf    12524 contrib/dep11/Components-armel.yml.xz
 75c6b8bd42fc863caa66c454306c7d39   113437 contrib/dep11/Components-armhf.yml
 ac52f103d1c493d0f8d8e5662d758f78    14127 contrib/dep11/Components-armhf.yml.gz
 80f4310b2d68bf09c7fbba34a0eec794    12480 contrib/dep11/Components-armhf.yml.xz
 a46b6878a89f45fab86aca68bffe081d   118972 contrib/dep11/Components-i386.yml
 751ea67ac68d2e755726b4e9d62ab15e    15566 contrib/dep11/Components-i386.yml.gz
 82c956565311c8a7d90bff6e0a226fbe    13560 contrib/dep11/Components-i386.yml.xz
 6f822ef8f2c13dc4212ade261b4a8752   113437 contrib/dep11/Components-mips64el.yml
 a072aab0fb45dab4a6e25295f23e9b5f    14056 contrib/dep11/Components-mips64el.yml.gz
 e5c2dd7fd785fa1ab66099d7763bd670    12500 contrib/dep11/Components-mips64el.yml.xz
 432a29a22c4a782f6edad376f386937f   113437 contrib/dep11/Components-ppc64el.yml
 b5202b5037949e593060f92290d6f949    14219 contrib/dep11/Components-ppc64el.yml.gz
 dd92a500c7807091665dbc207c9bef68    12496 contrib/dep11/Components-ppc64el.yml.xz
 53c6b87820861b0ed316a88f7542cd76   113437 contrib/dep11/Components-s390x.yml
 5a4872d3187bc79418b468890be4b5fe    14050 contrib/dep11/Components-s390x.yml.gz
 eefb3301e486aedbbbb1d735e2522a00    12488 contrib/dep11/Components-s390x.yml.xz
 5d8e37f26e7e15f367751089fa13c876   271360 contrib/dep11/icons-128x128.tar
 500b14a4cafa23b9106b402737f863a7   195507 contrib/dep11/icons-128x128.tar.gz
 d9651fb188be2221d2f583aeba83d8fc    83968 contrib/dep11/icons-48x48.tar
 6b5ea4675ad78554aaa53b344f1bd146    47168 contrib/dep11/icons-48x48.tar.gz
 7115d3a3d41fc9bca9cfcc3c608bebf2   138752 contrib/dep11/icons-64x64.tar
 c839e679f1d60d294d39884d0911e514    93294 contrib/dep11/icons-64x64.tar.gz
 01e75740c90a7df7e474a1c6152b2aa6   192685 contrib/i18n/Translation-en
 a2e9608c3e388d26e031583f200e2f92    46929 contrib/i18n/Translation-en.bz2
 7b851a6fc52e455ec6e64d1bbd002e60      120 contrib/source/Release
 d615756c28aa372e2bc408abe1d9ec5b   178776 contrib/source/Sources
 c19b950adb0b02bb84fec45d11d257d8    51355 contrib/source/Sources.gz
 0e1710e68ffbd6a7b3542844610a69fc    43208 contrib/source/Sources.xz
 052421edd3e77801652c5e82cea27172 477769406 main/Contents-all
 c6642306466300d5b980a46ab2da3448 31069218 main/Contents-all.gz
 4f76cfae77ca68a2534e4776c1ba603a 129058022 main/Contents-amd64
 d00bf88e20a9167d72c15f914e2f6ae6 10270460 main/Contents-amd64.gz
 4c143d623f5b8d26d47c079554c17287 122426895 main/Contents-arm64
 44ba782a6a21b58a1ff85d2c04785f8d  9831920 main/Contents-arm64.gz
 801e7ed91bc44eb81525999ec2a8291e 104683113 main/Contents-armel
 a5a18ca6cde98c20f5b89666cc6ada02  8703570 main/Contents-armel.gz
 307b7ca5872bf53d92aced5dc4fa75ba 113716591 main/Contents-armhf
 ec3f7e25caefcde0999e74f88fe29c25  9305906 main/Contents-armhf.gz
 39e08183dd281004ce0853d8138db6b9 129088857 main/Contents-i386
 4339b5c20026a75c512e5c97c56ac03c 10208982 main/Contents-i386.gz
 1468642d6dbe21a9b910d360f52d1a71 111097071 main/Contents-mips64el
 f5727ac1ba4208d6994869b64251d40f  9042221 main/Contents-mips64el.gz
 30ac6e6b838d5fc79a6139fc5b4e7337 112593872 main/Contents-mipsel
 13fcab9f9e956d966bf9975da41bec6c  9178325 main/Contents-mipsel.gz
 985636740f62394375012f87593d5c21 116027632 main/Contents-ppc64el
 97f1aaf6603044158ce139c2570992d0  9355024 main/Contents-ppc64el.gz
 332ff60dc3b48ca16f5bf3baa139b530 103638209 main/Contents-s390x
 1dfb6d3460020eb28ef7ab36bd7d0c08  8711885 main/Contents-s390x.gz
 30e2a744a0a8fc6c48325fa30d7d0e70 690410830 main/Contents-source
 453c66c682ee49babee0fac4ec460ac7 73501881 main/Contents-source.gz
 1f4bf598c355a2bbb0c8ddf889d9636e   157382 main/Contents-udeb-all
 708ed31f29f9daf4c980b7abdd66c356    13516 main/Contents-udeb-all.gz
 069860439eabdda442aa81afb59f8644   477050 main/Contents-udeb-amd64
 6e95b271bba66b8135cdd9ee13cad982    36011 main/Contents-udeb-amd64.gz
 8884d6660508188095f2991c73ede3a2   508817 main/Contents-udeb-arm64
 a972a7d9191733ca34c65bbec0c4da30    38139 main/Contents-udeb-arm64.gz
 72cc361d1b9ae73eeb7e3798a52564b2   323083 main/Contents-udeb-armel
 2521b5dc40ca4ce0c2cf495642512931    25477 main/Contents-udeb-armel.gz
 b74da65320e8e14ccd398d9b3a0af741   579793 main/Contents-udeb-armhf
 a6b01ebd28d333afe285226a6d3902b5    43153 main/Contents-udeb-armhf.gz
 02f78f33d39614e8f2c1ae4a5971637a   751383 main/Contents-udeb-i386
 f77c976f4226372caba729cd86720f36    53984 main/Contents-udeb-i386.gz
 fc8c6638ad4e7036abcfb74c9ca40e67   760534 main/Contents-udeb-mips64el
 b29f9bef4f9b6237adac6822c3f644ee    52873 main/Contents-udeb-mips64el.gz
 8851f799ab3bac7dbe3ade6ca88058d3   760210 main/Contents-udeb-mipsel
 f5b4e16d70afd5fe145bbcff78ed60c7    52810 main/Contents-udeb-mipsel.gz
 b0c21603250d55447094b00f1438aef7   401639 main/Contents-udeb-ppc64el
 9cc88f8f084a1bf1b0f4a3f7d4d2baa1    29533 main/Contents-udeb-ppc64el.gz
 942cbd0dfe1ec1bbc24f50b6a22102e0   258318 main/Contents-udeb-s390x
 bdeed95042d0b946c8d8f72cb49fd28d    20894 main/Contents-udeb-s390x.gz
 779c0c7072ee9cd9b776167e3b0d8694 20423830 main/binary-all/Packages
 78a6edfff04a3b7505c0b8b1cc468c68  5208282 main/binary-all/Packages.gz
 296b8e6e27112ca9610cde0fbc84f34f  3918264 main/binary-all/Packages.xz
 d8d2edd733e3235987c8c0c9565344d8      114 main/binary-all/Release
 ee0b34bb7ba7a8e1a7964ebd20187def 45534962 main/binary-amd64/Packages
 c14373e666988e64b30c26f3b6c3fbf2 11096605 main/binary-amd64/Packages.gz
 f30e2d1e8f395c903155dda0c4ba0970  8182920 main/binary-amd64/Packages.xz
 dbeadc926a4f14b4a73390c82832052b      116 main/binary-amd64/Release
 e02c425b41e1c7f2e910960cb80b8fc6 44816551 main/binary-arm64/Packages
 854700a00d0c4c7b9f8b7946d97b85fc 10941625 main/binary-arm64/Packages.gz
 3fd4c3700b238504448734039842d4fd  8071508 main/binary-arm64/Packages.xz
 f02cb9aab85fccb7a19d168b5acb2390      116 main/binary-arm64/Release
 a0174a68bcedce8fba19bde6cd1208b3 43343990 main/binary-armel/Packages
 56c75313e445b1b136fd240122a4a207 10677432 main/binary-armel/Packages.gz
 797f4ee8e47a372aae0a83ea352fe2fa  7871888 main/binary-armel/Packages.xz
 358a6eb5337f79950b79beaae6d06bd4      116 main/binary-armel/Release
 d4028809623d98cbf20cb043be845906 43846413 main/binary-armhf/Packages
 8326ddf7c01158570ca901a8827c0449 10775534 main/binary-armhf/Packages.gz
 5845702f6c696189347091fd5cb51276  7944712 main/binary-armhf/Packages.xz
 8811dc441114bb1b2f90dfce9ff6acfc      116 main/binary-armhf/Release
 99f2432683f72cb4833cc0392f8a1313 45094980 main/binary-i386/Packages
 1c5363ed68d7894cf94ab51ec66bf926 11013153 main/binary-i386/Packages.gz
 534024b184373545b78e74aa164ba211  8121972 main/binary-i386/Packages.xz
 50b3c16ad95352c06904ec1341afe2d2      115 main/binary-i386/Release
 87f3a748abd585d485b04e11a8f75fa8 43733274 main/binary-mips64el/Packages
 e7ee93fdf444409e1d751e3160a599e3 10720185 main/binary-mips64el/Packages.gz
 c2f655d6e0fb46a1eb029045054e5b52  7907404 main/binary-mips64el/Packages.xz
 c0cc63128ced0d323a714281b3f78ba2      119 main/binary-mips64el/Release
 d5fc8d1553a24222dda3e6fc804b2aeb 43667386 main/binary-mipsel/Packages
 88a8a5f188c1a0e18255daab88d8c83f 10726366 main/binary-mipsel/Packages.gz
 c9568fef286c9fe7d80cdcf9dece78bc  7906936 main/binary-mipsel/Packages.xz
 0ac20990fd13d5eaf32c0041fd37c568      117 main/binary-mipsel/Release
 735e4dcaafa4c558fd21e8a7075f4997 44671240 main/binary-ppc64el/Packages
 5f14e959fec4dfca2d5b3f8b7bd090af 10884852 main/binary-ppc64el/Packages.gz
 1b587b581cb630066fa51c8ea85ea327  8031816 main/binary-ppc64el/Packages.xz
 641a1901dc2496b912f4f49e9f7d4db8      118 main/binary-ppc64el/Release
 d93e11281b31f88d89a0d1eb73cc13ca 43340190 main/binary-s390x/Packages
 1ca35cf8189cbb3fe643b9be4ca39e48 10686656 main/binary-s390x/Packages.gz
 9f00d6b29f1659c08eea54ca8e0e652e  7877060 main/binary-s390x/Packages.xz
 40a1a7ba21820ed919518a0e4f6cbbbd      116 main/binary-s390x/Release
 8523f5593a344ec29029e3e20b8e10fa    61160 main/debian-installer/binary-all/Packages
 8322a8e0b943187cc1ad41f5e91e0c8c    16449 main/debian-installer/binary-all/Packages.gz
 73f68ee665b0ba4fe8b1d5bd0986e6a1    14676 main/debian-installer/binary-all/Packages.xz
 d8d2edd733e3235987c8c0c9565344d8      114 main/debian-installer/binary-all/Release
 e5156b114c9a46b50dc7b14217399795   274352 main/debian-installer/binary-amd64/Packages
 fa8d2c9b9be51d30622654b67ecac5c5    67349 main/debian-installer/binary-amd64/Packages.gz
 79cadb77602e77b501f0d9354d6a940b    56064 main/debian-installer/binary-amd64/Packages.xz
 dbeadc926a4f14b4a73390c82832052b      116 main/debian-installer/binary-amd64/Release
 bf5150ba5d1823e80ce45b268a79a392   257349 main/debian-installer/binary-arm64/Packages
 74c5e0915ec84c2c336d97652ffa0a7a    64271 main/debian-installer/binary-arm64/Packages.gz
 cca08998fcdd03ca3284112927344e20    53980 main/debian-installer/binary-arm64/Packages.xz
 f02cb9aab85fccb7a19d168b5acb2390      116 main/debian-installer/binary-arm64/Release
 79673899cedce0be43ebc1d416fb58bd   248363 main/debian-installer/binary-armel/Packages
 80bf080680db4b7b02ed444454b8981f    63792 main/debian-installer/binary-armel/Packages.gz
 7cfb8b710c1228c6359c7b48041cc8c0    53168 main/debian-installer/binary-armel/Packages.xz
 358a6eb5337f79950b79beaae6d06bd4      116 main/debian-installer/binary-armel/Release
 1f43e9a44586e87494ec1a7269ec7f2c   251788 main/debian-installer/binary-armhf/Packages
 262d12c86cfee6e0c82383272d15c377    64864 main/debian-installer/binary-armhf/Packages.gz
 b4db61d6a2322a13cf8d6b0f49e9ffbe    53852 main/debian-installer/binary-armhf/Packages.xz
 8811dc441114bb1b2f90dfce9ff6acfc      116 main/debian-installer/binary-armhf/Release
 cd8f8bf8d19b9ba5a1efc7a75930121a   349445 main/debian-installer/binary-i386/Packages
 41400360bb68ffe289e94a68da63e79f    77230 main/debian-installer/binary-i386/Packages.gz
 2a77d691876cab7b5f0803b7611ca267    64124 main/debian-installer/binary-i386/Packages.xz
 50b3c16ad95352c06904ec1341afe2d2      115 main/debian-installer/binary-i386/Release
 c22d0ce635eb0fae86afba6242116a19   364716 main/debian-installer/binary-mips64el/Packages
 1aef85058cd12a9638321fedd2ffff31    79498 main/debian-installer/binary-mips64el/Packages.gz
 9d5da1ee87189d9671b42c4bc122c48a    66396 main/debian-installer/binary-mips64el/Packages.xz
 c0cc63128ced0d323a714281b3f78ba2      119 main/debian-installer/binary-mips64el/Release
 18bc2f5de2b576eee963afeb65375aab   364202 main/debian-installer/binary-mipsel/Packages
 a1b8c712b5272debb29e8c07de9caf0b    79784 main/debian-installer/binary-mipsel/Packages.gz
 cce1945593d8c4b82fd33b6e5f761521    66500 main/debian-installer/binary-mipsel/Packages.xz
 0ac20990fd13d5eaf32c0041fd37c568      117 main/debian-installer/binary-mipsel/Release
 d7b8901246bae032e5ddbc9e45cc872c   256933 main/debian-installer/binary-ppc64el/Packages
 70a122a874633fde8db5504f98ee7439    64920 main/debian-installer/binary-ppc64el/Packages.gz
 f2e4f1994de7021fbfc39fa44056b2b1    53960 main/debian-installer/binary-ppc64el/Packages.xz
 641a1901dc2496b912f4f49e9f7d4db8      118 main/debian-installer/binary-ppc64el/Release
 1b44e25a26eefd464c288608423d6e42   226275 main/debian-installer/binary-s390x/Packages
 095ad8009e027e93ec3bbe8678eef9f6    60464 main/debian-installer/binary-s390x/Packages.gz
 e513ca8104e23a972e147e86ef1bf5ab    50116 main/debian-installer/binary-s390x/Packages.xz
 40a1a7ba21820ed919518a0e4f6cbbbd      116 main/debian-installer/binary-s390x/Release
 97a6eda13094854f8838218d5869a796 18520413 main/dep11/Components-amd64.yml
 9cd807c0b66a8489b5385bf4f343b288  6213469 main/dep11/Components-amd64.yml.gz
 c16ba02c289510dce9857dfa6cde4550  4048504 main/dep11/Components-amd64.yml.xz
 3e8ecb0bbaecb88d0b16dfaa037dba73 18436837 main/dep11/Components-arm64.yml
 09ef5a87673c946f916b0d8ef0c2471d  6191092 main/dep11/Components-arm64.yml.gz
 fef127cee05f3efb96261e78b4fe4568  4033216 main/dep11/Components-arm64.yml.xz
 67becc674b536e310fe22492d55c8652 17658848 main/dep11/Components-armel.yml
 34cd8a6a1206f804e6d5c54dcdd3ef63  5952269 main/dep11/Components-armel.yml.gz
 d7cc0222cae53bcfa1de29218fe5cb94  3879744 main/dep11/Components-armel.yml.xz
 09010fea4c1cf082bd54aecc24182e45 18205252 main/dep11/Components-armhf.yml
 f5b7fd1a9cb147fa6b90e60a4d2139c1  6110587 main/dep11/Components-armhf.yml.gz
 f1f223ca9e69ad1901345ceb404a5666  3983180 main/dep11/Components-armhf.yml.xz
 ee8f83c597007ab84b58feec05d647fa 18485654 main/dep11/Components-i386.yml
 5a6b35ea7b54d88842ab30bbbd469623  6201776 main/dep11/Components-i386.yml.gz
 239cc12774e7c2925d1d783faaf01b5d  4041608 main/dep11/Components-i386.yml.xz
 dd59f50383f269a8e1ec09c49d8a786c 17819116 main/dep11/Components-mips64el.yml
 e3f03ed2f2c22dac3207e5f3fb98f862  5977494 main/dep11/Components-mips64el.yml.gz
 437c9fa1e058fc9a3486fb8b224740f6  3896708 main/dep11/Components-mips64el.yml.xz
 09d0cb63fdf4a4904155dc0d56ccc04b 17947079 main/dep11/Components-ppc64el.yml
 3d396ef7d8293620c5160a75fda04d39  6023058 main/dep11/Components-ppc64el.yml.gz
 23ebc600f44eb4973c351a4a324ba219  3925796 main/dep11/Components-ppc64el.yml.xz
 64acc85d1d2ce3e3dc551ae85e80ca57 17735785 main/dep11/Components-s390x.yml
 b7f851e780c93532c1707895dfa22474  5976062 main/dep11/Components-s390x.yml.gz
 117c2f52a672bca008f2c206ad8527a6  3894008 main/dep11/Components-s390x.yml.xz
 3f40799bee1a72a060f7dff19efa7b05 13048320 main/dep11/icons-128x128.tar
 6ac207d4fb6b76c25dc59edb50c3bf6b 11409337 main/dep11/icons-128x128.tar.gz
 66ce5f075d189138824e736123711450  4878336 main/dep11/icons-48x48.tar
 260bbc45bfa6b33e31399b4adb3b1f6d  3477622 main/dep11/icons-48x48.tar.gz
 47dea6d08e37b4a5154a072f3ad92cf0  9378816 main/dep11/icons-64x64.tar
 417f46677b9086f9dd0a425f0f39ee31  7315395 main/dep11/icons-64x64.tar.gz
 180389879ed6715b463d05b637e191dc     6191 main/i18n/Translation-ca
 8f8b7ffa4659d4f03b65ed28e69821f9     2673 main/i18n/Translation-ca.bz2
 b4ef33a20d80c576c7b352e96a86e063  1205166 main/i18n/Translation-cs
 d70ae6198f35f876b3070d928d5cdba2   323247 main/i18n/Translation-cs.bz2
 3fa5a10989da6ec5b19b5b6ba161b0bf 20240560 main/i18n/Translation-da
 e83f678061ca99aaedd2f20cb75bba77  4411163 main/i18n/Translation-da.bz2
 9f5077418506388082a72c7023c56f8f  7801238 main/i18n/Translation-de
 a57e3821e975f45d21bf2388a190b770  1717951 main/i18n/Translation-de.bz2
 a344219bf0eec9139d5270017ecfceee     1347 main/i18n/Translation-de_DE
 0fe0725f74bb5249f15f30ce965142d5      830 main/i18n/Translation-de_DE.bz2
 87bf9810c05aba15fb4aca6791feb73d     6257 main/i18n/Translation-el
 002ddfc4187acd8414873fe9f0a6442a     1835 main/i18n/Translation-el.bz2
 36467cceb9cb2cea759d49c8759be7f9 30246698 main/i18n/Translation-en
 b4a727f22675ec9db1426d7dbc7a34f0  6240167 main/i18n/Translation-en.bz2
 0fdd8948881357f49ead0845c7e621c1     2261 main/i18n/Translation-eo
 43bd21f8b5d52b955e509e5893eef37e     1196 main/i18n/Translation-eo.bz2
 2ad9740f4bf39f163c04bd0b7266c1aa  1325929 main/i18n/Translation-es
 b4d4140461b4d6195e3337dcf541554f   317946 main/i18n/Translation-es.bz2
 2f7f0aac6c4ae5bd9c1499fd612ef996    10093 main/i18n/Translation-eu
 3178567e5f21fe43e4cf1f1a38ed6adc     3914 main/i18n/Translation-eu.bz2
 d1e71d50a88504d6b48c27960250acae   269212 main/i18n/Translation-fi
 9ca11408c191cfc5270f39467ed80f9b    75849 main/i18n/Translation-fi.bz2
 945a63eed28af4c45fd5185b334b33b3 11857302 main/i18n/Translation-fr
 06100e8db22b6d72d2c466bc85ea117b  2433064 main/i18n/Translation-fr.bz2
 f543980d7c6e8335eb0bb5d00b787418     1427 main/i18n/Translation-gl
 09c22bb0dfa3874802c4e7e4389f2b58      824 main/i18n/Translation-gl.bz2
 363537eb238e19bd527554a2d1de2533    21069 main/i18n/Translation-hr
 3fbd3535dcc2e805f0283d54bd38f5f3     4695 main/i18n/Translation-hr.bz2
 5393df220c56a4a92b91b2cac6843067    65236 main/i18n/Translation-hu
 61236a1bada04fd4ab090269498c5393    22243 main/i18n/Translation-hu.bz2
 d8d93a0510fedeb68fbbdae0342520c0     3983 main/i18n/Translation-id
 7542ee230bbc1f2f9f873c265b3b467f     1780 main/i18n/Translation-id.bz2
 87ba73fdeb9bac4348a4be42b2386f32 24489940 main/i18n/Translation-it
 9c9cd08156baf73f9f088bb97ac00662  4844227 main/i18n/Translation-it.bz2
 0f39595a0a049759d0d50ead781f73fd  4511401 main/i18n/Translation-ja
 74ff41ba40e19c9ceb4c607b122b7811   803966 main/i18n/Translation-ja.bz2
 85c4f9ec1e8e2d6faab177ef030ad2aa    11879 main/i18n/Translation-km
 46d57c586859cecf5c1a4470f666000d     2371 main/i18n/Translation-km.bz2
 def6a2d200b3c67b6a1c497524d0a631  2606190 main/i18n/Translation-ko
 3210a7e112a3f29ecf785ba05a78559a   584643 main/i18n/Translation-ko.bz2
 d41d8cd98f00b204e9800998ecf8427e        0 main/i18n/Translation-ml
 4059d198768f9f8dc9372dc1c54bc3c3       14 main/i18n/Translation-ml.bz2
 904af013a9ba73cd72f71a1ca451be5a     1193 main/i18n/Translation-nb
 bf917a722cf4d90cf2f56acb8edb1b31      738 main/i18n/Translation-nb.bz2
 cb57eb70e5645204174caec8edcc4a2b   174332 main/i18n/Translation-nl
 ad8c86dde21a892ff20203dc71eb981c    47973 main/i18n/Translation-nl.bz2
 bc88d84933fd8ae64ea0a7ba32a1e814  2051811 main/i18n/Translation-pl
 3095483ca3926b759de515651199283a   491993 main/i18n/Translation-pl.bz2
 d1736cf50b7994e7c6ce66962b7f4b03  1074959 main/i18n/Translation-pt
 7f9e024af1c410635fc69db5bf5d090a   272186 main/i18n/Translation-pt.bz2
 c3453467a749e3888da35949b643835d  3306707 main/i18n/Translation-pt_BR
 89726f5a5abac29bd3a6069e27019c9a   802734 main/i18n/Translation-pt_BR.bz2
 b50c9c49ea0a9da73b0a76db38a36ea4     1717 main/i18n/Translation-ro
 22696f68e30228ffbd84b26dbc821f81      982 main/i18n/Translation-ro.bz2
 52035b6ff376a4d7c38eea8bbd406751  3058931 main/i18n/Translation-ru
 d6c7de740e63ee4ce0e2044a0d449804   494782 main/i18n/Translation-ru.bz2
 2b383f6dbb23852965418241eda484de  5984088 main/i18n/Translation-sk
 04f2970e8de7fc5a090b84ab700cbb23  1304539 main/i18n/Translation-sk.bz2
 cf58326418b53f94289ad593878bfda2   323953 main/i18n/Translation-sr
 096b962e3404fbc28ebfb174e7587136    58385 main/i18n/Translation-sr.bz2
 366024c5bc4dabb550f8481c2d662611    85612 main/i18n/Translation-sv
 22b0c4eaa8e59ee11318ce2e68953f4b    27320 main/i18n/Translation-sv.bz2
 ced97abb44ee155f744680871aa5a6e2    14670 main/i18n/Translation-tr
 233a8366a334283e9b802cae336ed09b     5362 main/i18n/Translation-tr.bz2
 c8840c6e4bbe54b098d5b589e5d9e08b  3740343 main/i18n/Translation-uk
 7ed20cfd2585b8f77be6e2bab7561133   576766 main/i18n/Translation-uk.bz2
 2adb559c8ab8415644e43781db4f739a    21882 main/i18n/Translation-vi
 82caa7c535a1c4c7589a7b1647017f53     6510 main/i18n/Translation-vi.bz2
 f895594ce62c202132bbbe9ae32f1bc2     2007 main/i18n/Translation-zh
 3d2be55ee5ef9a79e0db9f90acc449cf     1215 main/i18n/Translation-zh.bz2
 91e9eec000876a989969a700ac7b3821   425199 main/i18n/Translation-zh_CN
 ab34838b3553d042d515eb65f5aa8816   113621 main/i18n/Translation-zh_CN.bz2
 34208715b80dcbd5fd1b87874a6705d4    39965 main/i18n/Translation-zh_TW
 6ed487c9d90ac9866174796ce73dec77    14859 main/i18n/Translation-zh_TW.bz2
 c8730ab591a9c561bfbe29bb2bd721d9    58277 main/installer-amd64/20210731+deb11u7+b1/images/MD5SUMS
 1a197cdc8ba7a3094159a1ebec0b24f9    78097 main/installer-amd64/20210731+deb11u7+b1/images/SHA256SUMS
 8521cd018a0e0b50238dab3cf673c4f7    57705 main/installer-amd64/20210731/images/MD5SUMS
 bb4d5d5a421f536dcaa3f2e4fc96c1c3    77333 main/installer-amd64/20210731/images/SHA256SUMS
 c8730ab591a9c561bfbe29bb2bd721d9    58277 main/installer-amd64/current/images/MD5SUMS
 1a197cdc8ba7a3094159a1ebec0b24f9    78097 main/installer-amd64/current/images/SHA256SUMS
 026bc90f5673b695c093e88b6e0ec351    69049 main/installer-arm64/20210731+deb11u7+b1/images/MD5SUMS
 5ef21176e2d62d993fdad8fe6f66d13f    94149 main/installer-arm64/20210731+deb11u7+b1/images/SHA256SUMS
 8544dac6e811bff5ed42e276cf530ebf    68403 main/installer-arm64/20210731/images/MD5SUMS
 7989c6f2e37aeda05d7dfc58de88d7f5    93279 main/installer-arm64/20210731/images/SHA256SUMS
 026bc90f5673b695c093e88b6e0ec351    69049 main/installer-arm64/current/images/MD5SUMS
 5ef21176e2d62d993fdad8fe6f66d13f    94149 main/installer-arm64/current/images/SHA256SUMS
 9d5c1487daa7fbbc0eb09a58cd905102    20678 main/installer-armel/20210731+deb11u7+b1/images/MD5SUMS
 9caca58b3425516dd16fec20f1ee05fd    28882 main/installer-armel/20210731+deb11u7+b1/images/SHA256SUMS
 6e3afe07880cea11cee1a8ac19ce5d13    20182 main/installer-armel/20210731/images/MD5SUMS
 350c18339820cfa3989e1297c80b9f12    28194 main/installer-armel/20210731/images/SHA256SUMS
 9d5c1487daa7fbbc0eb09a58cd905102    20678 main/installer-armel/current/images/MD5SUMS
 9caca58b3425516dd16fec20f1ee05fd    28882 main/installer-armel/current/images/SHA256SUMS
 b6629d5e5a8344e0905c72ed18aeaca4    64380 main/installer-armhf/20210731+deb11u7+b1/images/MD5SUMS
 3e31a8a4a6eac90bff6befbe1dbfc3cd    92680 main/installer-armhf/20210731+deb11u7+b1/images/SHA256SUMS
 3dca9930d681a0ba4186171684027ec6    64240 main/installer-armhf/20210731/images/MD5SUMS
 869454c4efa0fcddd91e08ab8ccf9d3b    92476 main/installer-armhf/20210731/images/SHA256SUMS
 b6629d5e5a8344e0905c72ed18aeaca4    64380 main/installer-armhf/current/images/MD5SUMS
 3e31a8a4a6eac90bff6befbe1dbfc3cd    92680 main/installer-armhf/current/images/SHA256SUMS
 d2556badb036046aff1f8d6eed468533    56840 main/installer-i386/20210731+deb11u7+b1/images/MD5SUMS
 87137d3494aed456f81705c70f5a8560    76724 main/installer-i386/20210731+deb11u7+b1/images/SHA256SUMS
 8932831dfc7fb479ada48f6936639179    56286 main/installer-i386/20210731/images/MD5SUMS
 0ccfb273991e3302a49093743aa9032f    75978 main/installer-i386/20210731/images/SHA256SUMS
 d2556badb036046aff1f8d6eed468533    56840 main/installer-i386/current/images/MD5SUMS
 87137d3494aed456f81705c70f5a8560    76724 main/installer-i386/current/images/SHA256SUMS
 998868016e1fdfa2a145942395800280      630 main/installer-mips64el/20210731+deb11u7+b1/images/MD5SUMS
 7aa9b76c5e09c5b05445ffa606fe53db     1026 main/installer-mips64el/20210731+deb11u7+b1/images/SHA256SUMS
 9533fc15e5b64180b5ad78129a5230b2      627 main/installer-mips64el/20210731/images/MD5SUMS
 a776640760fbaacfb1681f3abd0fb40b     1023 main/installer-mips64el/20210731/images/SHA256SUMS
 998868016e1fdfa2a145942395800280      630 main/installer-mips64el/current/images/MD5SUMS
 7aa9b76c5e09c5b05445ffa606fe53db     1026 main/installer-mips64el/current/images/SHA256SUMS
 fa571598ee1e33c6b2dbee7e30bbf665      630 main/installer-mipsel/20210731+deb11u7+b1/images/MD5SUMS
 6755ade8ad0a3238ef992b2b5b055c60     1026 main/installer-mipsel/20210731+deb11u7+b1/images/SHA256SUMS
 c3a9b6724a2ff5e2abf741f47a7600da      627 main/installer-mipsel/20210731/images/MD5SUMS
 01da3e1833ca954309023210e9b16159     1023 main/installer-mipsel/20210731/images/SHA256SUMS
 fa571598ee1e33c6b2dbee7e30bbf665      630 main/installer-mipsel/current/images/MD5SUMS
 6755ade8ad0a3238ef992b2b5b055c60     1026 main/installer-mipsel/current/images/SHA256SUMS
 a3b2d71556d4030ba67ddd5e2edb63cf      576 main/installer-ppc64el/20210731+deb11u7+b1/images/MD5SUMS
 fb4c51ffbc1c1c0de08e035cb06a0c63      972 main/installer-ppc64el/20210731+deb11u7+b1/images/SHA256SUMS
 37515f49026f1bc4682fefba24e9decf      576 main/installer-ppc64el/20210731/images/MD5SUMS
 89c70369e7ab670f721a135f055d81a4      972 main/installer-ppc64el/20210731/images/SHA256SUMS
 a3b2d71556d4030ba67ddd5e2edb63cf      576 main/installer-ppc64el/current/images/MD5SUMS
 fb4c51ffbc1c1c0de08e035cb06a0c63      972 main/installer-ppc64el/current/images/SHA256SUMS
 c89c26c2cc9d407be87915ad5de99f88      374 main/installer-s390x/20210731+deb11u7+b1/images/MD5SUMS
 0ac8638a6ff89d2f8e3ceb1c51b39eab      674 main/installer-s390x/20210731+deb11u7+b1/images/SHA256SUMS
 580b19117c2b6c6f2a8ad8aca5132826      374 main/installer-s390x/20210731/images/MD5SUMS
 da16ad53b0185c6e48397e05f2efadfc      674 main/installer-s390x/20210731/images/SHA256SUMS
 c89c26c2cc9d407be87915ad5de99f88      374 main/installer-s390x/current/images/MD5SUMS
 0ac8638a6ff89d2f8e3ceb1c51b39eab      674 main/installer-s390x/current/images/SHA256SUMS
 89ad4d3b28d51f39938cf10575544163      117 main/source/Release
 4dc0d4fb57d31a820d50565ca5904136 44655922 main/source/Sources
 6ca64fd70ce2f771595248c67b1d63ab 11429086 main/source/Sources.gz
 632766a36d87c6379182819386228c24  8633788 main/source/Sources.xz
 5f624011d3b0a82f23445c2861deac99 17347341 non-free/Contents-all
 c64dcd5c2b4db85f729afa8623adb65a   888157 non-free/Contents-all.gz
 d6bec1f2c68aa61c10d5ea048bb61876  1097448 non-free/Contents-amd64
 f5a3b5d556d2ac2276e434d47321c42c    79655 non-free/Contents-amd64.gz
 2a3fa76ebbc2b8ce1dc696fd4f93d5cf   499970 non-free/Contents-arm64
 6fbffff6347fe5e6e7099295803f549c    37376 non-free/Contents-arm64.gz
 f408ea79e9570389d5ee84acf709fefe    95417 non-free/Contents-armel
 b7a69ebcb774fa413e4016bb93c3d044     9298 non-free/Contents-armel.gz
 6778fabc7cec1e4431b4e6354d7c6331   146124 non-free/Contents-armhf
 146fba98ac2f400fe25facd0ca7aa193    13502 non-free/Contents-armhf.gz
 c2a617bfa92c1ae1471d92c59fe2e012   343198 non-free/Contents-i386
 1550b2598d6a74262e40f69cc64ed0e1    29072 non-free/Contents-i386.gz
 900df746b6e7accfd8883d31c7d28313    91215 non-free/Contents-mips64el
 7c382180d55972ff768bb8a05222a412     8686 non-free/Contents-mips64el.gz
 904ab7d197244bdfdbf6b58bc61d09ac    92244 non-free/Contents-mipsel
 73868036dab5f62f60ad63ebfb7ca253     9026 non-free/Contents-mipsel.gz
 9ff21fb911bfd562eb84f85d9adda009   716110 non-free/Contents-ppc64el
 5c487a4250d7e24f4cce14e8e7c430f0    49881 non-free/Contents-ppc64el.gz
 f3aa91e39f1d170310ec9820ea4dae2d    74537 non-free/Contents-s390x
 2b363c4c14b66b56f3009f85c29415dc     7407 non-free/Contents-s390x.gz
 28092fe18d286a60369b2baf177a3b66 10803369 non-free/Contents-source
 a1340038124c66a82eb9afd4e0a5b39e  1063443 non-free/Contents-source.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-all
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-all.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-amd64
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-amd64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-arm64
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-arm64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-armel
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-armel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-armhf
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-armhf.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-i386
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-i386.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-mips64el
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-mips64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-mipsel
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-mipsel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-ppc64el
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-ppc64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-s390x
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-s390x.gz
 28683b0c800362ab66657f988f8fe158   189021 non-free/binary-all/Packages
 8b503f66350a43348e728ef668a3e66d    50928 non-free/binary-all/Packages.gz
 89e1a28553ba1bf59ef7a537d0e13dcd    42996 non-free/binary-all/Packages.xz
 7e31516542d9449a20d6d5a5be387724      118 non-free/binary-all/Release
 48fd35f0f54926f3b555aca2d9cc267c   545576 non-free/binary-amd64/Packages
 f4a7af068e39f558fb3c7d38d7227d31   122225 non-free/binary-amd64/Packages.gz
 90b0a4d2ddb8c4e4a507459f79006f8a    97772 non-free/binary-amd64/Packages.xz
 e1a343e13638a8191104cc84d9c87347      120 non-free/binary-amd64/Release
 d1b662147ba2a93fda8daa87bcc45a4f   381335 non-free/binary-arm64/Packages
 0ea4ed22af6d2313b0e15670783ff965    88201 non-free/binary-arm64/Packages.gz
 471ad96a8a2139576049b8bc0a7541de    72980 non-free/binary-arm64/Packages.xz
 9e926156e80b4e4db84524d2f0079024      120 non-free/binary-arm64/Release
 0967ff1cbab012d79d544d2fc19bcb3c   227933 non-free/binary-armel/Packages
 66f87c4a0607b4d535045f41bb1debbf    61822 non-free/binary-armel/Packages.gz
 943edb5f2d977c5e883e123d7a162a3c    51800 non-free/binary-armel/Packages.xz
 096a48f395e2487865b756ea3d0e20ff      120 non-free/binary-armel/Release
 11aef19231277b7df07bb88b31da40fb   259156 non-free/binary-armhf/Packages
 f084eff9f9e23dd4f071fc6caf167026    67317 non-free/binary-armhf/Packages.gz
 478795a629bddb465e832a8c15908d23    56272 non-free/binary-armhf/Packages.xz
 b94819d3bb5bb39f9abcf15388d47bf3      120 non-free/binary-armhf/Release
 cf0f27353a145dc9a999d6ac8f2b242d   422388 non-free/binary-i386/Packages
 cac7e560af4f05675b65252d54968a1e    96319 non-free/binary-i386/Packages.gz
 d528af0816ff9a8b491442be615e0875    79344 non-free/binary-i386/Packages.xz
 4a714713c871406dae3fee358bf4525b      119 non-free/binary-i386/Release
 b241349c71327389608d1ed7805fb917   225506 non-free/binary-mips64el/Packages
 79ea1e07e0c12ca9587d966e90a803d3    61024 non-free/binary-mips64el/Packages.gz
 800788cecc80de3a8dc8555edc4e1f3c    51124 non-free/binary-mips64el/Packages.xz
 9673c21044a83dbab7dd0cc54a4e02c6      123 non-free/binary-mips64el/Release
 5637ea382ea6ea47628b489854f51823   226162 non-free/binary-mipsel/Packages
 cb900ebc58b732e246dad1c05c2da62b    61277 non-free/binary-mipsel/Packages.gz
 eefd4b08c8da7bb89f71627c9f05a04e    51364 non-free/binary-mipsel/Packages.xz
 c3acf902cc79cfb97370b0efec244dea      121 non-free/binary-mipsel/Release
 4404ce86106e7e32bd47bd465f954e8f   381597 non-free/binary-ppc64el/Packages
 9e8c1c8f825dd79ed1d335608297770e    86900 non-free/binary-ppc64el/Packages.gz
 ffe9119e39ab6813cdd7dd7b5b8299a0    71812 non-free/binary-ppc64el/Packages.xz
 79b2651c4e8f6dc350c53e634f30ef2d      122 non-free/binary-ppc64el/Release
 205f9ec14fe81d12021eba70ac927040   220570 non-free/binary-s390x/Packages
 73a6b1dbd8f6c0ffbc4cb90c8737651b    59856 non-free/binary-s390x/Packages.gz
 d4f95c7b3fed2787ebb231f6e8fea4ef    50216 non-free/binary-s390x/Packages.xz
 cf48e148549473e729455b280f93e43c      120 non-free/binary-s390x/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-all/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-all/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-all/Packages.xz
 7e31516542d9449a20d6d5a5be387724      118 non-free/debian-installer/binary-all/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-amd64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-amd64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-amd64/Packages.xz
 e1a343e13638a8191104cc84d9c87347      120 non-free/debian-installer/binary-amd64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-arm64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-arm64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-arm64/Packages.xz
 9e926156e80b4e4db84524d2f0079024      120 non-free/debian-installer/binary-arm64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-armel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-armel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-armel/Packages.xz
 096a48f395e2487865b756ea3d0e20ff      120 non-free/debian-installer/binary-armel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-armhf/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-armhf/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-armhf/Packages.xz
 b94819d3bb5bb39f9abcf15388d47bf3      120 non-free/debian-installer/binary-armhf/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-i386/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-i386/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-i386/Packages.xz
 4a714713c871406dae3fee358bf4525b      119 non-free/debian-installer/binary-i386/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-mips64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-mips64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-mips64el/Packages.xz
 9673c21044a83dbab7dd0cc54a4e02c6      123 non-free/debian-installer/binary-mips64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-mipsel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-mipsel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-mipsel/Packages.xz
 c3acf902cc79cfb97370b0efec244dea      121 non-free/debian-installer/binary-mipsel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-ppc64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-ppc64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-ppc64el/Packages.xz
 79b2651c4e8f6dc350c53e634f30ef2d      122 non-free/debian-installer/binary-ppc64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-s390x/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-s390x/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-s390x/Packages.xz
 cf48e148549473e729455b280f93e43c      120 non-free/debian-installer/binary-s390x/Release
 f7208886e345a2c1c5681b7bc1f891f3   278293 non-free/dep11/Components-amd64.yml
 ab8bcc71919bb29e6a367d9058dc0125    29634 non-free/dep11/Components-amd64.yml.gz
 afd21b4c476c6b604c4f998d90383234    17904 non-free/dep11/Components-amd64.yml.xz
 71e3cebf69c369e3d4e6b64e48fe037b   271451 non-free/dep11/Components-arm64.yml
 4b40bf8ff6579f425fd308cc4f32bb26    27686 non-free/dep11/Components-arm64.yml.gz
 04fa2b6c4dc8d23f6ee6334754b725df    16392 non-free/dep11/Components-arm64.yml.xz
 678290cc20fe4c69fac625c25f48577f   271451 non-free/dep11/Components-armel.yml
 b76376c24cdd9bb014e63503830766f8    27606 non-free/dep11/Components-armel.yml.gz
 b431acc1b0f700a021a3ab1305bc3c33    16448 non-free/dep11/Components-armel.yml.xz
 7f659804cad02381ed7735779c211771   271451 non-free/dep11/Components-armhf.yml
 0221ab3c0654617c6de5d2b74eac7b15    27691 non-free/dep11/Components-armhf.yml.gz
 2df1dfb4d502d5c01f744bac99e8a0bc    16364 non-free/dep11/Components-armhf.yml.xz
 1422b7cb028418049315374e46dcbf86   280613 non-free/dep11/Components-i386.yml
 7a014ddef58173efeb07ce9d7b866331    31098 non-free/dep11/Components-i386.yml.gz
 ee2f702d30a2274d969a8e9044da54f2    19156 non-free/dep11/Components-i386.yml.xz
 2f39022b38ebd28b86acd148ad0389d2   271451 non-free/dep11/Components-mips64el.yml
 5e839450348a20fc9f81cdc9dd0b9663    27765 non-free/dep11/Components-mips64el.yml.gz
 fbf40f634081acbde994e89d8731d159    16380 non-free/dep11/Components-mips64el.yml.xz
 4ff7e301bb5eaab539783f39c24b421f   271451 non-free/dep11/Components-ppc64el.yml
 d7c37af104343f2eb2b10a0980c96661    27592 non-free/dep11/Components-ppc64el.yml.gz
 afabe491b91df1be19287ea4e978e7aa    16576 non-free/dep11/Components-ppc64el.yml.xz
 05dc5f141a7ca96f1aae6d571dd37361   271451 non-free/dep11/Components-s390x.yml
 4a5b9e250991cd5d661db03f4bebefa8    27558 non-free/dep11/Components-s390x.yml.gz
 b0593a88d870f066f1a83dfb382e09c5    16356 non-free/dep11/Components-s390x.yml.xz
 40dd67e0e1f81416405be5c0dc8ee47e     8192 non-free/dep11/icons-128x128.tar
 b117213e4fd39f9c75c1699ebaf3d610     2394 non-free/dep11/icons-128x128.tar.gz
 08a465949d80332d065e6f4ec8459930     4096 non-free/dep11/icons-48x48.tar
 49466a3c36fe0d0cbb5940896da60960      741 non-free/dep11/icons-48x48.tar.gz
 5d6e61a41610797276e5b6f16d60f7e1    36864 non-free/dep11/icons-64x64.tar
 0196f7b979db4111a6d9b988e63101a0    27667 non-free/dep11/icons-64x64.tar.gz
 c423c38128e8f1d7984682751173441c   572893 non-free/i18n/Translation-en
 65a9781186757af5a261165878a7f9b0    92419 non-free/i18n/Translation-en.bz2
 d48a4039dfcadee2dbc49be8216a78f3      121 non-free/source/Release
 1ebf108ffd532e93efc36f22d900441a   360307 non-free/source/Sources
 85f6ca3b8dfaa5af893d96ea4b759971    98323 non-free/source/Sources.gz
 10afbe839c1da98bc50d6dc6506652a8    81280 non-free/source/Sources.xz
SHA256:
 3957f28db16e3f28c7b34ae84f1c929c567de6970f3f1b95dac9b498dd80fe63   738242 contrib/Contents-all
 3e9a121d599b56c08bc8f144e4830807c77c29d7114316d6984ba54695d3db7b    57319 contrib/Contents-all.gz
 e60f82140294e076f97a4148cfd8e594ae808c423d40b62be455bb28af8fb6d8   787321 contrib/Contents-amd64
 845f71ed2a0a3ea784c355427362164cb316b01e6ce956a38ea95a001711709b    54668 contrib/Contents-amd64.gz
 1ad2b49ab401affafeb146c2badf94f1d699abd27f52b57d5e4b0fe3d37c9682   370915 contrib/Contents-arm64
 5f54b4d15ca5a9308eee238da9fa9512dcf8ec15a55cc22fce4efc3142146c01    29596 contrib/Contents-arm64.gz
 b4985377d670dbc4ab9bf0f7fb15d11b100c442050dee7c1e9203d3f0cfd3f37   359292 contrib/Contents-armel
 f134666bc09535cbc917f63022ea31613da15ec3c0ce1c664981ace325acdd6a    28039 contrib/Contents-armel.gz
 b5363d1e3ec276a0cb10bc16685bd02bdc330719d76c275bebd344adaa91583b   367655 contrib/Contents-armhf
 fc4edd280f2b254dbfa98f495e5f4ca6047ec9a1539ccb8754a1f93546ea32b5    29236 contrib/Contents-armhf.gz
 77d465435ba8f5bad03b76624835f91e9ebf3bb09b124ab1a06e70c8b2629b30   407328 contrib/Contents-i386
 e4a82b31ac7b5b139fd3bd93ad466de75f7bf7d54410967253044895e41c36fb    33556 contrib/Contents-i386.gz
 c0efa60eaa3b47bd93ca71220c6fc734d54b257e16bb6dd8dde43ca722f242dc   359402 contrib/Contents-mips64el
 4fccf5298ef664c2de3dc7eeb203eefa3bf8ec82b95b1c696b856a43af35e395    27962 contrib/Contents-mips64el.gz
 db2388b4b8d300fdc265fe064288a8de5f69958b06ed6cfeff3b8528e719015b   360549 contrib/Contents-mipsel
 27db69688406433748363f4a70cac108f29b99555a6d5dc3eaba6b2e8b526dfc    27942 contrib/Contents-mipsel.gz
 e62412c1f585461c8ae27d4d2a79b82c27dba109ac19df81a15ae7f53369cf65   370025 contrib/Contents-ppc64el
 8ac6ff54ba23486d9c139ee79a6296760dc20022209ffc321296967717a37fd2    29381 contrib/Contents-ppc64el.gz
 bb1fdc3fafd28760f57d951e96a150e8ec7d6b0fb75443de93f08a61ffbd7042   357860 contrib/Contents-s390x
 009373ff8cde80de63a4303b8c6eab79af34d6c2c0c831d1b38e1f9329c396cc    27518 contrib/Contents-s390x.gz
 7d79e95f92007f2885bba7ff9d40a81cefea96959cb090dc7cde26a77e7f1ea5  6722669 contrib/Contents-source
 d6655657ff285c9372e18b0ebff346e922694de31669d6c0260e789306841e9d   469817 contrib/Contents-source.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-all
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-all.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-amd64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-amd64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-arm64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-arm64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-armel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-armel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-armhf
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-armhf.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-i386
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-i386.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-mips64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-mips64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-mipsel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-mipsel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-ppc64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-ppc64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-s390x
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-s390x.gz
 70d58353b3bc6083f3946ebcdc1f150204988bed60df8c0389fa23b26924adcd   103239 contrib/binary-all/Packages
 9baa8f0dbe243eea5e03bc9551b0e5774ea0ba690db28ae63d1f81cd6e16aef7    27385 contrib/binary-all/Packages.gz
 24cb5963261a9cb0a4671061d65ee51e211e00ea754e4f5ec6426a1a78745ec1    23916 contrib/binary-all/Packages.xz
 93a2ce91dbee932c8b48caae660d67b864819f239de1cf9c85cbfeb3c450e396      117 contrib/binary-all/Release
 25bba54443595d2760419c8873b026880ad3553697b4254f0473b7c859c3526f   231878 contrib/binary-amd64/Packages
 05b545380de2e24307c4b33497327a397b5fac53c53c2479d487280c69c55b7b    60884 contrib/binary-amd64/Packages.gz
 572aa5c4767342e411f9ec261ebb871a48da20400d37e9f960c0f3960a26fc66    50588 contrib/binary-amd64/Packages.xz
 4c337ceffea66616199c9d6f6f0996dac105940b4e220425a12c9ecba87a1ff6      119 contrib/binary-amd64/Release
 7ab66ca6c3c1f575100f8e39fee460115ba8292a489c07e9ea1b0a914e47f67c   180884 contrib/binary-arm64/Packages
 4da911f1c6926b85d6a9a025d73be907124db4a3e99872b0128ad2187a5af5ef    48958 contrib/binary-arm64/Packages.gz
 07b68a663f305c1a676642f078a3d9243072e2f2402ad87c405f0a4c7744cab1    40964 contrib/binary-arm64/Packages.xz
 1b6ff9a1c182ed456e4aeff56a54eddfb128ce6c39877b70769dd79e012143f6      119 contrib/binary-arm64/Release
 d353d3f7b451cb07472d111221866fd89c6e7b28ad0fe66044f35e2eca6189fc   163042 contrib/binary-armel/Packages
 5333591cd2ee7e750d864f875799c83b4985f0473a02e525365db3fc5b27ab36    44389 contrib/binary-armel/Packages.gz
 6493591c5f010aa3b50e7052c4746f6afe40a0fd31ffcce08c706aec6e7b672d    37452 contrib/binary-armel/Packages.xz
 04ff4b12d802b8291b4408a1435e0e11424b96e1628d10981b18d7bfbe481708      119 contrib/binary-armel/Release
 75d98358dbea38501853ae9cd7a2da4f84d02eb4543bd9e96f0c3e6cd5945533   175566 contrib/binary-armhf/Packages
 fde856e3b07624cb5e3d6c11dd450aae8e56f38646c4b3f3b7cbe0423f78970e    47805 contrib/binary-armhf/Packages.gz
 c572038b5ced50f74da2baa5cda8150846cface0b285218336f6af4e1365b9b0    40220 contrib/binary-armhf/Packages.xz
 d37bedd8d7cdad30b0f6699f0b0c12d60cf2a9a24866e5a256a957d625b62b8b      119 contrib/binary-armhf/Release
 6b9d6d64b15686f83bf58c5e2255bdef26a5f2cdd97c76b047ea46f533aeb0bc   203514 contrib/binary-i386/Packages
 010b321fd585b2d1c45512db80e60aefdd0fc7bbc60a53e1594ba9ad5f9ba45a    54100 contrib/binary-i386/Packages.gz
 a17c01bbbba0f218b3a38cb5b7fc3053a7cfb6364453b46b6b80687d11eab142    45340 contrib/binary-i386/Packages.xz
 4ce72f7efaa89af0624897fe2cd8495e137d4e5e0f5320cb44de27fbc3b02986      118 contrib/binary-i386/Release
 4c71f56a967f6f390c1e6d381f399d74da5a545c8906f014fe805859ba9ae55c   163507 contrib/binary-mips64el/Packages
 49f3fc82266f184e331b2b0ea0762540b8ef68486f299a5673b247f8c03d3858    44652 contrib/binary-mips64el/Packages.gz
 e0c365ed89f4538b36ab3366293d3b9f4e8472b9537d91b770f650650021f4e1    37496 contrib/binary-mips64el/Packages.xz
 59e8e1e1ec5e0d469be59b6d3321aba3f9ddd686e440bde74616b2acce355b41      122 contrib/binary-mips64el/Release
 a951b730b4a059ef33073627d50a40f204591c3a5348fbe1c5e3b21782a77e5a   164647 contrib/binary-mipsel/Packages
 662a2fb412beb7130ef5ba0440ec368825d21713392a55ea33048673bbcca3a0    44883 contrib/binary-mipsel/Packages.gz
 7a01af1780b68648eec3923fbe4fe766e210e83f0ba8b03f6bc8b9a8d4c0169f    37816 contrib/binary-mipsel/Packages.xz
 9df253300a3c33585a18f1c8b91018a558e04a222a70ce8072f76ea2e2b27ad1      120 contrib/binary-mipsel/Release
 8ff5ce44abf0d9fba97b3ce63b2d41db58d24b463dfe23cf06069a71724f7047   180387 contrib/binary-ppc64el/Packages
 ddf5d43553c9af8a6dfa0ff6f51236dee72fe15d2a09ecc9212bfeee5e667e92    48843 contrib/binary-ppc64el/Packages.gz
 84cd02fcb4a610501538fd06ebf77a67ef7badcbc6f5b1f338c6d013329ea38e    40808 contrib/binary-ppc64el/Packages.xz
 57f78f401d86eaadc5fe6ca190f162e4a0fc1e77021a6118f27aab68db0d7f82      121 contrib/binary-ppc64el/Release
 cfc032377fc264eff4a6319ecfd2722e95de7364a63b29eed53cc78603a8a8aa   162250 contrib/binary-s390x/Packages
 72be2806452fee7d70ef80ffac98e3f408e7389dbbbaaa6d9228f48a6733b773    44334 contrib/binary-s390x/Packages.gz
 9a14a52c690b24eb92939192abc4d4e8b23a2347a838232774016ac79c3d8ec8    37244 contrib/binary-s390x/Packages.xz
 cb54af7d630a4046eb41cc3096838019e16b72f3c0f505136788bcf09fa632c5      119 contrib/binary-s390x/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-all/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-all/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-all/Packages.xz
 93a2ce91dbee932c8b48caae660d67b864819f239de1cf9c85cbfeb3c450e396      117 contrib/debian-installer/binary-all/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-amd64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-amd64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-amd64/Packages.xz
 4c337ceffea66616199c9d6f6f0996dac105940b4e220425a12c9ecba87a1ff6      119 contrib/debian-installer/binary-amd64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-arm64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-arm64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-arm64/Packages.xz
 1b6ff9a1c182ed456e4aeff56a54eddfb128ce6c39877b70769dd79e012143f6      119 contrib/debian-installer/binary-arm64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-armel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-armel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-armel/Packages.xz
 04ff4b12d802b8291b4408a1435e0e11424b96e1628d10981b18d7bfbe481708      119 contrib/debian-installer/binary-armel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-armhf/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-armhf/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-armhf/Packages.xz
 d37bedd8d7cdad30b0f6699f0b0c12d60cf2a9a24866e5a256a957d625b62b8b      119 contrib/debian-installer/binary-armhf/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-i386/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-i386/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-i386/Packages.xz
 4ce72f7efaa89af0624897fe2cd8495e137d4e5e0f5320cb44de27fbc3b02986      118 contrib/debian-installer/binary-i386/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-mips64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-mips64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-mips64el/Packages.xz
 59e8e1e1ec5e0d469be59b6d3321aba3f9ddd686e440bde74616b2acce355b41      122 contrib/debian-installer/binary-mips64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-mipsel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-mipsel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-mipsel/Packages.xz
 9df253300a3c33585a18f1c8b91018a558e04a222a70ce8072f76ea2e2b27ad1      120 contrib/debian-installer/binary-mipsel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-ppc64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-ppc64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-ppc64el/Packages.xz
 57f78f401d86eaadc5fe6ca190f162e4a0fc1e77021a6118f27aab68db0d7f82      121 contrib/debian-installer/binary-ppc64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-s390x/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-s390x/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-s390x/Packages.xz
 cb54af7d630a4046eb41cc3096838019e16b72f3c0f505136788bcf09fa632c5      119 contrib/debian-installer/binary-s390x/Release
 f0a51e6d75f883bdecf739b214104a17dba111de8b42022f6b8b053870c83851   119152 contrib/dep11/Components-amd64.yml
 e14a1bb3690a18ec7c5b7997fabf4d8d4fa633efdf84a25e071a1f62a2c064b2    15579 contrib/dep11/Components-amd64.yml.gz
 58921318632f77413bee8d9e980689f8f139eb1169b5ce201da06e6f280d485f    13564 contrib/dep11/Components-amd64.yml.xz
 26538634f90cd6f04a6be602151fa6a098075c3013b66a81439a7bbdbfaa40f5   113437 contrib/dep11/Components-arm64.yml
 840908ab753dba952e073216007f93d351577792911dcc09a15a16abfc32c8a7    14251 contrib/dep11/Components-arm64.yml.gz
 3afec5908036aa2d47b9a9a33c13eca12bba1aaf8d8bbb06ffb1627e93f6526f    12480 contrib/dep11/Components-arm64.yml.xz
 fb35649f6c32b71b9d85388c2c238011161c250df5c62e2c4d3446e369dced4c   113437 contrib/dep11/Components-armel.yml
 c305f1c0826e0414bbf36524d8b0fc2723ffc0fb222275e1e1728914fc334c75    14029 contrib/dep11/Components-armel.yml.gz
 fe15a53774801f8d9cb04aa8324cbdb9d741ec75ae0999e033873458bd6160b0    12524 contrib/dep11/Components-armel.yml.xz
 0ed24b6d7ff891c82697497dddfbbbb6818c168c55b41ae710e9cc9240d0d9b2   113437 contrib/dep11/Components-armhf.yml
 f5260cdac915ff5eba0a48757c93f8f8b6421a673e641285f43d83f62be3eb8c    14127 contrib/dep11/Components-armhf.yml.gz
 db97becd2ab6a05bcef05d824b89080a1e7c03a69735df3bf5945f6989a9e504    12480 contrib/dep11/Components-armhf.yml.xz
 9adf35216113140c31c2e9c169a3eaa465044f41f8803afaac955c467a1e5a49   118972 contrib/dep11/Components-i386.yml
 c1d4ea9c0ac26f2b62d45c8c595ec9a5bc1c737b50634d7f86a4bfac17c9b180    15566 contrib/dep11/Components-i386.yml.gz
 51ff60d5f02b46e08acea4054484f5c66d721c19beff4857cb2570f43e881a69    13560 contrib/dep11/Components-i386.yml.xz
 50b6970af7de299a90ac651cceb6cc011e8d165ea0701f7b1c9daf6c1be485f0   113437 contrib/dep11/Components-mips64el.yml
 78aad16ddec6b18d30ce4e20f52008f72efc78ba55688fa462741f4bb514043f    14056 contrib/dep11/Components-mips64el.yml.gz
 efb0fb003bbd3997128bef56f12104872604fad320b38fd99bca25e68210d98e    12500 contrib/dep11/Components-mips64el.yml.xz
 05c2268c20e748baf8da20f7169918e2f6dcffb6e4f6dfc22829607cec7ea564   113437 contrib/dep11/Components-ppc64el.yml
 19f600014e245e7d07762b7f07d8de6884b1208a280a19274e56b4174931082a    14219 contrib/dep11/Components-ppc64el.yml.gz
 dc8b525d7043ba3a85154ad39d0c809e7215c5b2f3865efbd94ff3daabe54810    12496 contrib/dep11/Components-ppc64el.yml.xz
 5d43b650d261ac23815d98e9a4f644d56f4113e63f8a42b1558ff1c82e925d2f   113437 contrib/dep11/Components-s390x.yml
 c1811e0538dad96441a4172e661b9ef7fca9c05d86c4b157a66046bf49aa70e1    14050 contrib/dep11/Components-s390x.yml.gz
 42356b4c04801189947748d6fce6e28e356a114869a7895e4921a3b4901e678c    12488 contrib/dep11/Components-s390x.yml.xz
 641e9a50f98d7e4921102164e7737b095c9faead09f6de4459086b598b3bf0d0   271360 contrib/dep11/icons-128x128.tar
 34b531c5292651ac5a18d0477bb8cf1420f3d969ad73d45fd596641d768b853d   195507 contrib/dep11/icons-128x128.tar.gz
 fa3a19603046c258e647b0c1fcdc6110f0b5c1f2801ee950eb1261e8c02e03d6    83968 contrib/dep11/icons-48x48.tar
 28a6f153e56e9b567cc7fc03d6faa6dfb8480ee3f36e0c8d9646e4de3898480b    47168 contrib/dep11/icons-48x48.tar.gz
 d882fc33534a8677ed8d3ecf81f7a076fa57e8e8135bf586f8af20371edb195b   138752 contrib/dep11/icons-64x64.tar
 45c8eda64d05f1feee0040809128760f9489665d66bed0502cb179fe0ec79f6e    93294 contrib/dep11/icons-64x64.tar.gz
 094badc305c90db005324c484a55d88f14dfc805aa429856a5863a96518a88e8   192685 contrib/i18n/Translation-en
 ce7d3d607194cdfabf421c313030e88876ee899d5cd01f5b023cfdc0c0ed0f40    46929 contrib/i18n/Translation-en.bz2
 b89a3b9258ada994f8857f734110206864802d179201da6fa97a666db306ada9      120 contrib/source/Release
 e331ac856d30949d3d70b299678f1f23462785681c70a62205ae35903d2c50d0   178776 contrib/source/Sources
 b34bb0d3527f1086ae23a6d2ae47bf790572a7d07ff0ad444f0f2c68afd3c504    51355 contrib/source/Sources.gz
 99262e6c7f527f6654eb8e8b3415ee29fa5f2669d9bc22ce95881422b4b9b603    43208 contrib/source/Sources.xz
 2400074e2a3897ad55b2e0e110b3ad66af9446b0cb77e28c7d5c92abf0a60db1 477769406 main/Contents-all
 a61ae2ae233b5eb73a624cc09c8df2eb3beab0ff44fd7cc75d2e64eaf36d2204 31069218 main/Contents-all.gz
 226a3117b453b3350ee326fa65963b4936e6f5f0f0baabfc71ebe9458b3a5735 129058022 main/Contents-amd64
 ee49ff0f5accae61de15bab5f6afd31d6b0b4676d59c9930fbe6dc24ed54954c 10270460 main/Contents-amd64.gz
 13b617dbf9aee8e874fe709647f47bd2ee3780f4cf7c717f33aa7e1cd58d5e3c 122426895 main/Contents-arm64
 68d31c4707f80bb72cd02c1276b53e22b5c0175a7f46bf75da6eecb754f8aff3  9831920 main/Contents-arm64.gz
 5586eebc2846a2c4537cdb9020b216dd67b8c0eddc5a3bb8a9a0a6155e5946d5 104683113 main/Contents-armel
 780507976f07c70aa2e787b9a6f9cab2ed8b1aed99b726906677d8e4ce1c8436  8703570 main/Contents-armel.gz
 6f02632c558a77c4d6a78d64b437bc1c25857a4d04250abb51c5f13b3e86c119 113716591 main/Contents-armhf
 22f19d2f3ae739ba4f7b0d0bf2effab552e64aa65c8a236b16c069e9fb8e5e90  9305906 main/Contents-armhf.gz
 1c9cecfb8e79dfebf5d5cf0dc17271c2419fa72a4ef6e3b4b9e5ef1e3acad18c 129088857 main/Contents-i386
 b826bd0b623bdce4568f0f1f8205c8f6f4e50b8ecfcd99a3b26bbddaf3900f8e 10208982 main/Contents-i386.gz
 2a03448109546da0c72c31d0a534637306106e2195bd10b58aa2237ea60095f9 111097071 main/Contents-mips64el
 147af2223dc310a089b0d18c820421f926d33e24ce2d0dbc6b20203c35cfffb7  9042221 main/Contents-mips64el.gz
 6ef7f5d32e074dfe0231fbb8ac14f3cc67b511f924ec502736afe36cd549774a 112593872 main/Contents-mipsel
 a28b893a37dd761f6c95c0f6c722b9ac5324869d91bfc97cd7a1270159ac939e  9178325 main/Contents-mipsel.gz
 720f513250bebd466149094ff4ca8f8e1b412810a218f1cddfaa31163577f44f 116027632 main/Contents-ppc64el
 a852312c04f59070951821eda6893270b28d23e12977f77a0933cce2882547e5  9355024 main/Contents-ppc64el.gz
 c92fc53215a097d7be1cc62c20946a4744221ba8dd58f62a81258fa79021aa06 103638209 main/Contents-s390x
 e1ed13910c59f0df90724c116450ac3aa2936a2d89497bbeb263993b9e767102  8711885 main/Contents-s390x.gz
 19cb2eeeb6bb6459bf824cfbe9a82c44298fbd2ccb614ad130583fb5b07f3be3 690410830 main/Contents-source
 2d5b1d50f3f42a073f6b27127bdbc0e19870188aecab8417dc32dde30138fbe1 73501881 main/Contents-source.gz
 b709d41e19af82147c367d90a74eae144ab18744d78817b6395fc1344fb99c76   157382 main/Contents-udeb-all
 f9801d96354f0b11d5357633cb9068dff1f39b9210eaeb70455db63ee0ecbdbc    13516 main/Contents-udeb-all.gz
 88d816aa94f2071b483a84751d8109af7e89e049d9a5d690e2fc75a1fd86a9dd   477050 main/Contents-udeb-amd64
 1344217ca4f19362a2bcbeb119e0a6d36e853481086431794142a930b46b13b8    36011 main/Contents-udeb-amd64.gz
 5860a70ba4852152099c974ee16e92c0a935f6f96257204313ca99e8169826fe   508817 main/Contents-udeb-arm64
 71a73fbf6e739034fd57e1a8255565d260b91cbce409128dcc69fa059623dcd2    38139 main/Contents-udeb-arm64.gz
 b4326a16088882aa0a038240624002e1994e232d98f4194b65907be2f94270b3   323083 main/Contents-udeb-armel
 53c51078092e821f51bfa9477f35bd2a2148f045b5f6ae06a42b4ac79d440c42    25477 main/Contents-udeb-armel.gz
 e85592b3fbaaa08298eb08c7ee40c80c3826b961f3fcee0de1b6cedc0bf283aa   579793 main/Contents-udeb-armhf
 a9694e389e0c7eb23c9bad861b0f07db9114a4f4abf4648081b7640783c1e52c    43153 main/Contents-udeb-armhf.gz
 286e7790529e1012095eeedadef806ab30696dbf3ca55ecb55cd91247d239287   751383 main/Contents-udeb-i386
 bbe85229c4d8e20b737bf432e365a3efd51fcf557df061db147e9f63a322b69f    53984 main/Contents-udeb-i386.gz
 fcc311dbf697321971d9608ffc05555edbce48bd126b6d1d2b7bcd9a8eab0a25   760534 main/Contents-udeb-mips64el
 15bcf854ec4356278e912856e3904938ea994ae9742818854912126ee15f9cfc    52873 main/Contents-udeb-mips64el.gz
 572ddd8f7183d851c2fcfcda55166cd4ddb95b6eba0b73c07572dff8e74f797a   760210 main/Contents-udeb-mipsel
 d51989963ffcccba95d5591fe78e9aa6ecefd480f7464a199288d7153ea1a637    52810 main/Contents-udeb-mipsel.gz
 c6e87c5351596a66921e0559dcfdfae17c52cb422c709f2e44b19cf6064e80c9   401639 main/Contents-udeb-ppc64el
 3a94166a9523c86e71d08304a2bd46dd72392738f22b608a4b2b45fb77491f58    29533 main/Contents-udeb-ppc64el.gz
 42b53406c44e9439e86506343040298b5e1405e6791594953bb058ca6effe8f0   258318 main/Contents-udeb-s390x
 ce12cd039c002aeef6d9b364d73e313712d4d39970241953919fa6e8db0ce628    20894 main/Contents-udeb-s390x.gz
 b42ce26db7c150a2dbac237732eb0e5dd5ef28e2ca51a5482cd9293dc64d8357 20423830 main/binary-all/Packages
 33eec3157da3c566e1f078bff8b46bd6074dcf3c9f242c760b8fcb2233bc5d32  5208282 main/binary-all/Packages.gz
 09728ec87e7b549eaa43b80fbb9432e36043b9874cb4b3f95428a1eb2a96582f  3918264 main/binary-all/Packages.xz
 5fca0b091a4008553328742c4e5509375042ae86fd25e078e5641da80c6e35ed      114 main/binary-all/Release
 35eb7de95c102ffbea4818ea91e470962ddafc97ae539384d7f95d2836d7aa2e 45534962 main/binary-amd64/Packages
 a445d7472b76164584ebd9aebed31517837dac1f792164bba926278dcb166255 11096605 main/binary-amd64/Packages.gz
 9b3d1e096767eae5ade343b1b123e1787cc49cc78b139db247fbe96f8f3f545d  8182920 main/binary-amd64/Packages.xz
 ab78444b1bbaa56630b4f90edc8982f4fd965ac4db2b5530855b768c1c8fa9f9      116 main/binary-amd64/Release
 d908fe964d366107388f445a2afa408224ccf6a665ef087f26afd1cfd2b9ad04 44816551 main/binary-arm64/Packages
 1afdf5fece156bfb26fcb25409a00defecc507b38ae69097a09b18ff6b1d2b50 10941625 main/binary-arm64/Packages.gz
 d2b7315d4fda95e5a5f2ce7ca6e2e44d9bf1b1d9e9d980ce416d35a4d00f1a2f  8071508 main/binary-arm64/Packages.xz
 fc1fcedbe9926a4b0b8eb49c4ad003eeb5d656f7a447864ebab16f026100f6f7      116 main/binary-arm64/Release
 6b115f03bd7e988bade97cb51a9ada488bad7623ad3f085da265df9e4e64cfec 43343990 main/binary-armel/Packages
 c2564b86e9dd83293f0a43f4fb18506ab8487878bf518115dc42b4e2125ca5d2 10677432 main/binary-armel/Packages.gz
 a81082ad524af5c8ff7fe7674bf715daa82de2ce1bfc39dde407dfb0d6bb6ad8  7871888 main/binary-armel/Packages.xz
 abb6c54c329433e32610e26704ca667256c1ad24cbdef67431ded86b67b9df8d      116 main/binary-armel/Release
 e14f5af333a1e465450a88a9a40806b8d4b0e2dd903e9b9c698f4004eac6f0b0 43846413 main/binary-armhf/Packages
 7cb2281126c6161b691eaa41e647209b5240c660a99e2b083119e6c701a0a5d3 10775534 main/binary-armhf/Packages.gz
 ba960fa5d4178671db25ac4be29a375496edb695aac902f99c04aa482a60a379  7944712 main/binary-armhf/Packages.xz
 07c1cebfbbc800619727cfabb5bbd313a65ff1ad3df60fe04b680de8c63846cf      116 main/binary-armhf/Release
 164486fd11378f87865c09143df1514fca7045166c9c1ba61f2c50cffb987ea6 45094980 main/binary-i386/Packages
 216af7eb177d93f2004318058ff3f833dd6cb66bc23a3ad17b0c27edbbacc923 11013153 main/binary-i386/Packages.gz
 cfd786ed196f7a512764069e09f20ef97c536552f777ecd303b4a1538de5fe9c  8121972 main/binary-i386/Packages.xz
 598ab0b654f7296c5dd22bf8ebc2f1452e7585bb4fee5b0318d08a7700d59f39      115 main/binary-i386/Release
 2f4b83b3beff8e697aa7aba63b87a3841eda7e121dca7efeeba2fdd6c46d4708 43733274 main/binary-mips64el/Packages
 5d3435e4b966e83eff68bdc0f1390639ee4cf8ca85a0912086118d18fca56895 10720185 main/binary-mips64el/Packages.gz
 2f5114b8774c2ebb9e4bde58f4f61228413faf25c6f0f8cfdfef166d59194d1c  7907404 main/binary-mips64el/Packages.xz
 f3e83d91633067c9cc7c22a7b17331307039cb7a194534c86c45a0ae8b15e159      119 main/binary-mips64el/Release
 94dfcf07165f1f9da1d465a87d0978f2cd267341b0cb100a976db872731b0861 43667386 main/binary-mipsel/Packages
 dc8003ba9043dc725eb21a2d51f70fd0f68a98398e0819083663de884cc73721 10726366 main/binary-mipsel/Packages.gz
 886bc8567cdd318d3380636c313f736e35220acc8be711584ea919d5265e96a8  7906936 main/binary-mipsel/Packages.xz
 56e88cdccc438d85773e9d9dcd4626dc93905cc85c28492cf1115e0f6d6d86c4      117 main/binary-mipsel/Release
 53f4716144d0126ec83ade49820c2737e4097d058c7ec55c26a94401aff90799 44671240 main/binary-ppc64el/Packages
 0d7e6d81bc985f84d71bfa9dc1568b5bacde58766499fb50c9f9615627eb64d9 10884852 main/binary-ppc64el/Packages.gz
 8bd383fa40a08bde86f78b7768a3c8eb8aff0a16f380fe3ba259258db8cd89dd  8031816 main/binary-ppc64el/Packages.xz
 32c55acd12e6699b68c50747b5d72a0d2252a1db5856ab75fea6771c8311ba21      118 main/binary-ppc64el/Release
 1e53bd7f1a45174fdb3db7ecebeaabfbfecfa0a88aaea4a9d060039c99b0580f 43340190 main/binary-s390x/Packages
 07462d6e7a7e6ef042830e993747f9d471ae8dc0ba792c3056811c64d37c0e6d 10686656 main/binary-s390x/Packages.gz
 be641a245bcbd2b2138762c88793df74b04bad687f2c8185137254e9cb6bb229  7877060 main/binary-s390x/Packages.xz
 612cf5c4ef5247bb112bcb8af86780ecfc13514729575fce1087ec12340965d7      116 main/binary-s390x/Release
 4f60d86324cc91f8ac32625dfd1f8750a7f79e866376a34a478d2d3f8033ce84    61160 main/debian-installer/binary-all/Packages
 1e0c3c1d9f21267ec4183fa21ffb26808808678d6393cde03820b5f8c677977c    16449 main/debian-installer/binary-all/Packages.gz
 3831da178354890a18394e5d531c28c77f70c6fcc628e369eb584fbf7ce28812    14676 main/debian-installer/binary-all/Packages.xz
 5fca0b091a4008553328742c4e5509375042ae86fd25e078e5641da80c6e35ed      114 main/debian-installer/binary-all/Release
 8e6eade3d4d6600d25629ef41a6e7d7f1735cb999923c20962ab96c4c60cab8b   274352 main/debian-installer/binary-amd64/Packages
 127cbf365fb6430a108efe73be70b65c93a156c3e9d54a26515fb0637fecf7a0    67349 main/debian-installer/binary-amd64/Packages.gz
 b15c72bd10652b7c5a456b8dbce9ee1002d9ee36b4c8377d5224bf71d7c343e5    56064 main/debian-installer/binary-amd64/Packages.xz
 ab78444b1bbaa56630b4f90edc8982f4fd965ac4db2b5530855b768c1c8fa9f9      116 main/debian-installer/binary-amd64/Release
 42d0cbedcd391dcd0ae974c2feb668676aa33b430b213d23a913e411c817f23f   257349 main/debian-installer/binary-arm64/Packages
 1e7d6c63aeeb7b5923f514df4586dd7c9a23415f318e4d99c03c435fed764ded    64271 main/debian-installer/binary-arm64/Packages.gz
 155a73d0f9cb8c70eb64cf86204fb88a81585d79136dec3399b54571307daf5d    53980 main/debian-installer/binary-arm64/Packages.xz
 fc1fcedbe9926a4b0b8eb49c4ad003eeb5d656f7a447864ebab16f026100f6f7      116 main/debian-installer/binary-arm64/Release
 01175829fcfa8f2d6599c49971251106ace55e9b660a6ab2b6cb84990b615f23   248363 main/debian-installer/binary-armel/Packages
 41e38adbe03f5e12ce7bb71a17a1afa385a19129f3e2c4fe064358e83c41f50f    63792 main/debian-installer/binary-armel/Packages.gz
 a669674d70b74c4f3928ee0824025cd032a2cd681bee9608194da11bd96140ee    53168 main/debian-installer/binary-armel/Packages.xz
 abb6c54c329433e32610e26704ca667256c1ad24cbdef67431ded86b67b9df8d      116 main/debian-installer/binary-armel/Release
 7805822347f4d4a5c174408573f6d212e6f639a8d2587c1358dd1273c1e4bfd1   251788 main/debian-installer/binary-armhf/Packages
 e39dc55b91aecd52890df43e9661536022c68301e6d2d46140f0d883ea0d4097    64864 main/debian-installer/binary-armhf/Packages.gz
 508561858e1d7d9533704014303d875ddecb6c8a9be3a5692e4db28b8673bd0f    53852 main/debian-installer/binary-armhf/Packages.xz
 07c1cebfbbc800619727cfabb5bbd313a65ff1ad3df60fe04b680de8c63846cf      116 main/debian-installer/binary-armhf/Release
 545fe891b7ccfa9058a34a9ca644eec47d4d1e32b8d19731577719914d57b1cf   349445 main/debian-installer/binary-i386/Packages
 b3dcfa8a62aa51c55cb0cd999fe2930828eec945d947c737a4e0251299d031a5    77230 main/debian-installer/binary-i386/Packages.gz
 bb6f1ba125b73e6031b0db1aff6666d674614b2900f829edc00f5422b71a9ba6    64124 main/debian-installer/binary-i386/Packages.xz
 598ab0b654f7296c5dd22bf8ebc2f1452e7585bb4fee5b0318d08a7700d59f39      115 main/debian-installer/binary-i386/Release
 e99d10f54387b1515192c78420b8320f19226950e45628b464419a16cbbe0851   364716 main/debian-installer/binary-mips64el/Packages
 c16ea980c78ef318d090f661bb8a32b013b9aba1e4e03cfc7a1fcdc710b315bb    79498 main/debian-installer/binary-mips64el/Packages.gz
 0fe50a043e08a0c0f92cb774acbaefc95f78d7123efa606770dd02f9fdeff404    66396 main/debian-installer/binary-mips64el/Packages.xz
 f3e83d91633067c9cc7c22a7b17331307039cb7a194534c86c45a0ae8b15e159      119 main/debian-installer/binary-mips64el/Release
 e9b79bdf2204d27512128a1f1d85e8455d94c402be68b815c24f66be4f496e8b   364202 main/debian-installer/binary-mipsel/Packages
 94265e6e880e2c55618fcde79440b3060922932eb14eac1beaa3c7b1c6865d17    79784 main/debian-installer/binary-mipsel/Packages.gz
 803db2a15312c03059f31f2a20cde06935f7a3ca6c3f35e043b3d1881eaed353    66500 main/debian-installer/binary-mipsel/Packages.xz
 56e88cdccc438d85773e9d9dcd4626dc93905cc85c28492cf1115e0f6d6d86c4      117 main/debian-installer/binary-mipsel/Release
 d779769699bad795292351e1d2bf4c294d0df53f43a8e812e607d2ef5d979fc6   256933 main/debian-installer/binary-ppc64el/Packages
 6d2b2b5ac8b21d5dcec79146959b1bc617b65c5fb69a72bde8fe9b494bf03e30    64920 main/debian-installer/binary-ppc64el/Packages.gz
 adf0f93f39ffbdf3efc60e423653d16ca020f9d40d76c51b153462d4c556fac0    53960 main/debian-installer/binary-ppc64el/Packages.xz
 32c55acd12e6699b68c50747b5d72a0d2252a1db5856ab75fea6771c8311ba21      118 main/debian-installer/binary-ppc64el/Release
 08fac5f6592875d7466899b2bab7a44d8eea409b2b05dd8a334f0bd4e7bac807   226275 main/debian-installer/binary-s390x/Packages
 dad6130f7794acf153f2654ef56ce0f51ad202a6652862332025ef08d299b092    60464 main/debian-installer/binary-s390x/Packages.gz
 255a06d1829ff337a371c2e3565ad96ea789703016ce91735b36a9dd6fab1647    50116 main/debian-installer/binary-s390x/Packages.xz
 612cf5c4ef5247bb112bcb8af86780ecfc13514729575fce1087ec12340965d7      116 main/debian-installer/binary-s390x/Release
 99d8d572b0219a7b37addc91ff4e4ff238a33b3452580d4bd2469588a2225cad 18520413 main/dep11/Components-amd64.yml
 9c5522d811abead85a73407f6b56b171207105bb3641e22d76f2146482d4750b  6213469 main/dep11/Components-amd64.yml.gz
 0b517038e27fe4864c35de9459537d91f5d274800a172be69f91e90bb3631589  4048504 main/dep11/Components-amd64.yml.xz
 ed767617ad156481cc8948fb72c2d699d6292bfd2d83fb2f24b2b155612dc539 18436837 main/dep11/Components-arm64.yml
 1732a30dff783f891da2245f955becf3a43be40f0400b722087ba626316e980a  6191092 main/dep11/Components-arm64.yml.gz
 a02d6259b836d37804838b6de8f40568332a9a78cb4bc7668b32208f6062e782  4033216 main/dep11/Components-arm64.yml.xz
 aa3eea13a49b29dba27956d6fb6093817775361e29fef3f751e8e70b7065e54d 17658848 main/dep11/Components-armel.yml
 ca3d41da75c25408834b265c9c95f700a1241189f6bf62270e14b85920f5cdc2  5952269 main/dep11/Components-armel.yml.gz
 5c90b5a79fb5cf11b4e822396183bd3b4d3712e5f8e9363c5fce4a3a6c42a58b  3879744 main/dep11/Components-armel.yml.xz
 9d95db48c33d5671c96a2931458a92b6290e9c3f880c7ec7d7aef2b23a681eb3 18205252 main/dep11/Components-armhf.yml
 55c47f2e4607828ad1d875c1ade2aea6565916e9dce3e043f6de2e85b6cd74c4  6110587 main/dep11/Components-armhf.yml.gz
 20797715d417813ddd77d1bf746b8ea9f6353ad0e8be2e67f1700813d992268d  3983180 main/dep11/Components-armhf.yml.xz
 5579083d9a290f05eeb86967fd664c46464b3bafc00c073887560523a1793a64 18485654 main/dep11/Components-i386.yml
 ac8dd6c8b9e575785646a7d41adc7783956e22bcc757a60c80f225328c769f08  6201776 main/dep11/Components-i386.yml.gz
 589f93188296c83e394c89ccdaae1565436dc203161958e96f3a5cf2797684ca  4041608 main/dep11/Components-i386.yml.xz
 2b028df6a795c2a4b058b0f239745da363ea0f8b9fb8ce1a7955bedf579cc8cc 17819116 main/dep11/Components-mips64el.yml
 0865e497ec87d5d45f84106166bb035610443e87528aacc1a43f13000542a3f5  5977494 main/dep11/Components-mips64el.yml.gz
 46745049532f14f438f41704b442c157ee0f2990baed5d06da8fda3b41501547  3896708 main/dep11/Components-mips64el.yml.xz
 c0e1c64172edc19edcc287b0e617adff28b31354028de4c755cdf1fd077de913 17947079 main/dep11/Components-ppc64el.yml
 ba4eb9c1ab3f03a7fd184e5fc47dce250c083a617d9e2ba49a70c920fd957b29  6023058 main/dep11/Components-ppc64el.yml.gz
 aa34918432eeb8a82d912d86f69d82e84a4bc0eb48056ebe321b83d2757d1052  3925796 main/dep11/Components-ppc64el.yml.xz
 dc222c504c71bbc9ff6b698bf5ef7942e098efff1031861e5eb8670afdd18452 17735785 main/dep11/Components-s390x.yml
 29584e8fd8bc91d9d9099893ae4951601430b1df4f55659e089d34e4525540e5  5976062 main/dep11/Components-s390x.yml.gz
 1f9ca828b916aabab9b41f75950df49f71dc5e8a42f674ff4cb2138f85274314  3894008 main/dep11/Components-s390x.yml.xz
 057f28adb7c2452ab2c810fdfbfce0305ba8143ffe2e24969b2ece077aba7e9f 13048320 main/dep11/icons-128x128.tar
 4f46415e13538a05743752a630c9b8795a9772d0ab4ebe83c9d7e19f0e4bf179 11409337 main/dep11/icons-128x128.tar.gz
 e0c306e3293ecdcb8392faa372b00f1fb979c327c3e4370452acf7713ab885a4  4878336 main/dep11/icons-48x48.tar
 93c4366d8b6ef489bb935434d9a2c56d842978922e941dd4ee716ede2a805494  3477622 main/dep11/icons-48x48.tar.gz
 910ec31c85f12f0edefbb43fa2514b9896d105ce7316272a4c55263af864c238  9378816 main/dep11/icons-64x64.tar
 a94629c3e4fbe9607fb2921e1c906f88343a7cadc484a1087983181ae6df66a3  7315395 main/dep11/icons-64x64.tar.gz
 e061ee16e4478c39875bc3d977fdd5f880a71a3ea97c9f5119ac127a4305579a     6191 main/i18n/Translation-ca
 ed06627194c667d774188bcf0d9b859625ec60d2098238ee3c1cd5e1c147c4f7     2673 main/i18n/Translation-ca.bz2
 857bef6538df7a4e2ae01a6ef40f8a5c9e0512797a769d8813caaa57ca867f29  1205166 main/i18n/Translation-cs
 bdd79636af5f08f4c40bb5266a41e4707b7bdc84d5458451df0255b787c380a6   323247 main/i18n/Translation-cs.bz2
 2c7c6d7013e3d04a62c457525567fac4ac2747ef59f1b2a93cad8c0904c960b9 20240560 main/i18n/Translation-da
 8935ec6ddfeaeb542fe444013ad9fefd6ffd2da2afe818efeb417fb50568b52e  4411163 main/i18n/Translation-da.bz2
 55e94848df1df7d0963f3cb02cfb4171031350c549e4ae64f6aed517ed08ca6d  7801238 main/i18n/Translation-de
 b68fe8718325ebd1e2a8dd30f52b17c003e315f3468f9b7890fe5b1b91c709cd  1717951 main/i18n/Translation-de.bz2
 284169348b8bd4e0de4cc5641eeb05577e80d2bd736452e454976c052cf3cbe2     1347 main/i18n/Translation-de_DE
 481a435ad350105b74c4972859c44f447b7a8b5edea0d42f6dd635792e00a461      830 main/i18n/Translation-de_DE.bz2
 9f3b3bc0da0653f0ac8484024a7f77aeda681474907f3a94b8a0a0933775d14d     6257 main/i18n/Translation-el
 807de361285151534654b83681415016d443e4abd1a7ba36e1e78b4ac337b973     1835 main/i18n/Translation-el.bz2
 87a5cc96d599e93f7cd76ea6f32b27e9742abd8027c9c76c40ad1a091e0d8950 30246698 main/i18n/Translation-en
 4d7cf2aa527bdd9129bd6e5974c41f574de06f1963d9062af0787972b4a76b7c  6240167 main/i18n/Translation-en.bz2
 abccaeb24d409c21b94883b74785053d0f8fad3e94449078ebe92af38861bc5a     2261 main/i18n/Translation-eo
 747ab457a83de3b107e25b9cc5536aea2f19e0fe1f08d5357475acea0d788fae     1196 main/i18n/Translation-eo.bz2
 38345d246390b3845920937338647a70b1a6a93f354615da725fbf426ac3e332  1325929 main/i18n/Translation-es
 d6bd3bb26fb52e553bdaa40a041aa167f8a0c207149ebf626bea65c90ff7e99f   317946 main/i18n/Translation-es.bz2
 80c3ff00f3b37b64e73c85b11eab47fe88901b6f8d9f189de0e95a387e02ebed    10093 main/i18n/Translation-eu
 7ce6c68ef8a577bd215da5f7a12153bee27268b0b6b9503aaf88244b225f20a1     3914 main/i18n/Translation-eu.bz2
 54c5db1926c3309513d37990460a51c586ae6f01bcaaf2732e537ae400b6f5f5   269212 main/i18n/Translation-fi
 a0c315c9c517ac029e5981f14a3c15fa022c7c0e1e86edf123e05027343974d7    75849 main/i18n/Translation-fi.bz2
 bd258bc1f5bbc6694e24f58fe4dfb5f5636afc86a431795b931225e9e336feb3 11857302 main/i18n/Translation-fr
 ef77125783dc8b1125ea85050ba00bfe042e6f38fa1f73613387fe30cae47c5c  2433064 main/i18n/Translation-fr.bz2
 ce1a70b1000909a09166e30d574c717f3d60ba173bb65ad65e768374dc73232d     1427 main/i18n/Translation-gl
 fa1eb924fc1473b81f7790ccd909de1dc274f4f266df8af544261f03e1d21079      824 main/i18n/Translation-gl.bz2
 22e19c218655a9a4d09e9930a66715aeb5d0b02bdc4d147e5816067873e71861    21069 main/i18n/Translation-hr
 04e538e90503a9238d071bba89039e563d4c03ee038c217708a4f8c8672c28d6     4695 main/i18n/Translation-hr.bz2
 a275d9da1b509fc6c1d8307ff33daea14669cec8b8f89bb4c4fdf4d50ff48135    65236 main/i18n/Translation-hu
 94827a9f6e251237fb3b093360f88ba469d2be8d4a7c2c02c84298c94faceaa5    22243 main/i18n/Translation-hu.bz2
 0f4bfaba954ffa37332a34df69c8844b7334cc0b61515e9510513e2c43e140b1     3983 main/i18n/Translation-id
 11aebe26133b1249ebc06ec6d1a8b76f5975b9a3630daf71ecb7e2f6521a2fd2     1780 main/i18n/Translation-id.bz2
 d965461960f14ff1f614bcd0ba757874e098cd460b8ae0e018fb4aba254ce641 24489940 main/i18n/Translation-it
 451a92cd21dc98889f43a39223dc8863284bd1a8e515bc58633bdb7bf96dd37c  4844227 main/i18n/Translation-it.bz2
 1cb8cbfe8b502cc64639b02150e6f805bdeebedae3eb69273146c03ca6c9287c  4511401 main/i18n/Translation-ja
 0c00e0a8cff6fb13bdc4ed3387e3faf4f9db94f3ed4ca8e72d324c0a03d8f018   803966 main/i18n/Translation-ja.bz2
 7238152be74233d91630f7100ef7ff2bb8a95598b5fbc11c21c7afeecfc0fecd    11879 main/i18n/Translation-km
 01577e06c8e41b3a914ae539147af0fcdc7a0f883f50d82b57b263cf62fe1bf8     2371 main/i18n/Translation-km.bz2
 232cb289feae187cf94ad451662d7ce36be8014c40b69e645d19b9534dd586df  2606190 main/i18n/Translation-ko
 894aba3a34a47f3d59deca3bda07f8aa288e9f4ed6ae92422eab3fd9dd370ad5   584643 main/i18n/Translation-ko.bz2
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 main/i18n/Translation-ml
 d3dda84eb03b9738d118eb2be78e246106900493c0ae07819ad60815134a8058       14 main/i18n/Translation-ml.bz2
 16be336bba03786450a43321709eca2fce7fa7b50a135a97da71e16eb5e7d60b     1193 main/i18n/Translation-nb
 fdec5fc00fe2d0e3c7730462f95273492d278eb8a6957c1b437969833366c217      738 main/i18n/Translation-nb.bz2
 ce65092fbb0a09286644912bfaf3a9535921705519e16d07617ad85ec44ccf3a   174332 main/i18n/Translation-nl
 e12b923a6f3f83636a31e6e1b2503d8a213e1e4112586a27700fc17bb48ce564    47973 main/i18n/Translation-nl.bz2
 8999184566c11a42f9a31c810d9252316dc4f52ba738db43e0be2cd760c823a1  2051811 main/i18n/Translation-pl
 17fe48deb79b044bdf5894d0d129823b1d86653b9759f848667a74b563625379   491993 main/i18n/Translation-pl.bz2
 2dbf3c4316bba32571abc589b177be93c8e72885131940c9993d3fb6b8d58cb4  1074959 main/i18n/Translation-pt
 991a66952f6395d7588f38e68e1032f4dcc72da61322a59460c34a24d7713400   272186 main/i18n/Translation-pt.bz2
 5d7ec6fe173a67789c445369b7ebf8709cbc9ce4f3e06a75cf36c562a16580a1  3306707 main/i18n/Translation-pt_BR
 1583cdd6a71e29b6eaea0d29dee9ce903fc8ced1f9f57e5ad4de154938799bd0   802734 main/i18n/Translation-pt_BR.bz2
 c90708ca8975ced4acf4be98a4ac1f5c8092fd826b4d928e35c3650e705553d4     1717 main/i18n/Translation-ro
 35f2449dba7bd93e0aece908f4c4de53cc864a48c8f7aeaa5a64f67384e1bcda      982 main/i18n/Translation-ro.bz2
 f8b907289a1970413a47a3450c59b04e166c08cb387ee3ae4f6c0d2e4774c379  3058931 main/i18n/Translation-ru
 8685feba7a33fef7ad8d7fe5db5f59e837eba69134deb87610742cf564e47258   494782 main/i18n/Translation-ru.bz2
 ee2a1713ba3ccf4aa7ef3ee1b5786874c38ecc15db012bc15c3efbf5ad8facd2  5984088 main/i18n/Translation-sk
 0dfec1c42d581b3fe8f95bbe26f649f45234d419c7e709dc881f1994bfb20974  1304539 main/i18n/Translation-sk.bz2
 5ff9c60997a547f07d212476a8f50b4942f012d7952765c6c1925c52495711d1   323953 main/i18n/Translation-sr
 b4608fc3c0c7f6aefe0f6e5e19d0fbe0d5035333e74044e29358b3e3efa99536    58385 main/i18n/Translation-sr.bz2
 5656d4e913760691e99cd4805e76c8f18c4441fe707a02e621a2a172da756d5b    85612 main/i18n/Translation-sv
 fbad8c083b9985e53a2a82d7e32f26f683bd5b8e2f1bf09a3e0fc3f8f7abf6da    27320 main/i18n/Translation-sv.bz2
 2e50dd5fdf1dd6157c0db51afb4457fcfbd427ebb6d1268aeeea1daf50da78f0    14670 main/i18n/Translation-tr
 401a0f8d754d92c562bafe54aa0cb2dd7686ca015425513b666b50b8c9dc36a7     5362 main/i18n/Translation-tr.bz2
 6c66f49d6c9df7ef28f92aaab2620a2151fa16f74bf96deb3b74987183e43b86  3740343 main/i18n/Translation-uk
 bd760427bda1a65895dd7b3bd6a3e2b2a0ee6b4060ce726ec4b7c02b89a72204   576766 main/i18n/Translation-uk.bz2
 c2207dfa8d62c7e2a31851842dd928739bc147515f69fb7a28db93196dd1a601    21882 main/i18n/Translation-vi
 e3eab47e1acdc01ee2d774dba5b0f9d29c98ff48b25a57d469eeecf60d3035ca     6510 main/i18n/Translation-vi.bz2
 7133134d1b1b6c869b4b700fed9778e93a0b774391402ad3399e9ff46984efff     2007 main/i18n/Translation-zh
 8cbeadbbcec613b8476f8e2aa40b15772909109e10a83317c111fcf7c28d0219     1215 main/i18n/Translation-zh.bz2
 d88628c7a7a16a042234daf91a709daa6d5f9de15406ec78530891354fa25c75   425199 main/i18n/Translation-zh_CN
 1ef87b145198090deb2d037bc16b5b940c0e757a2511f4ff84a7c750720b2723   113621 main/i18n/Translation-zh_CN.bz2
 564fdb3059cffbe78dde61697e77edd7bc94005a358cc4b5dffb436776d1b2b0    39965 main/i18n/Translation-zh_TW
 0a4d5ecccec7069a32b30de129018034b2f6f2b318f1530e1edc239182442cf8    14859 main/i18n/Translation-zh_TW.bz2
 343fe56ad4f39f517c6b504106ce828f6ab57b71fd8fe11ded31b5d217950b9a    58277 main/installer-amd64/20210731+deb11u7+b1/images/MD5SUMS
 3dddfa19f9ca9bd20c0f0249d68427e5a70cabb845c8dc9736f3949c96ec1188    78097 main/installer-amd64/20210731+deb11u7+b1/images/SHA256SUMS
 91e63d03c43f9feaed6c255a510c30c35c547c517f395c2574900b0119fad790    57705 main/installer-amd64/20210731/images/MD5SUMS
 a3a16cc4af2d688613ce8df4d224974629ad3383a1969350c24ea68bfdd5f1e5    77333 main/installer-amd64/20210731/images/SHA256SUMS
 343fe56ad4f39f517c6b504106ce828f6ab57b71fd8fe11ded31b5d217950b9a    58277 main/installer-amd64/current/images/MD5SUMS
 3dddfa19f9ca9bd20c0f0249d68427e5a70cabb845c8dc9736f3949c96ec1188    78097 main/installer-amd64/current/images/SHA256SUMS
 1df7955a3c09498e279431cb6304f4e616cb7ea5a8ee5d4b9db85ba9d2a05bed    69049 main/installer-arm64/20210731+deb11u7+b1/images/MD5SUMS
 fd710c158d06fae3de80d23198806c9101e7e6cc640fad6b366d3f06eed9e91f    94149 main/installer-arm64/20210731+deb11u7+b1/images/SHA256SUMS
 291e81049aa85b147063ec1aa5bec87da60d3196c06c3098de5210c3346837eb    68403 main/installer-arm64/20210731/images/MD5SUMS
 5dfc89487fc8717ab9a9b75cdaaf01a295ab3021cc3310d3fe9dd3e78fc1f666    93279 main/installer-arm64/20210731/images/SHA256SUMS
 1df7955a3c09498e279431cb6304f4e616cb7ea5a8ee5d4b9db85ba9d2a05bed    69049 main/installer-arm64/current/images/MD5SUMS
 fd710c158d06fae3de80d23198806c9101e7e6cc640fad6b366d3f06eed9e91f    94149 main/installer-arm64/current/images/SHA256SUMS
 54528ee7dfb52dc1ce6680b4a8b898d9454936c892012a677747465fa8f506d9    20678 main/installer-armel/20210731+deb11u7+b1/images/MD5SUMS
 86396ff61efdee365e4ab688b91f773409a12d6950f61a7e8671a9b64777458c    28882 main/installer-armel/20210731+deb11u7+b1/images/SHA256SUMS
 ee9f639b7a0304207f23c84f5396284720a6fc6c638ee7be6873944a0f224c95    20182 main/installer-armel/20210731/images/MD5SUMS
 07353d4c378ea579803ed8c1aca3fe6df2cbc89788736c7d01102a7b3ebad859    28194 main/installer-armel/20210731/images/SHA256SUMS
 54528ee7dfb52dc1ce6680b4a8b898d9454936c892012a677747465fa8f506d9    20678 main/installer-armel/current/images/MD5SUMS
 86396ff61efdee365e4ab688b91f773409a12d6950f61a7e8671a9b64777458c    28882 main/installer-armel/current/images/SHA256SUMS
 f899f04724b1fbce7e9a9060e82e1dcb942919914bdc808d120b7e52fb7b38b2    64380 main/installer-armhf/20210731+deb11u7+b1/images/MD5SUMS
 cf5b025aef61b2ea4e0c5f94d36e22e5ed26b01da945f498f9b6cb5156171b1f    92680 main/installer-armhf/20210731+deb11u7+b1/images/SHA256SUMS
 8c1f810a60fc7daf099e608b763cec563f59c82203a07bbf4469a6213a8946eb    64240 main/installer-armhf/20210731/images/MD5SUMS
 67c5b636e3fc02747ca9593e6fc7e906a3ec95d4947740fec81b1e942f0643ae    92476 main/installer-armhf/20210731/images/SHA256SUMS
 f899f04724b1fbce7e9a9060e82e1dcb942919914bdc808d120b7e52fb7b38b2    64380 main/installer-armhf/current/images/MD5SUMS
 cf5b025aef61b2ea4e0c5f94d36e22e5ed26b01da945f498f9b6cb5156171b1f    92680 main/installer-armhf/current/images/SHA256SUMS
 393b9f170f9732a04cee8abf0dc9d0a52272bd577c47d30310dd88c2552db5b7    56840 main/installer-i386/20210731+deb11u7+b1/images/MD5SUMS
 fb5c92b43fcaaa6850fe79473a5fac3c6a27e31b72a52d81297eb283fdbc46d1    76724 main/installer-i386/20210731+deb11u7+b1/images/SHA256SUMS
 96e8acb8eb827ce7032587400fbe848b6f53921c661d52e1b16fd243cb8e57aa    56286 main/installer-i386/20210731/images/MD5SUMS
 bced74c95a3688a9a2a28abb8190cb7efd7e1f6372dc8989e260771752ef571b    75978 main/installer-i386/20210731/images/SHA256SUMS
 393b9f170f9732a04cee8abf0dc9d0a52272bd577c47d30310dd88c2552db5b7    56840 main/installer-i386/current/images/MD5SUMS
 fb5c92b43fcaaa6850fe79473a5fac3c6a27e31b72a52d81297eb283fdbc46d1    76724 main/installer-i386/current/images/SHA256SUMS
 d1eb4b5cef71f7c78971aa99bf86ed4980ebcb8bab8d0e45835731d0ce173969      630 main/installer-mips64el/20210731+deb11u7+b1/images/MD5SUMS
 275fc83d164449c94cfc9c4039f38eb08e123bb11d6f6acc2724441f752a3727     1026 main/installer-mips64el/20210731+deb11u7+b1/images/SHA256SUMS
 af3b55dea76e91f1565bd54bc1af76a6a0bb4991eef9abe281a22d9fd8d54a7b      627 main/installer-mips64el/20210731/images/MD5SUMS
 995cda8278b101eb25849d56f3ef33290fb57a940fa1c6837f19df00ceafaaff     1023 main/installer-mips64el/20210731/images/SHA256SUMS
 d1eb4b5cef71f7c78971aa99bf86ed4980ebcb8bab8d0e45835731d0ce173969      630 main/installer-mips64el/current/images/MD5SUMS
 275fc83d164449c94cfc9c4039f38eb08e123bb11d6f6acc2724441f752a3727     1026 main/installer-mips64el/current/images/SHA256SUMS
 74028a1b5cf4c8a3e8b30fadaa3c4a2237b9032b93a3abfb3d3edb64667cbe61      630 main/installer-mipsel/20210731+deb11u7+b1/images/MD5SUMS
 1dd26a64b20327c1718dec6cf314168dbf68a225b1e68cedb2c8d4f4ee218087     1026 main/installer-mipsel/20210731+deb11u7+b1/images/SHA256SUMS
 ca77bbc823d1bf6999e141cd42c1bb4c18179cbe4a3fbb6da3e40e1055848ed7      627 main/installer-mipsel/20210731/images/MD5SUMS
 28589449e1b3ac9a73bdf6f266edc83e70ebbbca587a228b15b0dbe5e1a634fa     1023 main/installer-mipsel/20210731/images/SHA256SUMS
 74028a1b5cf4c8a3e8b30fadaa3c4a2237b9032b93a3abfb3d3edb64667cbe61      630 main/installer-mipsel/current/images/MD5SUMS
 1dd26a64b20327c1718dec6cf314168dbf68a225b1e68cedb2c8d4f4ee218087     1026 main/installer-mipsel/current/images/SHA256SUMS
 1703a54e2b260ec691ffecd444e7507f03bbefce7cb8341b73ad78ed16ca750c      576 main/installer-ppc64el/20210731+deb11u7+b1/images/MD5SUMS
 c234d16ddedfbb72bffb5cb22b32b981e03b3461f6720c10c7d5b8dc726e912c      972 main/installer-ppc64el/20210731+deb11u7+b1/images/SHA256SUMS
 d162b2da6777c1ea0643921cc1a3dde78ae48cf022711eb98c7e9dd030b89a44      576 main/installer-ppc64el/20210731/images/MD5SUMS
 73e281bce56df3c7512ffa1a1cb13886064759a461621db4acf9b1f71965c676      972 main/installer-ppc64el/20210731/images/SHA256SUMS
 1703a54e2b260ec691ffecd444e7507f03bbefce7cb8341b73ad78ed16ca750c      576 main/installer-ppc64el/current/images/MD5SUMS
 c234d16ddedfbb72bffb5cb22b32b981e03b3461f6720c10c7d5b8dc726e912c      972 main/installer-ppc64el/current/images/SHA256SUMS
 20b3ae961820dbc6df8275c2efa95d4ed34775cd22f9d5dc0d656bd699c9f99d      374 main/installer-s390x/20210731+deb11u7+b1/images/MD5SUMS
 1082cf1f5b94b3c234dea741a0ed81e03cf3f78b0a55affcf58d517bf37fee2d      674 main/installer-s390x/20210731+deb11u7+b1/images/SHA256SUMS
 b2c58a9c5b97a59742a8056e3e9d7f4f22d4d11e51c71d7a0051dc4649a717b9      374 main/installer-s390x/20210731/images/MD5SUMS
 61447263ea7318c444fde199afc718a8498fe67bc0e7116f2e1103cc65ef672b      674 main/installer-s390x/20210731/images/SHA256SUMS
 20b3ae961820dbc6df8275c2efa95d4ed34775cd22f9d5dc0d656bd699c9f99d      374 main/installer-s390x/current/images/MD5SUMS
 1082cf1f5b94b3c234dea741a0ed81e03cf3f78b0a55affcf58d517bf37fee2d      674 main/installer-s390x/current/images/SHA256SUMS
 de9a48c211839c666254f2eba37417143bf6d0db56abfe1d07e4c35609d3f04f      117 main/source/Release
 dced89e82fac92fdc1cb92f99321787f26c8c9b0d72da39ec091dd96234ae3d1 44655922 main/source/Sources
 006a5628b8afa45bf77cc449afa6f98647573b0e98b119a5944e65741094bdeb 11429086 main/source/Sources.gz
 a7e9e21d852dc2b685e9c28e0b06a9a4043220367cec57bd0e7043bd58c1a069  8633788 main/source/Sources.xz
 29cac69ab0fd86e224587eea8e2ed2fb9b1b2e3c936fb1dc7165b8ed8d00528a 17347341 non-free/Contents-all
 3b87590d0360ae141f3688fbafb5fdad35d4dd4b1a239888c911743c4357862d   888157 non-free/Contents-all.gz
 1335601f3e9b7f67c279a4c1619203dd6461fab7c16c29e1d71970a9bd023052  1097448 non-free/Contents-amd64
 df4bb7a18156a7f33c70f36d1709ae7ba48716d96ec1b940bd3bbb47ba432de7    79655 non-free/Contents-amd64.gz
 6f4902fb02e2f1092d88d8101024129a4af0fd245e75803b0b93b0475feef42e   499970 non-free/Contents-arm64
 c2715365833d3d97cb90e1fbf44df3c6835b323ef1e5dfd660b1cce148cf62e9    37376 non-free/Contents-arm64.gz
 386c53a056d4aedb9d48a332056c51a302e1b043480cc24fc9ea9053ff8fe002    95417 non-free/Contents-armel
 5fc23867def6ff06cf0c72080f1862ea142b20d25ca0a1e8e8b9c83ca3b82519     9298 non-free/Contents-armel.gz
 e2fe020c8c47e80e483acfe05462706e063c6932f9bb857e54d59383d415a44f   146124 non-free/Contents-armhf
 ac08720d4fc801273e1a8b2e0d7d7f80d07220f09089011a577ba47f12172ebb    13502 non-free/Contents-armhf.gz
 6468671814b9daa924278df786f198b0b34d8f525b7a9c0ff8cdd6db3dbc661a   343198 non-free/Contents-i386
 d85698eb7c99ba6fb568afcb497365ebbc59421c89dea8b6186b661e8c19fd12    29072 non-free/Contents-i386.gz
 6bdcba453cc1369f93e7157d5d7f9c67198edc62e4e194b079b0572186a95b34    91215 non-free/Contents-mips64el
 0986d6fc85dcf209edbf39b1ee2c84b370ea02dfe810ac33cd9cc89a2f3a2a18     8686 non-free/Contents-mips64el.gz
 5102cb8d1b74daa60d4d6444e563dbdaf73ffaa2b7ce71a304987ff575da7f4e    92244 non-free/Contents-mipsel
 53bd140b538ffea9c0bd8b6b073b3ef613ec1d452bb1bad5a5f86a029f11e3dc     9026 non-free/Contents-mipsel.gz
 03756e78d0f8004d0cdd2e4fe2238a6c851f94c42b0ca7064629b55a4ca494d6   716110 non-free/Contents-ppc64el
 e3321e93f91e779a59e4ca94c61d1eedd13d02a847824c459419c29203ca6959    49881 non-free/Contents-ppc64el.gz
 6d2b11e017bf520a64870b3ceecfac7944f991928095bd2715429987a342c37e    74537 non-free/Contents-s390x
 228df45a42a42dd62cc747f2abe99dccd25c384aa423c17896a6196955cd9c12     7407 non-free/Contents-s390x.gz
 1d53da6b88f2d7252351b65dafa6ec6453ef19326ce8490ea48d865557f30c52 10803369 non-free/Contents-source
 de64ec721f3e9589c6f7efc4f23c2713a40afcce15e033eddbfa0674dc81ae4c  1063443 non-free/Contents-source.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-all
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-all.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-amd64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-amd64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-arm64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-arm64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-armel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-armel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-armhf
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-armhf.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-i386
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-i386.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-mips64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-mips64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-mipsel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-mipsel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-ppc64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-ppc64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-s390x
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-s390x.gz
 68ddf090986f56743010180da8d3e05a41bd5185e0047a98c97adb038cc5fc4b   189021 non-free/binary-all/Packages
 569cc71a40dffea02aa6cf8b516370e08587ec71d34558cf6f1fe688c9629468    50928 non-free/binary-all/Packages.gz
 b9d8d7fb507a77a6222770fbe09815bc0cae22af92d0c16538d53b4576af6784    42996 non-free/binary-all/Packages.xz
 3f87c1d57bbb196bc7d6a2bec129e82e4f4296b3743a105f53104fa82e3d6f07      118 non-free/binary-all/Release
 41eae996375149a4854537915bf8162c5a22c77f3fa88c6466ce16d5f1b7d1d3   545576 non-free/binary-amd64/Packages
 6bebe66d1f22f6dc11b186fbd34d029402a0848057dfa5a8afa193cad65bc205   122225 non-free/binary-amd64/Packages.gz
 a108aa5d825e98f766b4e20d261c21c1fafd9340547006244aa6fbb51b77d837    97772 non-free/binary-amd64/Packages.xz
 9a0edbc466a3e91231c1ba756996d5fb598d3b14166a2a2b72899d4672f53a82      120 non-free/binary-amd64/Release
 514482332f1c35020f2ba2ac2cff8e956dc5ba0a9a5533251321cf3e2e50ff89   381335 non-free/binary-arm64/Packages
 c2b9e19b24c3c9f859da6a28fd8cf27bc1b698111d4bd48728a8b8cb093085b1    88201 non-free/binary-arm64/Packages.gz
 2ab2f8d500ce30e6b4e70fa5ef5678a3eef0743deaec93a24011949bc5911f75    72980 non-free/binary-arm64/Packages.xz
 76a1c234c80cbabd279f721e53350404c3cffb523962e44161ded825f87c673c      120 non-free/binary-arm64/Release
 f5738f5a5d9f4391ba0719b7bb175892d93561b688137917a4cdc75537ca70e5   227933 non-free/binary-armel/Packages
 89cb801437910d9b6076d9caf85f2144b224cb1eff7dfbd014219242df514b82    61822 non-free/binary-armel/Packages.gz
 bf2bfec078bdf2dcd2d0d411109257f3ec2d652087399062023d2fcce2e43710    51800 non-free/binary-armel/Packages.xz
 7148bdadd1b6755cc63ffebb30bb3f228e3d6d2565e18ae6641eb62cbc802fa1      120 non-free/binary-armel/Release
 4a9f94f9f510ff6c829677b8dd08ed0c5ff7b33f2118f152d2a4e6b410f8425a   259156 non-free/binary-armhf/Packages
 d7ae0acddc9f6a9acff311a662f78729a610fec44101cd8275fdbddebce7b5d4    67317 non-free/binary-armhf/Packages.gz
 21f37dc3d988493e921f40cd37cc6ef2391b2d7cccf5c83fbf1b037602c0e521    56272 non-free/binary-armhf/Packages.xz
 404c43c7b78d9a5b45b1d0c1851c58ac77a4b4ffe83c81d5c184b114c7c65804      120 non-free/binary-armhf/Release
 54c7fe6dbb5eba9498c1726c1e2119d86697ef32300d3bab99048f1b4141c482   422388 non-free/binary-i386/Packages
 54d73d03945551ef08f0c0b74828b3d78d2747a5f26c3a5d7d7fc446a79f383b    96319 non-free/binary-i386/Packages.gz
 3f0a14b592ba6bf04c31da2ccbbe82bf058d62e341c1777c02f3fd5c00aab76f    79344 non-free/binary-i386/Packages.xz
 fda2cc9eaf856a91a54c1c893a273d148234734ffea5e1ae811d3404c07700b8      119 non-free/binary-i386/Release
 f7e9a5d9f19cc5b819efa1aac30c9d833ed9e41dfdce9abf2bc48d0467abae1a   225506 non-free/binary-mips64el/Packages
 2d01bd458989434fd6555cdc4d4f9dc554881de09ced2db213fc26395f4108c8    61024 non-free/binary-mips64el/Packages.gz
 ed53056d18b6b8589fbbebffd26f8fbda708f71870e1bbffd4a4cfc7249283b2    51124 non-free/binary-mips64el/Packages.xz
 19a2da1050283b31ebd2f6664572c326fe39fa70de30821b9a5410e5e5ae0daa      123 non-free/binary-mips64el/Release
 c690e75e4633fad47565d5afcef96622ec6e02b2fa824e5c0508f1119044c906   226162 non-free/binary-mipsel/Packages
 fd05e8f63760b2163ba4b40cdf200a9b113edfbf81d5a2a318a2b5605812891d    61277 non-free/binary-mipsel/Packages.gz
 87cb9361adbac3f2604906109b21c6b685fda9caf3525395dd4ee057d7c4e43d    51364 non-free/binary-mipsel/Packages.xz
 7d90fbb38122b89666a80ad2665d91fc0eac09bab9f4f7603cc4547504abae06      121 non-free/binary-mipsel/Release
 74efb451a4beb4d707ceac0597842d515b78b7d9effb56a06663fb7428ef129e   381597 non-free/binary-ppc64el/Packages
 c4b451037905b8277fe0a2c0699c3e4ab0de2eb69559c19ac89361440f0439d5    86900 non-free/binary-ppc64el/Packages.gz
 7bc21cd6ac30fce563e47909e7ec989071941134e89b2d895100059749cf3a47    71812 non-free/binary-ppc64el/Packages.xz
 c83ec7a841e5fc039ecef935b1b67f91cebad518a361463db2f804fcb32aaf91      122 non-free/binary-ppc64el/Release
 79ebd2f1278b5db689359d517f88af2ae9acd8d493bf791e5cb5f73b9c81479d   220570 non-free/binary-s390x/Packages
 f7240f44940160f2d9b7cb553f6f47713186ebba6646c18a093e61bc4088e720    59856 non-free/binary-s390x/Packages.gz
 4a1d593c1cd1adb67b9ab6bd5c2558536c284486eb714f89b9ce09229bbb1eef    50216 non-free/binary-s390x/Packages.xz
 e51de0ad0c2a44d2a9054242a462481f42bf24e4da5f58fd0ef35993dd35693c      120 non-free/binary-s390x/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-all/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-all/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-all/Packages.xz
 3f87c1d57bbb196bc7d6a2bec129e82e4f4296b3743a105f53104fa82e3d6f07      118 non-free/debian-installer/binary-all/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-amd64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-amd64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-amd64/Packages.xz
 9a0edbc466a3e91231c1ba756996d5fb598d3b14166a2a2b72899d4672f53a82      120 non-free/debian-installer/binary-amd64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-arm64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-arm64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-arm64/Packages.xz
 76a1c234c80cbabd279f721e53350404c3cffb523962e44161ded825f87c673c      120 non-free/debian-installer/binary-arm64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-armel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-armel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-armel/Packages.xz
 7148bdadd1b6755cc63ffebb30bb3f228e3d6d2565e18ae6641eb62cbc802fa1      120 non-free/debian-installer/binary-armel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-armhf/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-armhf/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-armhf/Packages.xz
 404c43c7b78d9a5b45b1d0c1851c58ac77a4b4ffe83c81d5c184b114c7c65804      120 non-free/debian-installer/binary-armhf/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-i386/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-i386/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-i386/Packages.xz
 fda2cc9eaf856a91a54c1c893a273d148234734ffea5e1ae811d3404c07700b8      119 non-free/debian-installer/binary-i386/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-mips64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-mips64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-mips64el/Packages.xz
 19a2da1050283b31ebd2f6664572c326fe39fa70de30821b9a5410e5e5ae0daa      123 non-free/debian-installer/binary-mips64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-mipsel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-mipsel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-mipsel/Packages.xz
 7d90fbb38122b89666a80ad2665d91fc0eac09bab9f4f7603cc4547504abae06      121 non-free/debian-installer/binary-mipsel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-ppc64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-ppc64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-ppc64el/Packages.xz
 c83ec7a841e5fc039ecef935b1b67f91cebad518a361463db2f804fcb32aaf91      122 non-free/debian-installer/binary-ppc64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-s390x/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-s390x/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-s390x/Packages.xz
 e51de0ad0c2a44d2a9054242a462481f42bf24e4da5f58fd0ef35993dd35693c      120 non-free/debian-installer/binary-s390x/Release
 e13d055f233a81a77666f0ff8dd9d748917b2829740756e1dc2b8a350309bcb0   278293 non-free/dep11/Components-amd64.yml
 f51b1a07cd72a36b2a9f36742ab26819a7808aa7765cbf3e2ff4abe6be66b50c    29634 non-free/dep11/Components-amd64.yml.gz
 e113163e116c137577fc9d3a4f7c95e0934ddbae7bdae5e083aaa1ce095435b6    17904 non-free/dep11/Components-amd64.yml.xz
 6177cb908c067306c11bd8728a5b65a205d999be63930c079e3ff4250a24ce8e   271451 non-free/dep11/Components-arm64.yml
 1b6107a1fa771a8fff50e0b182362fd679dc01f58f7a1f3fe9fe0183daf3be0d    27686 non-free/dep11/Components-arm64.yml.gz
 7ff5eda9a37e07b9bcfa479c89863d7b2b1aafbedbe4b37ea6c32a16f2eaa241    16392 non-free/dep11/Components-arm64.yml.xz
 f54eccd2dbf23fa45cab9e9e7abfafeb667397ea70b6197a3653e8499ffea8bf   271451 non-free/dep11/Components-armel.yml
 5581d7f4c159a5cbd33927294f7fc9918e7deaf04b313001965c83412b6a81f7    27606 non-free/dep11/Components-armel.yml.gz
 0830d150400c82255a52a74f6af9f1a11007bf4b92fc814513f9e13cfac0b22c    16448 non-free/dep11/Components-armel.yml.xz
 15d1524c660c8fb1ee911775a9b59cebbc66843eb97cc0a15a361009f153e6ff   271451 non-free/dep11/Components-armhf.yml
 3fa04d7715c8955987742dc376d10327a975f9583cf656da055d13895e460a67    27691 non-free/dep11/Components-armhf.yml.gz
 bbf5a05de96a53c0e10af6019cb7b053b83b0f5def488cde4d8359475adb08da    16364 non-free/dep11/Components-armhf.yml.xz
 716cec6e00d8303375812c8c9be7cbfa5fc858fdb3d9af3f0c72a696d8f7cb2d   280613 non-free/dep11/Components-i386.yml
 40f189b3b3a74bc85652829d0c67b21aad7e60ce389f26fe1959db1e1e8ec48c    31098 non-free/dep11/Components-i386.yml.gz
 18507e0a03c74ed39b9bec853eb9216b458f2fe2b7535c2622c126b9cd35301e    19156 non-free/dep11/Components-i386.yml.xz
 d82d6fadb06b6a1f0d36c155b70a02eb2281838aee3ce1b9bf51b7ae06136721   271451 non-free/dep11/Components-mips64el.yml
 25d788e157070218396bafba65ff087551830ba0d0ba3e3cec5342bb150aec57    27765 non-free/dep11/Components-mips64el.yml.gz
 2d0aa3979fd6093dc6de8ba902166a985235c8c4926e07cab7aa2a9b4ad0c11d    16380 non-free/dep11/Components-mips64el.yml.xz
 c55445f6f87fd566212bb018f9fae1a4eb43c1a66fe1b0e198b1c7d7e500b009   271451 non-free/dep11/Components-ppc64el.yml
 f525af23f1a1eb26ee786c36e2afd4aa5e4102b646f33f8c6788aee395b752bf    27592 non-free/dep11/Components-ppc64el.yml.gz
 0ee03164cca5098ec7c6f98a469818b40b61da7846451cc223d0b9e01585c57c    16576 non-free/dep11/Components-ppc64el.yml.xz
 359af9af71c00d90265395225b75313966435729cf1f6cfb1085fe1721b01e72   271451 non-free/dep11/Components-s390x.yml
 47ef508dff3dfdf17ceeed229d98a2e3992c1a26f28eb328a2d1958d2ddfe070    27558 non-free/dep11/Components-s390x.yml.gz
 181db8b5130910114256e8809ff9a1637efac55b1f33d1f516983521b8d51e7b    16356 non-free/dep11/Components-s390x.yml.xz
 601045de5331d63b7ef2a24f8f74a7452d7be785f94ae6c46002c5dc2608188f     8192 non-free/dep11/icons-128x128.tar
 4fb59feb5d5afe99980ea36c3d7c14577a4b5f11705e7d16524767708666ed54     2394 non-free/dep11/icons-128x128.tar.gz
 977a5470a45ec30f5e230361a446f4692f9cf9bc2abccf6eabac2df0291f1ee4     4096 non-free/dep11/icons-48x48.tar
 07a401f7b03554c2d8ab32dea5885c43b7da7badeea0569b9ce5c9dbbb7cf66f      741 non-free/dep11/icons-48x48.tar.gz
 159551b3012db94a70261cb8f88619a6bb148318da051479ade6df7211c41a34    36864 non-free/dep11/icons-64x64.tar
 872b7437de6fb938db8b26d9de9a3113bc722cd6ed682973151722e2b7a190be    27667 non-free/dep11/icons-64x64.tar.gz
 db924f2bd81a5875019d05bea92accc667c5a99099512ee11862db412c21d7fb   572893 non-free/i18n/Translation-en
 91ff4a231eff217916da9113aa017d4090fe442fa54f1edf21af3811e0bb255a    92419 non-free/i18n/Translation-en.bz2
 6372d37a918ae4dc1be5a748e9e02e57573e765e14a3c8aa0f37208b223555cc      121 non-free/source/Release
 2bd47d8b576397abf753f06eb5bec85b2036e84b80b8d8646a0e784380d0d53e   360307 non-free/source/Sources
 c9d5108699279e6cb2946d907c13655ebe8b6fce12986a4ba8b0ece0257977c1    98323 non-free/source/Sources.gz
 3f3f09477a76bf44bbd93e7efc74f55783f0841c6692d6188b91e8f58a0c7999    81280 non-free/source/Sources.xz
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEEAUbcbUoLKRS97TTbZIrP1iLz0TgFAmOdlrgACgkQZIrP1iLz
0TidUg//UlgUqZja8Ij2B4G8PuR+lNXa2YFEde2ZvBzy8LIh0mUk7bFKFgDfikK0
Jdt8K1b2YlBVAGM65WvRY8AN1tqKy++kpn7Pg4ircw/n2rDlEicnX+h7wFXoWEkf
Cr3Vxu4dJRaXzeDPxKpms6WN5bnCQJdqfd68Unvx3LuhqNv1lJNBaMWUnIZMA7AN
IZqc6vOYlr9soBwaf0de7zmrDl+c/4o+C9MZlEQwp0+LsDGFTH0fZOdN+cSVEtkb
H88RwKFC/E54yUncfURAZ9lI+BYJkejLNlKxYwt7XIBhgOORhZacs79NuGN5SJu2
zFupHv+L7zJ6JJjSPzBNyKBC+UboleSoAfwV/M5RjEnRsPdHbEms3KJyadf1y4Jj
xSuGo4x1xppae02bu0bPPWNeEZwRqaot6XdP3nV4ADFgo5/CCOS2otLX1HIrVQiM
KklSVeqjikmMjR2u85ZMtZm4UzLchDtOMJyF9ZzdvLD8X1p6d5gZ8PEjQ+DQ8Fiz
y97AD0D8maarwpAvzQPVpMT5Wr+bPzz3/17BiV69cx5MAON9fUkUzHJA+bFxAEnb
I7jSP2lPpiZ2Vd3rbUKJKaaupAJWHXXAqhXSy3jPA9CEbxN0HKexlFt751vWhk6e
RwkEatgmrtXvwIYN/G0sKd63zWMparIDPiYN6oO+MmHHHyqqziWJAjMEAQEIAB0W
IQSnI2iG88zKrRSKJ/gOmEBNOG+h2QUCY52WuQAKCRAOmEBNOG+h2RZ4EACYbbdB
q234a0QxEekciuCfu7Bybco82dBG1dlQQdjeepOGLdTHToBzdKaR19Q2NFx5HDMj
7UE1QG2nAhoqqALdvfVHpR7lY/qd9lCfiQQt4aH3PteJuIrG7IvNWSHXA8To6+oQ
hq3N/qJVieZ8VaKX8W1OZS8IeOoCv9Y/jUyJbVUYgndd6Lpg9ieclDRc6GI7dVR9
ZQTQIiq/WMfVPaA3pnzf/z9p9pZcbB/4fyitkCJPUWchpM6LVOUTZ98m/SjJwtX5
A4snKKg+vyQy95ru5XoUr55B0RZePzIu/RYbX00SouqzyX8i6bmWCgWffHVDnwS7
eeorpj8Ww7fT1ejPgQs0rnFGC/cw0nHuB0sKS78o392iNF+5KuvaskJZMBWPQqoj
fO6yaamIUOuI1jCJdT1KnYtzzAWOET0cd5fUzH30M2wY+R80d0IgMLyzMiWMkUPw
J+duB05qGmSKCtOEZfmEP0cBDV2IbVC7427EGhe/b5EwD8xQDOIKywXBTGn8TEBD
aYUJiKQqepdvAk9hGxAmZhBTC7eiv0eXzdiHx/pEJ22RNVHSx1dnEfbsIcoNlGSe
EIIgneBZ8mGQQKqV8rddjt6NNruX9ERQRdeBmqrot9I5yzBOVyLnx5YvSKRHpVjo
gNaMTkf0SUA7mg9lDPOQMC2RttDMy1EHxRBakYkCVAQBAQgAPhYhBKQoUpX8exqB
YABiqWBcZvANbJeTBQJjnZfUIBxkZWJpYW4tcmVsZWFzZUBsaXN0cy5kZWJpYW4u
b3JnAAoJEGBcZvANbJeTw6kP/i6Myl2b6mCKIyFng0Uq/CR1dBvyZ0052W/aOOxb
E1ptwAPeizCLIkobpKspPMyNvOcbKJqDdSYoOnqYOa2sgt2lW4oXeICHC3SvTih1
R440ZoDXneHabmW8vONJdHsm5gJ14zoaoK6JEG4lXyWLOc0OsbeHX5180BMI9f//
cVncX6B1h39Sfu9TcVDdQdWaX8+K2P3/mNB/Kph7crruvYM6YSJOWLpaHFCYm8H4
Hla0WCgW2A9beGV7xQPxduObeXnPp9x0z8kCBCsphJsDhYhKKshaUeJ06u3Kb1C8
8ed8qx6YnO/XNjp4cvQQuKbMDXkl2uT9rf6Y79Z1XnGNnmDA1XgBuQ/wBWiV/iwu
ypYvXC8zlvF+s+SnIEYmdZyLYnkis57wAJyApiRvfnNB60t++BArlq2isVZhqfS8
IwIFLd0v87bU3LOSSaySknCn8jCb9G0+ohHOac1dUUbrT6C/M3weqDxcCfU56HAb
sXwQKswzFc9fVgVKRg9VzLpOK9a4ND2OJgbrwv54qAz6c60TT8VdVYqwT6YSwt3o
69p/xsaUttAdlwDdecAsk3dKG0TqjpTYQEuD0On6gbN0RkGCkVVZNWbge5HCvp5V
rpdC5ZEiCdXADFgiUg+vgbj1y1ValPU/UUQIVwsXuV5git4Yb96jqRxFiXUIIGAW
EXyj
=h5YC
-----END PGP SIGNATURE-----
")?;
        assert_eq!(remaining, b"");
        let mut keyring = Keyring::default();

        keyring.add_keyring(include_bytes!(
            "../contrib/debian-archive-bullseye-automatic.gpg"
        ))?;
        keyring.add_keyring(include_bytes!(
            "../contrib/debian-archive-bullseye-stable.gpg"
        ))?;

        let content = b"Origin: Debian
Label: Debian
Suite: stable
Version: 11.6
Codename: bullseye
Changelogs: https://metadata.ftp-master.debian.org/changelogs/@CHANGEPATH@_changelog
Date: Sat, 17 Dec 2022 10:14:37 UTC
Acquire-By-Hash: yes
No-Support-for-Architecture-all: Packages
Architectures: all amd64 arm64 armel armhf i386 mips64el mipsel ppc64el s390x
Components: main contrib non-free
Description: Debian 11.6 Released 17 December 2022
MD5Sum:
 7fdf4db15250af5368cc52a91e8edbce   738242 contrib/Contents-all
 cbd7bc4d3eb517ac2b22f929dfc07b47    57319 contrib/Contents-all.gz
 6e4ef0f159fa08f5ba74067e0a94b5e6   787321 contrib/Contents-amd64
 98583d055424774c060fdf4b02291da5    54668 contrib/Contents-amd64.gz
 61e10f1703d718d584f381a943bfe4d7   370915 contrib/Contents-arm64
 86a145a0d8d7346449f2cf62098a5553    29596 contrib/Contents-arm64.gz
 b6d2673f17fbdb3a5ce92404a62c2d7e   359292 contrib/Contents-armel
 d02d94be587d56a1246b407669d2a24c    28039 contrib/Contents-armel.gz
 d272ba9da0f302b6c09a36899e738115   367655 contrib/Contents-armhf
 317aa67ea34d625837d245f6fb00bdc4    29236 contrib/Contents-armhf.gz
 ccb13401b0f48dded08ed089f8074765   407328 contrib/Contents-i386
 e496015d7e6e8d5a91cec31fc4bde74c    33556 contrib/Contents-i386.gz
 44384de1db64f592fc69693b355a0ec7   359402 contrib/Contents-mips64el
 a2abf38d14c1c7e3aafcb21881b0fe7d    27962 contrib/Contents-mips64el.gz
 457feed233db5ce7db62cc69e7a8a5c6   360549 contrib/Contents-mipsel
 90ec76d0dca539a4c4aa33404de4c633    27942 contrib/Contents-mipsel.gz
 02985cbbdd1e790b29a9911ba00b5650   370025 contrib/Contents-ppc64el
 b34b90df14207eafe94313e6d466b28e    29381 contrib/Contents-ppc64el.gz
 e2089c91540f7adb693675935dacf9e5   357860 contrib/Contents-s390x
 bb90fb42e72d39da53b3e1e2c2f46bc3    27518 contrib/Contents-s390x.gz
 ba62d5cf69ffc155d75fa9e16228b039  6722669 contrib/Contents-source
 fec97c652e41904e73f17cc5f7b0b2ff   469817 contrib/Contents-source.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-all
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-all.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-amd64
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-amd64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-arm64
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-arm64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-armel
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-armel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-armhf
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-armhf.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-i386
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-i386.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-mips64el
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-mips64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-mipsel
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-mipsel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-ppc64el
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-ppc64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/Contents-udeb-s390x
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/Contents-udeb-s390x.gz
 73d0ad5df01464248f578fb7d7ba10b0   103239 contrib/binary-all/Packages
 6848b84ab94b0624ad15f5afea5f49bd    27385 contrib/binary-all/Packages.gz
 a9e21972669e0355e9a875ea31f25c63    23916 contrib/binary-all/Packages.xz
 3c9131b20395850cbf9735dfbc0cd6a7      117 contrib/binary-all/Release
 b6541899bd7907d9dc5afe604d26a719   231878 contrib/binary-amd64/Packages
 7cb1a35df9e7ef744685d28932cc1ef2    60884 contrib/binary-amd64/Packages.gz
 4ee4184e78f4b0d06e981706a6118dc7    50588 contrib/binary-amd64/Packages.xz
 7edd7af81aa30d5a929cad55b259de23      119 contrib/binary-amd64/Release
 4b9c68a7d2d23357dc171d29a03565c6   180884 contrib/binary-arm64/Packages
 c2d2253fb81e2a397e4a42d4d475bd24    48958 contrib/binary-arm64/Packages.gz
 f57a0a52945226cc76c241ce57c182be    40964 contrib/binary-arm64/Packages.xz
 34b661285be33d5dd033de35b00b0b52      119 contrib/binary-arm64/Release
 1636c115e53ef208266fcc6b024f7b34   163042 contrib/binary-armel/Packages
 ed80c2afd00562cee8543a3835ed0907    44389 contrib/binary-armel/Packages.gz
 ef8175333695e1554eeb8766d74c4795    37452 contrib/binary-armel/Packages.xz
 f5908602701eedda3f627be810655de2      119 contrib/binary-armel/Release
 900f4a8949a535dfd1af4326b43e6fa4   175566 contrib/binary-armhf/Packages
 11db111d1dd40616866a8b6d4e59ca8d    47805 contrib/binary-armhf/Packages.gz
 512198b43afc25d9da1e078b44f5b4a8    40220 contrib/binary-armhf/Packages.xz
 7271fc19a10e612fcdc17bfc361a4805      119 contrib/binary-armhf/Release
 feb05a736bdfbd41bfdd4d87fd34f72a   203514 contrib/binary-i386/Packages
 89a79f0c9d4bb2df7d3dc3d165f02242    54100 contrib/binary-i386/Packages.gz
 130d6b77d3b32c1ec94097e694d66718    45340 contrib/binary-i386/Packages.xz
 8dc8ab0c142d7166f1a8cb8ef5c8dcaa      118 contrib/binary-i386/Release
 825bc5698936bc26f5bb28c20287aeb1   163507 contrib/binary-mips64el/Packages
 190dd8f6a3e97c3ebe8ab216e79ed867    44652 contrib/binary-mips64el/Packages.gz
 9302a32bad830648c066bfb13a35b6b9    37496 contrib/binary-mips64el/Packages.xz
 268c4243d0a655c886c9533779085b8e      122 contrib/binary-mips64el/Release
 4e717be16d235fb7e6e118c898ac80af   164647 contrib/binary-mipsel/Packages
 f73fd75fc0a6371ae7e6b709a4d8d939    44883 contrib/binary-mipsel/Packages.gz
 9c8d77e03dcdc178465c28095f4e8d64    37816 contrib/binary-mipsel/Packages.xz
 5e4a6cc21b9343c50ab7eeb20be00166      120 contrib/binary-mipsel/Release
 1343f3307bbeea9f0b04dd64e8d23d62   180387 contrib/binary-ppc64el/Packages
 831c14a6428bbe7b05d290e9aa225785    48843 contrib/binary-ppc64el/Packages.gz
 8daa347dc96d3f69e7510c0d3f51916e    40808 contrib/binary-ppc64el/Packages.xz
 44eda0cdaff945cc2cb4f8bdfad50371      121 contrib/binary-ppc64el/Release
 1a2b7365b25b44a4304271198bda5094   162250 contrib/binary-s390x/Packages
 103b59f69a5c230eab05d06289ad7c9b    44334 contrib/binary-s390x/Packages.gz
 e4109e4637f7b1c233130da040451fd9    37244 contrib/binary-s390x/Packages.xz
 aa08c18b750a7efa1a4c3f23650132a4      119 contrib/binary-s390x/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-all/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-all/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-all/Packages.xz
 3c9131b20395850cbf9735dfbc0cd6a7      117 contrib/debian-installer/binary-all/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-amd64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-amd64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-amd64/Packages.xz
 7edd7af81aa30d5a929cad55b259de23      119 contrib/debian-installer/binary-amd64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-arm64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-arm64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-arm64/Packages.xz
 34b661285be33d5dd033de35b00b0b52      119 contrib/debian-installer/binary-arm64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-armel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-armel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-armel/Packages.xz
 f5908602701eedda3f627be810655de2      119 contrib/debian-installer/binary-armel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-armhf/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-armhf/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-armhf/Packages.xz
 7271fc19a10e612fcdc17bfc361a4805      119 contrib/debian-installer/binary-armhf/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-i386/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-i386/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-i386/Packages.xz
 8dc8ab0c142d7166f1a8cb8ef5c8dcaa      118 contrib/debian-installer/binary-i386/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-mips64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-mips64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-mips64el/Packages.xz
 268c4243d0a655c886c9533779085b8e      122 contrib/debian-installer/binary-mips64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-mipsel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-mipsel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-mipsel/Packages.xz
 5e4a6cc21b9343c50ab7eeb20be00166      120 contrib/debian-installer/binary-mipsel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-ppc64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-ppc64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-ppc64el/Packages.xz
 44eda0cdaff945cc2cb4f8bdfad50371      121 contrib/debian-installer/binary-ppc64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 contrib/debian-installer/binary-s390x/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 contrib/debian-installer/binary-s390x/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 contrib/debian-installer/binary-s390x/Packages.xz
 aa08c18b750a7efa1a4c3f23650132a4      119 contrib/debian-installer/binary-s390x/Release
 fc412a0e8fed50416ae55ca3a34c2654   119152 contrib/dep11/Components-amd64.yml
 7473c932902284e9c636636a5ff0587b    15579 contrib/dep11/Components-amd64.yml.gz
 751b272121122fce4882d17a9d099c44    13564 contrib/dep11/Components-amd64.yml.xz
 49911a9d2f76ed13124c7cff0081266b   113437 contrib/dep11/Components-arm64.yml
 ee72e145d0e71d94c0d418d36dabfd8c    14251 contrib/dep11/Components-arm64.yml.gz
 65f48dc9acec772076e60ce35239703f    12480 contrib/dep11/Components-arm64.yml.xz
 b1f970bbcdd889ccff5c2646bc2835ba   113437 contrib/dep11/Components-armel.yml
 d2a414b1147562c0ecfa1aab53fc0260    14029 contrib/dep11/Components-armel.yml.gz
 b450a677c3a5d4a52d2a0df274c222cf    12524 contrib/dep11/Components-armel.yml.xz
 75c6b8bd42fc863caa66c454306c7d39   113437 contrib/dep11/Components-armhf.yml
 ac52f103d1c493d0f8d8e5662d758f78    14127 contrib/dep11/Components-armhf.yml.gz
 80f4310b2d68bf09c7fbba34a0eec794    12480 contrib/dep11/Components-armhf.yml.xz
 a46b6878a89f45fab86aca68bffe081d   118972 contrib/dep11/Components-i386.yml
 751ea67ac68d2e755726b4e9d62ab15e    15566 contrib/dep11/Components-i386.yml.gz
 82c956565311c8a7d90bff6e0a226fbe    13560 contrib/dep11/Components-i386.yml.xz
 6f822ef8f2c13dc4212ade261b4a8752   113437 contrib/dep11/Components-mips64el.yml
 a072aab0fb45dab4a6e25295f23e9b5f    14056 contrib/dep11/Components-mips64el.yml.gz
 e5c2dd7fd785fa1ab66099d7763bd670    12500 contrib/dep11/Components-mips64el.yml.xz
 432a29a22c4a782f6edad376f386937f   113437 contrib/dep11/Components-ppc64el.yml
 b5202b5037949e593060f92290d6f949    14219 contrib/dep11/Components-ppc64el.yml.gz
 dd92a500c7807091665dbc207c9bef68    12496 contrib/dep11/Components-ppc64el.yml.xz
 53c6b87820861b0ed316a88f7542cd76   113437 contrib/dep11/Components-s390x.yml
 5a4872d3187bc79418b468890be4b5fe    14050 contrib/dep11/Components-s390x.yml.gz
 eefb3301e486aedbbbb1d735e2522a00    12488 contrib/dep11/Components-s390x.yml.xz
 5d8e37f26e7e15f367751089fa13c876   271360 contrib/dep11/icons-128x128.tar
 500b14a4cafa23b9106b402737f863a7   195507 contrib/dep11/icons-128x128.tar.gz
 d9651fb188be2221d2f583aeba83d8fc    83968 contrib/dep11/icons-48x48.tar
 6b5ea4675ad78554aaa53b344f1bd146    47168 contrib/dep11/icons-48x48.tar.gz
 7115d3a3d41fc9bca9cfcc3c608bebf2   138752 contrib/dep11/icons-64x64.tar
 c839e679f1d60d294d39884d0911e514    93294 contrib/dep11/icons-64x64.tar.gz
 01e75740c90a7df7e474a1c6152b2aa6   192685 contrib/i18n/Translation-en
 a2e9608c3e388d26e031583f200e2f92    46929 contrib/i18n/Translation-en.bz2
 7b851a6fc52e455ec6e64d1bbd002e60      120 contrib/source/Release
 d615756c28aa372e2bc408abe1d9ec5b   178776 contrib/source/Sources
 c19b950adb0b02bb84fec45d11d257d8    51355 contrib/source/Sources.gz
 0e1710e68ffbd6a7b3542844610a69fc    43208 contrib/source/Sources.xz
 052421edd3e77801652c5e82cea27172 477769406 main/Contents-all
 c6642306466300d5b980a46ab2da3448 31069218 main/Contents-all.gz
 4f76cfae77ca68a2534e4776c1ba603a 129058022 main/Contents-amd64
 d00bf88e20a9167d72c15f914e2f6ae6 10270460 main/Contents-amd64.gz
 4c143d623f5b8d26d47c079554c17287 122426895 main/Contents-arm64
 44ba782a6a21b58a1ff85d2c04785f8d  9831920 main/Contents-arm64.gz
 801e7ed91bc44eb81525999ec2a8291e 104683113 main/Contents-armel
 a5a18ca6cde98c20f5b89666cc6ada02  8703570 main/Contents-armel.gz
 307b7ca5872bf53d92aced5dc4fa75ba 113716591 main/Contents-armhf
 ec3f7e25caefcde0999e74f88fe29c25  9305906 main/Contents-armhf.gz
 39e08183dd281004ce0853d8138db6b9 129088857 main/Contents-i386
 4339b5c20026a75c512e5c97c56ac03c 10208982 main/Contents-i386.gz
 1468642d6dbe21a9b910d360f52d1a71 111097071 main/Contents-mips64el
 f5727ac1ba4208d6994869b64251d40f  9042221 main/Contents-mips64el.gz
 30ac6e6b838d5fc79a6139fc5b4e7337 112593872 main/Contents-mipsel
 13fcab9f9e956d966bf9975da41bec6c  9178325 main/Contents-mipsel.gz
 985636740f62394375012f87593d5c21 116027632 main/Contents-ppc64el
 97f1aaf6603044158ce139c2570992d0  9355024 main/Contents-ppc64el.gz
 332ff60dc3b48ca16f5bf3baa139b530 103638209 main/Contents-s390x
 1dfb6d3460020eb28ef7ab36bd7d0c08  8711885 main/Contents-s390x.gz
 30e2a744a0a8fc6c48325fa30d7d0e70 690410830 main/Contents-source
 453c66c682ee49babee0fac4ec460ac7 73501881 main/Contents-source.gz
 1f4bf598c355a2bbb0c8ddf889d9636e   157382 main/Contents-udeb-all
 708ed31f29f9daf4c980b7abdd66c356    13516 main/Contents-udeb-all.gz
 069860439eabdda442aa81afb59f8644   477050 main/Contents-udeb-amd64
 6e95b271bba66b8135cdd9ee13cad982    36011 main/Contents-udeb-amd64.gz
 8884d6660508188095f2991c73ede3a2   508817 main/Contents-udeb-arm64
 a972a7d9191733ca34c65bbec0c4da30    38139 main/Contents-udeb-arm64.gz
 72cc361d1b9ae73eeb7e3798a52564b2   323083 main/Contents-udeb-armel
 2521b5dc40ca4ce0c2cf495642512931    25477 main/Contents-udeb-armel.gz
 b74da65320e8e14ccd398d9b3a0af741   579793 main/Contents-udeb-armhf
 a6b01ebd28d333afe285226a6d3902b5    43153 main/Contents-udeb-armhf.gz
 02f78f33d39614e8f2c1ae4a5971637a   751383 main/Contents-udeb-i386
 f77c976f4226372caba729cd86720f36    53984 main/Contents-udeb-i386.gz
 fc8c6638ad4e7036abcfb74c9ca40e67   760534 main/Contents-udeb-mips64el
 b29f9bef4f9b6237adac6822c3f644ee    52873 main/Contents-udeb-mips64el.gz
 8851f799ab3bac7dbe3ade6ca88058d3   760210 main/Contents-udeb-mipsel
 f5b4e16d70afd5fe145bbcff78ed60c7    52810 main/Contents-udeb-mipsel.gz
 b0c21603250d55447094b00f1438aef7   401639 main/Contents-udeb-ppc64el
 9cc88f8f084a1bf1b0f4a3f7d4d2baa1    29533 main/Contents-udeb-ppc64el.gz
 942cbd0dfe1ec1bbc24f50b6a22102e0   258318 main/Contents-udeb-s390x
 bdeed95042d0b946c8d8f72cb49fd28d    20894 main/Contents-udeb-s390x.gz
 779c0c7072ee9cd9b776167e3b0d8694 20423830 main/binary-all/Packages
 78a6edfff04a3b7505c0b8b1cc468c68  5208282 main/binary-all/Packages.gz
 296b8e6e27112ca9610cde0fbc84f34f  3918264 main/binary-all/Packages.xz
 d8d2edd733e3235987c8c0c9565344d8      114 main/binary-all/Release
 ee0b34bb7ba7a8e1a7964ebd20187def 45534962 main/binary-amd64/Packages
 c14373e666988e64b30c26f3b6c3fbf2 11096605 main/binary-amd64/Packages.gz
 f30e2d1e8f395c903155dda0c4ba0970  8182920 main/binary-amd64/Packages.xz
 dbeadc926a4f14b4a73390c82832052b      116 main/binary-amd64/Release
 e02c425b41e1c7f2e910960cb80b8fc6 44816551 main/binary-arm64/Packages
 854700a00d0c4c7b9f8b7946d97b85fc 10941625 main/binary-arm64/Packages.gz
 3fd4c3700b238504448734039842d4fd  8071508 main/binary-arm64/Packages.xz
 f02cb9aab85fccb7a19d168b5acb2390      116 main/binary-arm64/Release
 a0174a68bcedce8fba19bde6cd1208b3 43343990 main/binary-armel/Packages
 56c75313e445b1b136fd240122a4a207 10677432 main/binary-armel/Packages.gz
 797f4ee8e47a372aae0a83ea352fe2fa  7871888 main/binary-armel/Packages.xz
 358a6eb5337f79950b79beaae6d06bd4      116 main/binary-armel/Release
 d4028809623d98cbf20cb043be845906 43846413 main/binary-armhf/Packages
 8326ddf7c01158570ca901a8827c0449 10775534 main/binary-armhf/Packages.gz
 5845702f6c696189347091fd5cb51276  7944712 main/binary-armhf/Packages.xz
 8811dc441114bb1b2f90dfce9ff6acfc      116 main/binary-armhf/Release
 99f2432683f72cb4833cc0392f8a1313 45094980 main/binary-i386/Packages
 1c5363ed68d7894cf94ab51ec66bf926 11013153 main/binary-i386/Packages.gz
 534024b184373545b78e74aa164ba211  8121972 main/binary-i386/Packages.xz
 50b3c16ad95352c06904ec1341afe2d2      115 main/binary-i386/Release
 87f3a748abd585d485b04e11a8f75fa8 43733274 main/binary-mips64el/Packages
 e7ee93fdf444409e1d751e3160a599e3 10720185 main/binary-mips64el/Packages.gz
 c2f655d6e0fb46a1eb029045054e5b52  7907404 main/binary-mips64el/Packages.xz
 c0cc63128ced0d323a714281b3f78ba2      119 main/binary-mips64el/Release
 d5fc8d1553a24222dda3e6fc804b2aeb 43667386 main/binary-mipsel/Packages
 88a8a5f188c1a0e18255daab88d8c83f 10726366 main/binary-mipsel/Packages.gz
 c9568fef286c9fe7d80cdcf9dece78bc  7906936 main/binary-mipsel/Packages.xz
 0ac20990fd13d5eaf32c0041fd37c568      117 main/binary-mipsel/Release
 735e4dcaafa4c558fd21e8a7075f4997 44671240 main/binary-ppc64el/Packages
 5f14e959fec4dfca2d5b3f8b7bd090af 10884852 main/binary-ppc64el/Packages.gz
 1b587b581cb630066fa51c8ea85ea327  8031816 main/binary-ppc64el/Packages.xz
 641a1901dc2496b912f4f49e9f7d4db8      118 main/binary-ppc64el/Release
 d93e11281b31f88d89a0d1eb73cc13ca 43340190 main/binary-s390x/Packages
 1ca35cf8189cbb3fe643b9be4ca39e48 10686656 main/binary-s390x/Packages.gz
 9f00d6b29f1659c08eea54ca8e0e652e  7877060 main/binary-s390x/Packages.xz
 40a1a7ba21820ed919518a0e4f6cbbbd      116 main/binary-s390x/Release
 8523f5593a344ec29029e3e20b8e10fa    61160 main/debian-installer/binary-all/Packages
 8322a8e0b943187cc1ad41f5e91e0c8c    16449 main/debian-installer/binary-all/Packages.gz
 73f68ee665b0ba4fe8b1d5bd0986e6a1    14676 main/debian-installer/binary-all/Packages.xz
 d8d2edd733e3235987c8c0c9565344d8      114 main/debian-installer/binary-all/Release
 e5156b114c9a46b50dc7b14217399795   274352 main/debian-installer/binary-amd64/Packages
 fa8d2c9b9be51d30622654b67ecac5c5    67349 main/debian-installer/binary-amd64/Packages.gz
 79cadb77602e77b501f0d9354d6a940b    56064 main/debian-installer/binary-amd64/Packages.xz
 dbeadc926a4f14b4a73390c82832052b      116 main/debian-installer/binary-amd64/Release
 bf5150ba5d1823e80ce45b268a79a392   257349 main/debian-installer/binary-arm64/Packages
 74c5e0915ec84c2c336d97652ffa0a7a    64271 main/debian-installer/binary-arm64/Packages.gz
 cca08998fcdd03ca3284112927344e20    53980 main/debian-installer/binary-arm64/Packages.xz
 f02cb9aab85fccb7a19d168b5acb2390      116 main/debian-installer/binary-arm64/Release
 79673899cedce0be43ebc1d416fb58bd   248363 main/debian-installer/binary-armel/Packages
 80bf080680db4b7b02ed444454b8981f    63792 main/debian-installer/binary-armel/Packages.gz
 7cfb8b710c1228c6359c7b48041cc8c0    53168 main/debian-installer/binary-armel/Packages.xz
 358a6eb5337f79950b79beaae6d06bd4      116 main/debian-installer/binary-armel/Release
 1f43e9a44586e87494ec1a7269ec7f2c   251788 main/debian-installer/binary-armhf/Packages
 262d12c86cfee6e0c82383272d15c377    64864 main/debian-installer/binary-armhf/Packages.gz
 b4db61d6a2322a13cf8d6b0f49e9ffbe    53852 main/debian-installer/binary-armhf/Packages.xz
 8811dc441114bb1b2f90dfce9ff6acfc      116 main/debian-installer/binary-armhf/Release
 cd8f8bf8d19b9ba5a1efc7a75930121a   349445 main/debian-installer/binary-i386/Packages
 41400360bb68ffe289e94a68da63e79f    77230 main/debian-installer/binary-i386/Packages.gz
 2a77d691876cab7b5f0803b7611ca267    64124 main/debian-installer/binary-i386/Packages.xz
 50b3c16ad95352c06904ec1341afe2d2      115 main/debian-installer/binary-i386/Release
 c22d0ce635eb0fae86afba6242116a19   364716 main/debian-installer/binary-mips64el/Packages
 1aef85058cd12a9638321fedd2ffff31    79498 main/debian-installer/binary-mips64el/Packages.gz
 9d5da1ee87189d9671b42c4bc122c48a    66396 main/debian-installer/binary-mips64el/Packages.xz
 c0cc63128ced0d323a714281b3f78ba2      119 main/debian-installer/binary-mips64el/Release
 18bc2f5de2b576eee963afeb65375aab   364202 main/debian-installer/binary-mipsel/Packages
 a1b8c712b5272debb29e8c07de9caf0b    79784 main/debian-installer/binary-mipsel/Packages.gz
 cce1945593d8c4b82fd33b6e5f761521    66500 main/debian-installer/binary-mipsel/Packages.xz
 0ac20990fd13d5eaf32c0041fd37c568      117 main/debian-installer/binary-mipsel/Release
 d7b8901246bae032e5ddbc9e45cc872c   256933 main/debian-installer/binary-ppc64el/Packages
 70a122a874633fde8db5504f98ee7439    64920 main/debian-installer/binary-ppc64el/Packages.gz
 f2e4f1994de7021fbfc39fa44056b2b1    53960 main/debian-installer/binary-ppc64el/Packages.xz
 641a1901dc2496b912f4f49e9f7d4db8      118 main/debian-installer/binary-ppc64el/Release
 1b44e25a26eefd464c288608423d6e42   226275 main/debian-installer/binary-s390x/Packages
 095ad8009e027e93ec3bbe8678eef9f6    60464 main/debian-installer/binary-s390x/Packages.gz
 e513ca8104e23a972e147e86ef1bf5ab    50116 main/debian-installer/binary-s390x/Packages.xz
 40a1a7ba21820ed919518a0e4f6cbbbd      116 main/debian-installer/binary-s390x/Release
 97a6eda13094854f8838218d5869a796 18520413 main/dep11/Components-amd64.yml
 9cd807c0b66a8489b5385bf4f343b288  6213469 main/dep11/Components-amd64.yml.gz
 c16ba02c289510dce9857dfa6cde4550  4048504 main/dep11/Components-amd64.yml.xz
 3e8ecb0bbaecb88d0b16dfaa037dba73 18436837 main/dep11/Components-arm64.yml
 09ef5a87673c946f916b0d8ef0c2471d  6191092 main/dep11/Components-arm64.yml.gz
 fef127cee05f3efb96261e78b4fe4568  4033216 main/dep11/Components-arm64.yml.xz
 67becc674b536e310fe22492d55c8652 17658848 main/dep11/Components-armel.yml
 34cd8a6a1206f804e6d5c54dcdd3ef63  5952269 main/dep11/Components-armel.yml.gz
 d7cc0222cae53bcfa1de29218fe5cb94  3879744 main/dep11/Components-armel.yml.xz
 09010fea4c1cf082bd54aecc24182e45 18205252 main/dep11/Components-armhf.yml
 f5b7fd1a9cb147fa6b90e60a4d2139c1  6110587 main/dep11/Components-armhf.yml.gz
 f1f223ca9e69ad1901345ceb404a5666  3983180 main/dep11/Components-armhf.yml.xz
 ee8f83c597007ab84b58feec05d647fa 18485654 main/dep11/Components-i386.yml
 5a6b35ea7b54d88842ab30bbbd469623  6201776 main/dep11/Components-i386.yml.gz
 239cc12774e7c2925d1d783faaf01b5d  4041608 main/dep11/Components-i386.yml.xz
 dd59f50383f269a8e1ec09c49d8a786c 17819116 main/dep11/Components-mips64el.yml
 e3f03ed2f2c22dac3207e5f3fb98f862  5977494 main/dep11/Components-mips64el.yml.gz
 437c9fa1e058fc9a3486fb8b224740f6  3896708 main/dep11/Components-mips64el.yml.xz
 09d0cb63fdf4a4904155dc0d56ccc04b 17947079 main/dep11/Components-ppc64el.yml
 3d396ef7d8293620c5160a75fda04d39  6023058 main/dep11/Components-ppc64el.yml.gz
 23ebc600f44eb4973c351a4a324ba219  3925796 main/dep11/Components-ppc64el.yml.xz
 64acc85d1d2ce3e3dc551ae85e80ca57 17735785 main/dep11/Components-s390x.yml
 b7f851e780c93532c1707895dfa22474  5976062 main/dep11/Components-s390x.yml.gz
 117c2f52a672bca008f2c206ad8527a6  3894008 main/dep11/Components-s390x.yml.xz
 3f40799bee1a72a060f7dff19efa7b05 13048320 main/dep11/icons-128x128.tar
 6ac207d4fb6b76c25dc59edb50c3bf6b 11409337 main/dep11/icons-128x128.tar.gz
 66ce5f075d189138824e736123711450  4878336 main/dep11/icons-48x48.tar
 260bbc45bfa6b33e31399b4adb3b1f6d  3477622 main/dep11/icons-48x48.tar.gz
 47dea6d08e37b4a5154a072f3ad92cf0  9378816 main/dep11/icons-64x64.tar
 417f46677b9086f9dd0a425f0f39ee31  7315395 main/dep11/icons-64x64.tar.gz
 180389879ed6715b463d05b637e191dc     6191 main/i18n/Translation-ca
 8f8b7ffa4659d4f03b65ed28e69821f9     2673 main/i18n/Translation-ca.bz2
 b4ef33a20d80c576c7b352e96a86e063  1205166 main/i18n/Translation-cs
 d70ae6198f35f876b3070d928d5cdba2   323247 main/i18n/Translation-cs.bz2
 3fa5a10989da6ec5b19b5b6ba161b0bf 20240560 main/i18n/Translation-da
 e83f678061ca99aaedd2f20cb75bba77  4411163 main/i18n/Translation-da.bz2
 9f5077418506388082a72c7023c56f8f  7801238 main/i18n/Translation-de
 a57e3821e975f45d21bf2388a190b770  1717951 main/i18n/Translation-de.bz2
 a344219bf0eec9139d5270017ecfceee     1347 main/i18n/Translation-de_DE
 0fe0725f74bb5249f15f30ce965142d5      830 main/i18n/Translation-de_DE.bz2
 87bf9810c05aba15fb4aca6791feb73d     6257 main/i18n/Translation-el
 002ddfc4187acd8414873fe9f0a6442a     1835 main/i18n/Translation-el.bz2
 36467cceb9cb2cea759d49c8759be7f9 30246698 main/i18n/Translation-en
 b4a727f22675ec9db1426d7dbc7a34f0  6240167 main/i18n/Translation-en.bz2
 0fdd8948881357f49ead0845c7e621c1     2261 main/i18n/Translation-eo
 43bd21f8b5d52b955e509e5893eef37e     1196 main/i18n/Translation-eo.bz2
 2ad9740f4bf39f163c04bd0b7266c1aa  1325929 main/i18n/Translation-es
 b4d4140461b4d6195e3337dcf541554f   317946 main/i18n/Translation-es.bz2
 2f7f0aac6c4ae5bd9c1499fd612ef996    10093 main/i18n/Translation-eu
 3178567e5f21fe43e4cf1f1a38ed6adc     3914 main/i18n/Translation-eu.bz2
 d1e71d50a88504d6b48c27960250acae   269212 main/i18n/Translation-fi
 9ca11408c191cfc5270f39467ed80f9b    75849 main/i18n/Translation-fi.bz2
 945a63eed28af4c45fd5185b334b33b3 11857302 main/i18n/Translation-fr
 06100e8db22b6d72d2c466bc85ea117b  2433064 main/i18n/Translation-fr.bz2
 f543980d7c6e8335eb0bb5d00b787418     1427 main/i18n/Translation-gl
 09c22bb0dfa3874802c4e7e4389f2b58      824 main/i18n/Translation-gl.bz2
 363537eb238e19bd527554a2d1de2533    21069 main/i18n/Translation-hr
 3fbd3535dcc2e805f0283d54bd38f5f3     4695 main/i18n/Translation-hr.bz2
 5393df220c56a4a92b91b2cac6843067    65236 main/i18n/Translation-hu
 61236a1bada04fd4ab090269498c5393    22243 main/i18n/Translation-hu.bz2
 d8d93a0510fedeb68fbbdae0342520c0     3983 main/i18n/Translation-id
 7542ee230bbc1f2f9f873c265b3b467f     1780 main/i18n/Translation-id.bz2
 87ba73fdeb9bac4348a4be42b2386f32 24489940 main/i18n/Translation-it
 9c9cd08156baf73f9f088bb97ac00662  4844227 main/i18n/Translation-it.bz2
 0f39595a0a049759d0d50ead781f73fd  4511401 main/i18n/Translation-ja
 74ff41ba40e19c9ceb4c607b122b7811   803966 main/i18n/Translation-ja.bz2
 85c4f9ec1e8e2d6faab177ef030ad2aa    11879 main/i18n/Translation-km
 46d57c586859cecf5c1a4470f666000d     2371 main/i18n/Translation-km.bz2
 def6a2d200b3c67b6a1c497524d0a631  2606190 main/i18n/Translation-ko
 3210a7e112a3f29ecf785ba05a78559a   584643 main/i18n/Translation-ko.bz2
 d41d8cd98f00b204e9800998ecf8427e        0 main/i18n/Translation-ml
 4059d198768f9f8dc9372dc1c54bc3c3       14 main/i18n/Translation-ml.bz2
 904af013a9ba73cd72f71a1ca451be5a     1193 main/i18n/Translation-nb
 bf917a722cf4d90cf2f56acb8edb1b31      738 main/i18n/Translation-nb.bz2
 cb57eb70e5645204174caec8edcc4a2b   174332 main/i18n/Translation-nl
 ad8c86dde21a892ff20203dc71eb981c    47973 main/i18n/Translation-nl.bz2
 bc88d84933fd8ae64ea0a7ba32a1e814  2051811 main/i18n/Translation-pl
 3095483ca3926b759de515651199283a   491993 main/i18n/Translation-pl.bz2
 d1736cf50b7994e7c6ce66962b7f4b03  1074959 main/i18n/Translation-pt
 7f9e024af1c410635fc69db5bf5d090a   272186 main/i18n/Translation-pt.bz2
 c3453467a749e3888da35949b643835d  3306707 main/i18n/Translation-pt_BR
 89726f5a5abac29bd3a6069e27019c9a   802734 main/i18n/Translation-pt_BR.bz2
 b50c9c49ea0a9da73b0a76db38a36ea4     1717 main/i18n/Translation-ro
 22696f68e30228ffbd84b26dbc821f81      982 main/i18n/Translation-ro.bz2
 52035b6ff376a4d7c38eea8bbd406751  3058931 main/i18n/Translation-ru
 d6c7de740e63ee4ce0e2044a0d449804   494782 main/i18n/Translation-ru.bz2
 2b383f6dbb23852965418241eda484de  5984088 main/i18n/Translation-sk
 04f2970e8de7fc5a090b84ab700cbb23  1304539 main/i18n/Translation-sk.bz2
 cf58326418b53f94289ad593878bfda2   323953 main/i18n/Translation-sr
 096b962e3404fbc28ebfb174e7587136    58385 main/i18n/Translation-sr.bz2
 366024c5bc4dabb550f8481c2d662611    85612 main/i18n/Translation-sv
 22b0c4eaa8e59ee11318ce2e68953f4b    27320 main/i18n/Translation-sv.bz2
 ced97abb44ee155f744680871aa5a6e2    14670 main/i18n/Translation-tr
 233a8366a334283e9b802cae336ed09b     5362 main/i18n/Translation-tr.bz2
 c8840c6e4bbe54b098d5b589e5d9e08b  3740343 main/i18n/Translation-uk
 7ed20cfd2585b8f77be6e2bab7561133   576766 main/i18n/Translation-uk.bz2
 2adb559c8ab8415644e43781db4f739a    21882 main/i18n/Translation-vi
 82caa7c535a1c4c7589a7b1647017f53     6510 main/i18n/Translation-vi.bz2
 f895594ce62c202132bbbe9ae32f1bc2     2007 main/i18n/Translation-zh
 3d2be55ee5ef9a79e0db9f90acc449cf     1215 main/i18n/Translation-zh.bz2
 91e9eec000876a989969a700ac7b3821   425199 main/i18n/Translation-zh_CN
 ab34838b3553d042d515eb65f5aa8816   113621 main/i18n/Translation-zh_CN.bz2
 34208715b80dcbd5fd1b87874a6705d4    39965 main/i18n/Translation-zh_TW
 6ed487c9d90ac9866174796ce73dec77    14859 main/i18n/Translation-zh_TW.bz2
 c8730ab591a9c561bfbe29bb2bd721d9    58277 main/installer-amd64/20210731+deb11u7+b1/images/MD5SUMS
 1a197cdc8ba7a3094159a1ebec0b24f9    78097 main/installer-amd64/20210731+deb11u7+b1/images/SHA256SUMS
 8521cd018a0e0b50238dab3cf673c4f7    57705 main/installer-amd64/20210731/images/MD5SUMS
 bb4d5d5a421f536dcaa3f2e4fc96c1c3    77333 main/installer-amd64/20210731/images/SHA256SUMS
 c8730ab591a9c561bfbe29bb2bd721d9    58277 main/installer-amd64/current/images/MD5SUMS
 1a197cdc8ba7a3094159a1ebec0b24f9    78097 main/installer-amd64/current/images/SHA256SUMS
 026bc90f5673b695c093e88b6e0ec351    69049 main/installer-arm64/20210731+deb11u7+b1/images/MD5SUMS
 5ef21176e2d62d993fdad8fe6f66d13f    94149 main/installer-arm64/20210731+deb11u7+b1/images/SHA256SUMS
 8544dac6e811bff5ed42e276cf530ebf    68403 main/installer-arm64/20210731/images/MD5SUMS
 7989c6f2e37aeda05d7dfc58de88d7f5    93279 main/installer-arm64/20210731/images/SHA256SUMS
 026bc90f5673b695c093e88b6e0ec351    69049 main/installer-arm64/current/images/MD5SUMS
 5ef21176e2d62d993fdad8fe6f66d13f    94149 main/installer-arm64/current/images/SHA256SUMS
 9d5c1487daa7fbbc0eb09a58cd905102    20678 main/installer-armel/20210731+deb11u7+b1/images/MD5SUMS
 9caca58b3425516dd16fec20f1ee05fd    28882 main/installer-armel/20210731+deb11u7+b1/images/SHA256SUMS
 6e3afe07880cea11cee1a8ac19ce5d13    20182 main/installer-armel/20210731/images/MD5SUMS
 350c18339820cfa3989e1297c80b9f12    28194 main/installer-armel/20210731/images/SHA256SUMS
 9d5c1487daa7fbbc0eb09a58cd905102    20678 main/installer-armel/current/images/MD5SUMS
 9caca58b3425516dd16fec20f1ee05fd    28882 main/installer-armel/current/images/SHA256SUMS
 b6629d5e5a8344e0905c72ed18aeaca4    64380 main/installer-armhf/20210731+deb11u7+b1/images/MD5SUMS
 3e31a8a4a6eac90bff6befbe1dbfc3cd    92680 main/installer-armhf/20210731+deb11u7+b1/images/SHA256SUMS
 3dca9930d681a0ba4186171684027ec6    64240 main/installer-armhf/20210731/images/MD5SUMS
 869454c4efa0fcddd91e08ab8ccf9d3b    92476 main/installer-armhf/20210731/images/SHA256SUMS
 b6629d5e5a8344e0905c72ed18aeaca4    64380 main/installer-armhf/current/images/MD5SUMS
 3e31a8a4a6eac90bff6befbe1dbfc3cd    92680 main/installer-armhf/current/images/SHA256SUMS
 d2556badb036046aff1f8d6eed468533    56840 main/installer-i386/20210731+deb11u7+b1/images/MD5SUMS
 87137d3494aed456f81705c70f5a8560    76724 main/installer-i386/20210731+deb11u7+b1/images/SHA256SUMS
 8932831dfc7fb479ada48f6936639179    56286 main/installer-i386/20210731/images/MD5SUMS
 0ccfb273991e3302a49093743aa9032f    75978 main/installer-i386/20210731/images/SHA256SUMS
 d2556badb036046aff1f8d6eed468533    56840 main/installer-i386/current/images/MD5SUMS
 87137d3494aed456f81705c70f5a8560    76724 main/installer-i386/current/images/SHA256SUMS
 998868016e1fdfa2a145942395800280      630 main/installer-mips64el/20210731+deb11u7+b1/images/MD5SUMS
 7aa9b76c5e09c5b05445ffa606fe53db     1026 main/installer-mips64el/20210731+deb11u7+b1/images/SHA256SUMS
 9533fc15e5b64180b5ad78129a5230b2      627 main/installer-mips64el/20210731/images/MD5SUMS
 a776640760fbaacfb1681f3abd0fb40b     1023 main/installer-mips64el/20210731/images/SHA256SUMS
 998868016e1fdfa2a145942395800280      630 main/installer-mips64el/current/images/MD5SUMS
 7aa9b76c5e09c5b05445ffa606fe53db     1026 main/installer-mips64el/current/images/SHA256SUMS
 fa571598ee1e33c6b2dbee7e30bbf665      630 main/installer-mipsel/20210731+deb11u7+b1/images/MD5SUMS
 6755ade8ad0a3238ef992b2b5b055c60     1026 main/installer-mipsel/20210731+deb11u7+b1/images/SHA256SUMS
 c3a9b6724a2ff5e2abf741f47a7600da      627 main/installer-mipsel/20210731/images/MD5SUMS
 01da3e1833ca954309023210e9b16159     1023 main/installer-mipsel/20210731/images/SHA256SUMS
 fa571598ee1e33c6b2dbee7e30bbf665      630 main/installer-mipsel/current/images/MD5SUMS
 6755ade8ad0a3238ef992b2b5b055c60     1026 main/installer-mipsel/current/images/SHA256SUMS
 a3b2d71556d4030ba67ddd5e2edb63cf      576 main/installer-ppc64el/20210731+deb11u7+b1/images/MD5SUMS
 fb4c51ffbc1c1c0de08e035cb06a0c63      972 main/installer-ppc64el/20210731+deb11u7+b1/images/SHA256SUMS
 37515f49026f1bc4682fefba24e9decf      576 main/installer-ppc64el/20210731/images/MD5SUMS
 89c70369e7ab670f721a135f055d81a4      972 main/installer-ppc64el/20210731/images/SHA256SUMS
 a3b2d71556d4030ba67ddd5e2edb63cf      576 main/installer-ppc64el/current/images/MD5SUMS
 fb4c51ffbc1c1c0de08e035cb06a0c63      972 main/installer-ppc64el/current/images/SHA256SUMS
 c89c26c2cc9d407be87915ad5de99f88      374 main/installer-s390x/20210731+deb11u7+b1/images/MD5SUMS
 0ac8638a6ff89d2f8e3ceb1c51b39eab      674 main/installer-s390x/20210731+deb11u7+b1/images/SHA256SUMS
 580b19117c2b6c6f2a8ad8aca5132826      374 main/installer-s390x/20210731/images/MD5SUMS
 da16ad53b0185c6e48397e05f2efadfc      674 main/installer-s390x/20210731/images/SHA256SUMS
 c89c26c2cc9d407be87915ad5de99f88      374 main/installer-s390x/current/images/MD5SUMS
 0ac8638a6ff89d2f8e3ceb1c51b39eab      674 main/installer-s390x/current/images/SHA256SUMS
 89ad4d3b28d51f39938cf10575544163      117 main/source/Release
 4dc0d4fb57d31a820d50565ca5904136 44655922 main/source/Sources
 6ca64fd70ce2f771595248c67b1d63ab 11429086 main/source/Sources.gz
 632766a36d87c6379182819386228c24  8633788 main/source/Sources.xz
 5f624011d3b0a82f23445c2861deac99 17347341 non-free/Contents-all
 c64dcd5c2b4db85f729afa8623adb65a   888157 non-free/Contents-all.gz
 d6bec1f2c68aa61c10d5ea048bb61876  1097448 non-free/Contents-amd64
 f5a3b5d556d2ac2276e434d47321c42c    79655 non-free/Contents-amd64.gz
 2a3fa76ebbc2b8ce1dc696fd4f93d5cf   499970 non-free/Contents-arm64
 6fbffff6347fe5e6e7099295803f549c    37376 non-free/Contents-arm64.gz
 f408ea79e9570389d5ee84acf709fefe    95417 non-free/Contents-armel
 b7a69ebcb774fa413e4016bb93c3d044     9298 non-free/Contents-armel.gz
 6778fabc7cec1e4431b4e6354d7c6331   146124 non-free/Contents-armhf
 146fba98ac2f400fe25facd0ca7aa193    13502 non-free/Contents-armhf.gz
 c2a617bfa92c1ae1471d92c59fe2e012   343198 non-free/Contents-i386
 1550b2598d6a74262e40f69cc64ed0e1    29072 non-free/Contents-i386.gz
 900df746b6e7accfd8883d31c7d28313    91215 non-free/Contents-mips64el
 7c382180d55972ff768bb8a05222a412     8686 non-free/Contents-mips64el.gz
 904ab7d197244bdfdbf6b58bc61d09ac    92244 non-free/Contents-mipsel
 73868036dab5f62f60ad63ebfb7ca253     9026 non-free/Contents-mipsel.gz
 9ff21fb911bfd562eb84f85d9adda009   716110 non-free/Contents-ppc64el
 5c487a4250d7e24f4cce14e8e7c430f0    49881 non-free/Contents-ppc64el.gz
 f3aa91e39f1d170310ec9820ea4dae2d    74537 non-free/Contents-s390x
 2b363c4c14b66b56f3009f85c29415dc     7407 non-free/Contents-s390x.gz
 28092fe18d286a60369b2baf177a3b66 10803369 non-free/Contents-source
 a1340038124c66a82eb9afd4e0a5b39e  1063443 non-free/Contents-source.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-all
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-all.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-amd64
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-amd64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-arm64
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-arm64.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-armel
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-armel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-armhf
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-armhf.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-i386
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-i386.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-mips64el
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-mips64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-mipsel
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-mipsel.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-ppc64el
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-ppc64el.gz
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/Contents-udeb-s390x
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/Contents-udeb-s390x.gz
 28683b0c800362ab66657f988f8fe158   189021 non-free/binary-all/Packages
 8b503f66350a43348e728ef668a3e66d    50928 non-free/binary-all/Packages.gz
 89e1a28553ba1bf59ef7a537d0e13dcd    42996 non-free/binary-all/Packages.xz
 7e31516542d9449a20d6d5a5be387724      118 non-free/binary-all/Release
 48fd35f0f54926f3b555aca2d9cc267c   545576 non-free/binary-amd64/Packages
 f4a7af068e39f558fb3c7d38d7227d31   122225 non-free/binary-amd64/Packages.gz
 90b0a4d2ddb8c4e4a507459f79006f8a    97772 non-free/binary-amd64/Packages.xz
 e1a343e13638a8191104cc84d9c87347      120 non-free/binary-amd64/Release
 d1b662147ba2a93fda8daa87bcc45a4f   381335 non-free/binary-arm64/Packages
 0ea4ed22af6d2313b0e15670783ff965    88201 non-free/binary-arm64/Packages.gz
 471ad96a8a2139576049b8bc0a7541de    72980 non-free/binary-arm64/Packages.xz
 9e926156e80b4e4db84524d2f0079024      120 non-free/binary-arm64/Release
 0967ff1cbab012d79d544d2fc19bcb3c   227933 non-free/binary-armel/Packages
 66f87c4a0607b4d535045f41bb1debbf    61822 non-free/binary-armel/Packages.gz
 943edb5f2d977c5e883e123d7a162a3c    51800 non-free/binary-armel/Packages.xz
 096a48f395e2487865b756ea3d0e20ff      120 non-free/binary-armel/Release
 11aef19231277b7df07bb88b31da40fb   259156 non-free/binary-armhf/Packages
 f084eff9f9e23dd4f071fc6caf167026    67317 non-free/binary-armhf/Packages.gz
 478795a629bddb465e832a8c15908d23    56272 non-free/binary-armhf/Packages.xz
 b94819d3bb5bb39f9abcf15388d47bf3      120 non-free/binary-armhf/Release
 cf0f27353a145dc9a999d6ac8f2b242d   422388 non-free/binary-i386/Packages
 cac7e560af4f05675b65252d54968a1e    96319 non-free/binary-i386/Packages.gz
 d528af0816ff9a8b491442be615e0875    79344 non-free/binary-i386/Packages.xz
 4a714713c871406dae3fee358bf4525b      119 non-free/binary-i386/Release
 b241349c71327389608d1ed7805fb917   225506 non-free/binary-mips64el/Packages
 79ea1e07e0c12ca9587d966e90a803d3    61024 non-free/binary-mips64el/Packages.gz
 800788cecc80de3a8dc8555edc4e1f3c    51124 non-free/binary-mips64el/Packages.xz
 9673c21044a83dbab7dd0cc54a4e02c6      123 non-free/binary-mips64el/Release
 5637ea382ea6ea47628b489854f51823   226162 non-free/binary-mipsel/Packages
 cb900ebc58b732e246dad1c05c2da62b    61277 non-free/binary-mipsel/Packages.gz
 eefd4b08c8da7bb89f71627c9f05a04e    51364 non-free/binary-mipsel/Packages.xz
 c3acf902cc79cfb97370b0efec244dea      121 non-free/binary-mipsel/Release
 4404ce86106e7e32bd47bd465f954e8f   381597 non-free/binary-ppc64el/Packages
 9e8c1c8f825dd79ed1d335608297770e    86900 non-free/binary-ppc64el/Packages.gz
 ffe9119e39ab6813cdd7dd7b5b8299a0    71812 non-free/binary-ppc64el/Packages.xz
 79b2651c4e8f6dc350c53e634f30ef2d      122 non-free/binary-ppc64el/Release
 205f9ec14fe81d12021eba70ac927040   220570 non-free/binary-s390x/Packages
 73a6b1dbd8f6c0ffbc4cb90c8737651b    59856 non-free/binary-s390x/Packages.gz
 d4f95c7b3fed2787ebb231f6e8fea4ef    50216 non-free/binary-s390x/Packages.xz
 cf48e148549473e729455b280f93e43c      120 non-free/binary-s390x/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-all/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-all/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-all/Packages.xz
 7e31516542d9449a20d6d5a5be387724      118 non-free/debian-installer/binary-all/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-amd64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-amd64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-amd64/Packages.xz
 e1a343e13638a8191104cc84d9c87347      120 non-free/debian-installer/binary-amd64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-arm64/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-arm64/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-arm64/Packages.xz
 9e926156e80b4e4db84524d2f0079024      120 non-free/debian-installer/binary-arm64/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-armel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-armel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-armel/Packages.xz
 096a48f395e2487865b756ea3d0e20ff      120 non-free/debian-installer/binary-armel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-armhf/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-armhf/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-armhf/Packages.xz
 b94819d3bb5bb39f9abcf15388d47bf3      120 non-free/debian-installer/binary-armhf/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-i386/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-i386/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-i386/Packages.xz
 4a714713c871406dae3fee358bf4525b      119 non-free/debian-installer/binary-i386/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-mips64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-mips64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-mips64el/Packages.xz
 9673c21044a83dbab7dd0cc54a4e02c6      123 non-free/debian-installer/binary-mips64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-mipsel/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-mipsel/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-mipsel/Packages.xz
 c3acf902cc79cfb97370b0efec244dea      121 non-free/debian-installer/binary-mipsel/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-ppc64el/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-ppc64el/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-ppc64el/Packages.xz
 79b2651c4e8f6dc350c53e634f30ef2d      122 non-free/debian-installer/binary-ppc64el/Release
 d41d8cd98f00b204e9800998ecf8427e        0 non-free/debian-installer/binary-s390x/Packages
 4a4dd3598707603b3f76a2378a4504aa       20 non-free/debian-installer/binary-s390x/Packages.gz
 8dc5aea5b03dff8595f096f9e368e888       32 non-free/debian-installer/binary-s390x/Packages.xz
 cf48e148549473e729455b280f93e43c      120 non-free/debian-installer/binary-s390x/Release
 f7208886e345a2c1c5681b7bc1f891f3   278293 non-free/dep11/Components-amd64.yml
 ab8bcc71919bb29e6a367d9058dc0125    29634 non-free/dep11/Components-amd64.yml.gz
 afd21b4c476c6b604c4f998d90383234    17904 non-free/dep11/Components-amd64.yml.xz
 71e3cebf69c369e3d4e6b64e48fe037b   271451 non-free/dep11/Components-arm64.yml
 4b40bf8ff6579f425fd308cc4f32bb26    27686 non-free/dep11/Components-arm64.yml.gz
 04fa2b6c4dc8d23f6ee6334754b725df    16392 non-free/dep11/Components-arm64.yml.xz
 678290cc20fe4c69fac625c25f48577f   271451 non-free/dep11/Components-armel.yml
 b76376c24cdd9bb014e63503830766f8    27606 non-free/dep11/Components-armel.yml.gz
 b431acc1b0f700a021a3ab1305bc3c33    16448 non-free/dep11/Components-armel.yml.xz
 7f659804cad02381ed7735779c211771   271451 non-free/dep11/Components-armhf.yml
 0221ab3c0654617c6de5d2b74eac7b15    27691 non-free/dep11/Components-armhf.yml.gz
 2df1dfb4d502d5c01f744bac99e8a0bc    16364 non-free/dep11/Components-armhf.yml.xz
 1422b7cb028418049315374e46dcbf86   280613 non-free/dep11/Components-i386.yml
 7a014ddef58173efeb07ce9d7b866331    31098 non-free/dep11/Components-i386.yml.gz
 ee2f702d30a2274d969a8e9044da54f2    19156 non-free/dep11/Components-i386.yml.xz
 2f39022b38ebd28b86acd148ad0389d2   271451 non-free/dep11/Components-mips64el.yml
 5e839450348a20fc9f81cdc9dd0b9663    27765 non-free/dep11/Components-mips64el.yml.gz
 fbf40f634081acbde994e89d8731d159    16380 non-free/dep11/Components-mips64el.yml.xz
 4ff7e301bb5eaab539783f39c24b421f   271451 non-free/dep11/Components-ppc64el.yml
 d7c37af104343f2eb2b10a0980c96661    27592 non-free/dep11/Components-ppc64el.yml.gz
 afabe491b91df1be19287ea4e978e7aa    16576 non-free/dep11/Components-ppc64el.yml.xz
 05dc5f141a7ca96f1aae6d571dd37361   271451 non-free/dep11/Components-s390x.yml
 4a5b9e250991cd5d661db03f4bebefa8    27558 non-free/dep11/Components-s390x.yml.gz
 b0593a88d870f066f1a83dfb382e09c5    16356 non-free/dep11/Components-s390x.yml.xz
 40dd67e0e1f81416405be5c0dc8ee47e     8192 non-free/dep11/icons-128x128.tar
 b117213e4fd39f9c75c1699ebaf3d610     2394 non-free/dep11/icons-128x128.tar.gz
 08a465949d80332d065e6f4ec8459930     4096 non-free/dep11/icons-48x48.tar
 49466a3c36fe0d0cbb5940896da60960      741 non-free/dep11/icons-48x48.tar.gz
 5d6e61a41610797276e5b6f16d60f7e1    36864 non-free/dep11/icons-64x64.tar
 0196f7b979db4111a6d9b988e63101a0    27667 non-free/dep11/icons-64x64.tar.gz
 c423c38128e8f1d7984682751173441c   572893 non-free/i18n/Translation-en
 65a9781186757af5a261165878a7f9b0    92419 non-free/i18n/Translation-en.bz2
 d48a4039dfcadee2dbc49be8216a78f3      121 non-free/source/Release
 1ebf108ffd532e93efc36f22d900441a   360307 non-free/source/Sources
 85f6ca3b8dfaa5af893d96ea4b759971    98323 non-free/source/Sources.gz
 10afbe839c1da98bc50d6dc6506652a8    81280 non-free/source/Sources.xz
SHA256:
 3957f28db16e3f28c7b34ae84f1c929c567de6970f3f1b95dac9b498dd80fe63   738242 contrib/Contents-all
 3e9a121d599b56c08bc8f144e4830807c77c29d7114316d6984ba54695d3db7b    57319 contrib/Contents-all.gz
 e60f82140294e076f97a4148cfd8e594ae808c423d40b62be455bb28af8fb6d8   787321 contrib/Contents-amd64
 845f71ed2a0a3ea784c355427362164cb316b01e6ce956a38ea95a001711709b    54668 contrib/Contents-amd64.gz
 1ad2b49ab401affafeb146c2badf94f1d699abd27f52b57d5e4b0fe3d37c9682   370915 contrib/Contents-arm64
 5f54b4d15ca5a9308eee238da9fa9512dcf8ec15a55cc22fce4efc3142146c01    29596 contrib/Contents-arm64.gz
 b4985377d670dbc4ab9bf0f7fb15d11b100c442050dee7c1e9203d3f0cfd3f37   359292 contrib/Contents-armel
 f134666bc09535cbc917f63022ea31613da15ec3c0ce1c664981ace325acdd6a    28039 contrib/Contents-armel.gz
 b5363d1e3ec276a0cb10bc16685bd02bdc330719d76c275bebd344adaa91583b   367655 contrib/Contents-armhf
 fc4edd280f2b254dbfa98f495e5f4ca6047ec9a1539ccb8754a1f93546ea32b5    29236 contrib/Contents-armhf.gz
 77d465435ba8f5bad03b76624835f91e9ebf3bb09b124ab1a06e70c8b2629b30   407328 contrib/Contents-i386
 e4a82b31ac7b5b139fd3bd93ad466de75f7bf7d54410967253044895e41c36fb    33556 contrib/Contents-i386.gz
 c0efa60eaa3b47bd93ca71220c6fc734d54b257e16bb6dd8dde43ca722f242dc   359402 contrib/Contents-mips64el
 4fccf5298ef664c2de3dc7eeb203eefa3bf8ec82b95b1c696b856a43af35e395    27962 contrib/Contents-mips64el.gz
 db2388b4b8d300fdc265fe064288a8de5f69958b06ed6cfeff3b8528e719015b   360549 contrib/Contents-mipsel
 27db69688406433748363f4a70cac108f29b99555a6d5dc3eaba6b2e8b526dfc    27942 contrib/Contents-mipsel.gz
 e62412c1f585461c8ae27d4d2a79b82c27dba109ac19df81a15ae7f53369cf65   370025 contrib/Contents-ppc64el
 8ac6ff54ba23486d9c139ee79a6296760dc20022209ffc321296967717a37fd2    29381 contrib/Contents-ppc64el.gz
 bb1fdc3fafd28760f57d951e96a150e8ec7d6b0fb75443de93f08a61ffbd7042   357860 contrib/Contents-s390x
 009373ff8cde80de63a4303b8c6eab79af34d6c2c0c831d1b38e1f9329c396cc    27518 contrib/Contents-s390x.gz
 7d79e95f92007f2885bba7ff9d40a81cefea96959cb090dc7cde26a77e7f1ea5  6722669 contrib/Contents-source
 d6655657ff285c9372e18b0ebff346e922694de31669d6c0260e789306841e9d   469817 contrib/Contents-source.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-all
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-all.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-amd64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-amd64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-arm64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-arm64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-armel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-armel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-armhf
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-armhf.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-i386
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-i386.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-mips64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-mips64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-mipsel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-mipsel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-ppc64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-ppc64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/Contents-udeb-s390x
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/Contents-udeb-s390x.gz
 70d58353b3bc6083f3946ebcdc1f150204988bed60df8c0389fa23b26924adcd   103239 contrib/binary-all/Packages
 9baa8f0dbe243eea5e03bc9551b0e5774ea0ba690db28ae63d1f81cd6e16aef7    27385 contrib/binary-all/Packages.gz
 24cb5963261a9cb0a4671061d65ee51e211e00ea754e4f5ec6426a1a78745ec1    23916 contrib/binary-all/Packages.xz
 93a2ce91dbee932c8b48caae660d67b864819f239de1cf9c85cbfeb3c450e396      117 contrib/binary-all/Release
 25bba54443595d2760419c8873b026880ad3553697b4254f0473b7c859c3526f   231878 contrib/binary-amd64/Packages
 05b545380de2e24307c4b33497327a397b5fac53c53c2479d487280c69c55b7b    60884 contrib/binary-amd64/Packages.gz
 572aa5c4767342e411f9ec261ebb871a48da20400d37e9f960c0f3960a26fc66    50588 contrib/binary-amd64/Packages.xz
 4c337ceffea66616199c9d6f6f0996dac105940b4e220425a12c9ecba87a1ff6      119 contrib/binary-amd64/Release
 7ab66ca6c3c1f575100f8e39fee460115ba8292a489c07e9ea1b0a914e47f67c   180884 contrib/binary-arm64/Packages
 4da911f1c6926b85d6a9a025d73be907124db4a3e99872b0128ad2187a5af5ef    48958 contrib/binary-arm64/Packages.gz
 07b68a663f305c1a676642f078a3d9243072e2f2402ad87c405f0a4c7744cab1    40964 contrib/binary-arm64/Packages.xz
 1b6ff9a1c182ed456e4aeff56a54eddfb128ce6c39877b70769dd79e012143f6      119 contrib/binary-arm64/Release
 d353d3f7b451cb07472d111221866fd89c6e7b28ad0fe66044f35e2eca6189fc   163042 contrib/binary-armel/Packages
 5333591cd2ee7e750d864f875799c83b4985f0473a02e525365db3fc5b27ab36    44389 contrib/binary-armel/Packages.gz
 6493591c5f010aa3b50e7052c4746f6afe40a0fd31ffcce08c706aec6e7b672d    37452 contrib/binary-armel/Packages.xz
 04ff4b12d802b8291b4408a1435e0e11424b96e1628d10981b18d7bfbe481708      119 contrib/binary-armel/Release
 75d98358dbea38501853ae9cd7a2da4f84d02eb4543bd9e96f0c3e6cd5945533   175566 contrib/binary-armhf/Packages
 fde856e3b07624cb5e3d6c11dd450aae8e56f38646c4b3f3b7cbe0423f78970e    47805 contrib/binary-armhf/Packages.gz
 c572038b5ced50f74da2baa5cda8150846cface0b285218336f6af4e1365b9b0    40220 contrib/binary-armhf/Packages.xz
 d37bedd8d7cdad30b0f6699f0b0c12d60cf2a9a24866e5a256a957d625b62b8b      119 contrib/binary-armhf/Release
 6b9d6d64b15686f83bf58c5e2255bdef26a5f2cdd97c76b047ea46f533aeb0bc   203514 contrib/binary-i386/Packages
 010b321fd585b2d1c45512db80e60aefdd0fc7bbc60a53e1594ba9ad5f9ba45a    54100 contrib/binary-i386/Packages.gz
 a17c01bbbba0f218b3a38cb5b7fc3053a7cfb6364453b46b6b80687d11eab142    45340 contrib/binary-i386/Packages.xz
 4ce72f7efaa89af0624897fe2cd8495e137d4e5e0f5320cb44de27fbc3b02986      118 contrib/binary-i386/Release
 4c71f56a967f6f390c1e6d381f399d74da5a545c8906f014fe805859ba9ae55c   163507 contrib/binary-mips64el/Packages
 49f3fc82266f184e331b2b0ea0762540b8ef68486f299a5673b247f8c03d3858    44652 contrib/binary-mips64el/Packages.gz
 e0c365ed89f4538b36ab3366293d3b9f4e8472b9537d91b770f650650021f4e1    37496 contrib/binary-mips64el/Packages.xz
 59e8e1e1ec5e0d469be59b6d3321aba3f9ddd686e440bde74616b2acce355b41      122 contrib/binary-mips64el/Release
 a951b730b4a059ef33073627d50a40f204591c3a5348fbe1c5e3b21782a77e5a   164647 contrib/binary-mipsel/Packages
 662a2fb412beb7130ef5ba0440ec368825d21713392a55ea33048673bbcca3a0    44883 contrib/binary-mipsel/Packages.gz
 7a01af1780b68648eec3923fbe4fe766e210e83f0ba8b03f6bc8b9a8d4c0169f    37816 contrib/binary-mipsel/Packages.xz
 9df253300a3c33585a18f1c8b91018a558e04a222a70ce8072f76ea2e2b27ad1      120 contrib/binary-mipsel/Release
 8ff5ce44abf0d9fba97b3ce63b2d41db58d24b463dfe23cf06069a71724f7047   180387 contrib/binary-ppc64el/Packages
 ddf5d43553c9af8a6dfa0ff6f51236dee72fe15d2a09ecc9212bfeee5e667e92    48843 contrib/binary-ppc64el/Packages.gz
 84cd02fcb4a610501538fd06ebf77a67ef7badcbc6f5b1f338c6d013329ea38e    40808 contrib/binary-ppc64el/Packages.xz
 57f78f401d86eaadc5fe6ca190f162e4a0fc1e77021a6118f27aab68db0d7f82      121 contrib/binary-ppc64el/Release
 cfc032377fc264eff4a6319ecfd2722e95de7364a63b29eed53cc78603a8a8aa   162250 contrib/binary-s390x/Packages
 72be2806452fee7d70ef80ffac98e3f408e7389dbbbaaa6d9228f48a6733b773    44334 contrib/binary-s390x/Packages.gz
 9a14a52c690b24eb92939192abc4d4e8b23a2347a838232774016ac79c3d8ec8    37244 contrib/binary-s390x/Packages.xz
 cb54af7d630a4046eb41cc3096838019e16b72f3c0f505136788bcf09fa632c5      119 contrib/binary-s390x/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-all/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-all/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-all/Packages.xz
 93a2ce91dbee932c8b48caae660d67b864819f239de1cf9c85cbfeb3c450e396      117 contrib/debian-installer/binary-all/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-amd64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-amd64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-amd64/Packages.xz
 4c337ceffea66616199c9d6f6f0996dac105940b4e220425a12c9ecba87a1ff6      119 contrib/debian-installer/binary-amd64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-arm64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-arm64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-arm64/Packages.xz
 1b6ff9a1c182ed456e4aeff56a54eddfb128ce6c39877b70769dd79e012143f6      119 contrib/debian-installer/binary-arm64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-armel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-armel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-armel/Packages.xz
 04ff4b12d802b8291b4408a1435e0e11424b96e1628d10981b18d7bfbe481708      119 contrib/debian-installer/binary-armel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-armhf/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-armhf/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-armhf/Packages.xz
 d37bedd8d7cdad30b0f6699f0b0c12d60cf2a9a24866e5a256a957d625b62b8b      119 contrib/debian-installer/binary-armhf/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-i386/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-i386/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-i386/Packages.xz
 4ce72f7efaa89af0624897fe2cd8495e137d4e5e0f5320cb44de27fbc3b02986      118 contrib/debian-installer/binary-i386/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-mips64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-mips64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-mips64el/Packages.xz
 59e8e1e1ec5e0d469be59b6d3321aba3f9ddd686e440bde74616b2acce355b41      122 contrib/debian-installer/binary-mips64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-mipsel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-mipsel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-mipsel/Packages.xz
 9df253300a3c33585a18f1c8b91018a558e04a222a70ce8072f76ea2e2b27ad1      120 contrib/debian-installer/binary-mipsel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-ppc64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-ppc64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-ppc64el/Packages.xz
 57f78f401d86eaadc5fe6ca190f162e4a0fc1e77021a6118f27aab68db0d7f82      121 contrib/debian-installer/binary-ppc64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/debian-installer/binary-s390x/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 contrib/debian-installer/binary-s390x/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 contrib/debian-installer/binary-s390x/Packages.xz
 cb54af7d630a4046eb41cc3096838019e16b72f3c0f505136788bcf09fa632c5      119 contrib/debian-installer/binary-s390x/Release
 f0a51e6d75f883bdecf739b214104a17dba111de8b42022f6b8b053870c83851   119152 contrib/dep11/Components-amd64.yml
 e14a1bb3690a18ec7c5b7997fabf4d8d4fa633efdf84a25e071a1f62a2c064b2    15579 contrib/dep11/Components-amd64.yml.gz
 58921318632f77413bee8d9e980689f8f139eb1169b5ce201da06e6f280d485f    13564 contrib/dep11/Components-amd64.yml.xz
 26538634f90cd6f04a6be602151fa6a098075c3013b66a81439a7bbdbfaa40f5   113437 contrib/dep11/Components-arm64.yml
 840908ab753dba952e073216007f93d351577792911dcc09a15a16abfc32c8a7    14251 contrib/dep11/Components-arm64.yml.gz
 3afec5908036aa2d47b9a9a33c13eca12bba1aaf8d8bbb06ffb1627e93f6526f    12480 contrib/dep11/Components-arm64.yml.xz
 fb35649f6c32b71b9d85388c2c238011161c250df5c62e2c4d3446e369dced4c   113437 contrib/dep11/Components-armel.yml
 c305f1c0826e0414bbf36524d8b0fc2723ffc0fb222275e1e1728914fc334c75    14029 contrib/dep11/Components-armel.yml.gz
 fe15a53774801f8d9cb04aa8324cbdb9d741ec75ae0999e033873458bd6160b0    12524 contrib/dep11/Components-armel.yml.xz
 0ed24b6d7ff891c82697497dddfbbbb6818c168c55b41ae710e9cc9240d0d9b2   113437 contrib/dep11/Components-armhf.yml
 f5260cdac915ff5eba0a48757c93f8f8b6421a673e641285f43d83f62be3eb8c    14127 contrib/dep11/Components-armhf.yml.gz
 db97becd2ab6a05bcef05d824b89080a1e7c03a69735df3bf5945f6989a9e504    12480 contrib/dep11/Components-armhf.yml.xz
 9adf35216113140c31c2e9c169a3eaa465044f41f8803afaac955c467a1e5a49   118972 contrib/dep11/Components-i386.yml
 c1d4ea9c0ac26f2b62d45c8c595ec9a5bc1c737b50634d7f86a4bfac17c9b180    15566 contrib/dep11/Components-i386.yml.gz
 51ff60d5f02b46e08acea4054484f5c66d721c19beff4857cb2570f43e881a69    13560 contrib/dep11/Components-i386.yml.xz
 50b6970af7de299a90ac651cceb6cc011e8d165ea0701f7b1c9daf6c1be485f0   113437 contrib/dep11/Components-mips64el.yml
 78aad16ddec6b18d30ce4e20f52008f72efc78ba55688fa462741f4bb514043f    14056 contrib/dep11/Components-mips64el.yml.gz
 efb0fb003bbd3997128bef56f12104872604fad320b38fd99bca25e68210d98e    12500 contrib/dep11/Components-mips64el.yml.xz
 05c2268c20e748baf8da20f7169918e2f6dcffb6e4f6dfc22829607cec7ea564   113437 contrib/dep11/Components-ppc64el.yml
 19f600014e245e7d07762b7f07d8de6884b1208a280a19274e56b4174931082a    14219 contrib/dep11/Components-ppc64el.yml.gz
 dc8b525d7043ba3a85154ad39d0c809e7215c5b2f3865efbd94ff3daabe54810    12496 contrib/dep11/Components-ppc64el.yml.xz
 5d43b650d261ac23815d98e9a4f644d56f4113e63f8a42b1558ff1c82e925d2f   113437 contrib/dep11/Components-s390x.yml
 c1811e0538dad96441a4172e661b9ef7fca9c05d86c4b157a66046bf49aa70e1    14050 contrib/dep11/Components-s390x.yml.gz
 42356b4c04801189947748d6fce6e28e356a114869a7895e4921a3b4901e678c    12488 contrib/dep11/Components-s390x.yml.xz
 641e9a50f98d7e4921102164e7737b095c9faead09f6de4459086b598b3bf0d0   271360 contrib/dep11/icons-128x128.tar
 34b531c5292651ac5a18d0477bb8cf1420f3d969ad73d45fd596641d768b853d   195507 contrib/dep11/icons-128x128.tar.gz
 fa3a19603046c258e647b0c1fcdc6110f0b5c1f2801ee950eb1261e8c02e03d6    83968 contrib/dep11/icons-48x48.tar
 28a6f153e56e9b567cc7fc03d6faa6dfb8480ee3f36e0c8d9646e4de3898480b    47168 contrib/dep11/icons-48x48.tar.gz
 d882fc33534a8677ed8d3ecf81f7a076fa57e8e8135bf586f8af20371edb195b   138752 contrib/dep11/icons-64x64.tar
 45c8eda64d05f1feee0040809128760f9489665d66bed0502cb179fe0ec79f6e    93294 contrib/dep11/icons-64x64.tar.gz
 094badc305c90db005324c484a55d88f14dfc805aa429856a5863a96518a88e8   192685 contrib/i18n/Translation-en
 ce7d3d607194cdfabf421c313030e88876ee899d5cd01f5b023cfdc0c0ed0f40    46929 contrib/i18n/Translation-en.bz2
 b89a3b9258ada994f8857f734110206864802d179201da6fa97a666db306ada9      120 contrib/source/Release
 e331ac856d30949d3d70b299678f1f23462785681c70a62205ae35903d2c50d0   178776 contrib/source/Sources
 b34bb0d3527f1086ae23a6d2ae47bf790572a7d07ff0ad444f0f2c68afd3c504    51355 contrib/source/Sources.gz
 99262e6c7f527f6654eb8e8b3415ee29fa5f2669d9bc22ce95881422b4b9b603    43208 contrib/source/Sources.xz
 2400074e2a3897ad55b2e0e110b3ad66af9446b0cb77e28c7d5c92abf0a60db1 477769406 main/Contents-all
 a61ae2ae233b5eb73a624cc09c8df2eb3beab0ff44fd7cc75d2e64eaf36d2204 31069218 main/Contents-all.gz
 226a3117b453b3350ee326fa65963b4936e6f5f0f0baabfc71ebe9458b3a5735 129058022 main/Contents-amd64
 ee49ff0f5accae61de15bab5f6afd31d6b0b4676d59c9930fbe6dc24ed54954c 10270460 main/Contents-amd64.gz
 13b617dbf9aee8e874fe709647f47bd2ee3780f4cf7c717f33aa7e1cd58d5e3c 122426895 main/Contents-arm64
 68d31c4707f80bb72cd02c1276b53e22b5c0175a7f46bf75da6eecb754f8aff3  9831920 main/Contents-arm64.gz
 5586eebc2846a2c4537cdb9020b216dd67b8c0eddc5a3bb8a9a0a6155e5946d5 104683113 main/Contents-armel
 780507976f07c70aa2e787b9a6f9cab2ed8b1aed99b726906677d8e4ce1c8436  8703570 main/Contents-armel.gz
 6f02632c558a77c4d6a78d64b437bc1c25857a4d04250abb51c5f13b3e86c119 113716591 main/Contents-armhf
 22f19d2f3ae739ba4f7b0d0bf2effab552e64aa65c8a236b16c069e9fb8e5e90  9305906 main/Contents-armhf.gz
 1c9cecfb8e79dfebf5d5cf0dc17271c2419fa72a4ef6e3b4b9e5ef1e3acad18c 129088857 main/Contents-i386
 b826bd0b623bdce4568f0f1f8205c8f6f4e50b8ecfcd99a3b26bbddaf3900f8e 10208982 main/Contents-i386.gz
 2a03448109546da0c72c31d0a534637306106e2195bd10b58aa2237ea60095f9 111097071 main/Contents-mips64el
 147af2223dc310a089b0d18c820421f926d33e24ce2d0dbc6b20203c35cfffb7  9042221 main/Contents-mips64el.gz
 6ef7f5d32e074dfe0231fbb8ac14f3cc67b511f924ec502736afe36cd549774a 112593872 main/Contents-mipsel
 a28b893a37dd761f6c95c0f6c722b9ac5324869d91bfc97cd7a1270159ac939e  9178325 main/Contents-mipsel.gz
 720f513250bebd466149094ff4ca8f8e1b412810a218f1cddfaa31163577f44f 116027632 main/Contents-ppc64el
 a852312c04f59070951821eda6893270b28d23e12977f77a0933cce2882547e5  9355024 main/Contents-ppc64el.gz
 c92fc53215a097d7be1cc62c20946a4744221ba8dd58f62a81258fa79021aa06 103638209 main/Contents-s390x
 e1ed13910c59f0df90724c116450ac3aa2936a2d89497bbeb263993b9e767102  8711885 main/Contents-s390x.gz
 19cb2eeeb6bb6459bf824cfbe9a82c44298fbd2ccb614ad130583fb5b07f3be3 690410830 main/Contents-source
 2d5b1d50f3f42a073f6b27127bdbc0e19870188aecab8417dc32dde30138fbe1 73501881 main/Contents-source.gz
 b709d41e19af82147c367d90a74eae144ab18744d78817b6395fc1344fb99c76   157382 main/Contents-udeb-all
 f9801d96354f0b11d5357633cb9068dff1f39b9210eaeb70455db63ee0ecbdbc    13516 main/Contents-udeb-all.gz
 88d816aa94f2071b483a84751d8109af7e89e049d9a5d690e2fc75a1fd86a9dd   477050 main/Contents-udeb-amd64
 1344217ca4f19362a2bcbeb119e0a6d36e853481086431794142a930b46b13b8    36011 main/Contents-udeb-amd64.gz
 5860a70ba4852152099c974ee16e92c0a935f6f96257204313ca99e8169826fe   508817 main/Contents-udeb-arm64
 71a73fbf6e739034fd57e1a8255565d260b91cbce409128dcc69fa059623dcd2    38139 main/Contents-udeb-arm64.gz
 b4326a16088882aa0a038240624002e1994e232d98f4194b65907be2f94270b3   323083 main/Contents-udeb-armel
 53c51078092e821f51bfa9477f35bd2a2148f045b5f6ae06a42b4ac79d440c42    25477 main/Contents-udeb-armel.gz
 e85592b3fbaaa08298eb08c7ee40c80c3826b961f3fcee0de1b6cedc0bf283aa   579793 main/Contents-udeb-armhf
 a9694e389e0c7eb23c9bad861b0f07db9114a4f4abf4648081b7640783c1e52c    43153 main/Contents-udeb-armhf.gz
 286e7790529e1012095eeedadef806ab30696dbf3ca55ecb55cd91247d239287   751383 main/Contents-udeb-i386
 bbe85229c4d8e20b737bf432e365a3efd51fcf557df061db147e9f63a322b69f    53984 main/Contents-udeb-i386.gz
 fcc311dbf697321971d9608ffc05555edbce48bd126b6d1d2b7bcd9a8eab0a25   760534 main/Contents-udeb-mips64el
 15bcf854ec4356278e912856e3904938ea994ae9742818854912126ee15f9cfc    52873 main/Contents-udeb-mips64el.gz
 572ddd8f7183d851c2fcfcda55166cd4ddb95b6eba0b73c07572dff8e74f797a   760210 main/Contents-udeb-mipsel
 d51989963ffcccba95d5591fe78e9aa6ecefd480f7464a199288d7153ea1a637    52810 main/Contents-udeb-mipsel.gz
 c6e87c5351596a66921e0559dcfdfae17c52cb422c709f2e44b19cf6064e80c9   401639 main/Contents-udeb-ppc64el
 3a94166a9523c86e71d08304a2bd46dd72392738f22b608a4b2b45fb77491f58    29533 main/Contents-udeb-ppc64el.gz
 42b53406c44e9439e86506343040298b5e1405e6791594953bb058ca6effe8f0   258318 main/Contents-udeb-s390x
 ce12cd039c002aeef6d9b364d73e313712d4d39970241953919fa6e8db0ce628    20894 main/Contents-udeb-s390x.gz
 b42ce26db7c150a2dbac237732eb0e5dd5ef28e2ca51a5482cd9293dc64d8357 20423830 main/binary-all/Packages
 33eec3157da3c566e1f078bff8b46bd6074dcf3c9f242c760b8fcb2233bc5d32  5208282 main/binary-all/Packages.gz
 09728ec87e7b549eaa43b80fbb9432e36043b9874cb4b3f95428a1eb2a96582f  3918264 main/binary-all/Packages.xz
 5fca0b091a4008553328742c4e5509375042ae86fd25e078e5641da80c6e35ed      114 main/binary-all/Release
 35eb7de95c102ffbea4818ea91e470962ddafc97ae539384d7f95d2836d7aa2e 45534962 main/binary-amd64/Packages
 a445d7472b76164584ebd9aebed31517837dac1f792164bba926278dcb166255 11096605 main/binary-amd64/Packages.gz
 9b3d1e096767eae5ade343b1b123e1787cc49cc78b139db247fbe96f8f3f545d  8182920 main/binary-amd64/Packages.xz
 ab78444b1bbaa56630b4f90edc8982f4fd965ac4db2b5530855b768c1c8fa9f9      116 main/binary-amd64/Release
 d908fe964d366107388f445a2afa408224ccf6a665ef087f26afd1cfd2b9ad04 44816551 main/binary-arm64/Packages
 1afdf5fece156bfb26fcb25409a00defecc507b38ae69097a09b18ff6b1d2b50 10941625 main/binary-arm64/Packages.gz
 d2b7315d4fda95e5a5f2ce7ca6e2e44d9bf1b1d9e9d980ce416d35a4d00f1a2f  8071508 main/binary-arm64/Packages.xz
 fc1fcedbe9926a4b0b8eb49c4ad003eeb5d656f7a447864ebab16f026100f6f7      116 main/binary-arm64/Release
 6b115f03bd7e988bade97cb51a9ada488bad7623ad3f085da265df9e4e64cfec 43343990 main/binary-armel/Packages
 c2564b86e9dd83293f0a43f4fb18506ab8487878bf518115dc42b4e2125ca5d2 10677432 main/binary-armel/Packages.gz
 a81082ad524af5c8ff7fe7674bf715daa82de2ce1bfc39dde407dfb0d6bb6ad8  7871888 main/binary-armel/Packages.xz
 abb6c54c329433e32610e26704ca667256c1ad24cbdef67431ded86b67b9df8d      116 main/binary-armel/Release
 e14f5af333a1e465450a88a9a40806b8d4b0e2dd903e9b9c698f4004eac6f0b0 43846413 main/binary-armhf/Packages
 7cb2281126c6161b691eaa41e647209b5240c660a99e2b083119e6c701a0a5d3 10775534 main/binary-armhf/Packages.gz
 ba960fa5d4178671db25ac4be29a375496edb695aac902f99c04aa482a60a379  7944712 main/binary-armhf/Packages.xz
 07c1cebfbbc800619727cfabb5bbd313a65ff1ad3df60fe04b680de8c63846cf      116 main/binary-armhf/Release
 164486fd11378f87865c09143df1514fca7045166c9c1ba61f2c50cffb987ea6 45094980 main/binary-i386/Packages
 216af7eb177d93f2004318058ff3f833dd6cb66bc23a3ad17b0c27edbbacc923 11013153 main/binary-i386/Packages.gz
 cfd786ed196f7a512764069e09f20ef97c536552f777ecd303b4a1538de5fe9c  8121972 main/binary-i386/Packages.xz
 598ab0b654f7296c5dd22bf8ebc2f1452e7585bb4fee5b0318d08a7700d59f39      115 main/binary-i386/Release
 2f4b83b3beff8e697aa7aba63b87a3841eda7e121dca7efeeba2fdd6c46d4708 43733274 main/binary-mips64el/Packages
 5d3435e4b966e83eff68bdc0f1390639ee4cf8ca85a0912086118d18fca56895 10720185 main/binary-mips64el/Packages.gz
 2f5114b8774c2ebb9e4bde58f4f61228413faf25c6f0f8cfdfef166d59194d1c  7907404 main/binary-mips64el/Packages.xz
 f3e83d91633067c9cc7c22a7b17331307039cb7a194534c86c45a0ae8b15e159      119 main/binary-mips64el/Release
 94dfcf07165f1f9da1d465a87d0978f2cd267341b0cb100a976db872731b0861 43667386 main/binary-mipsel/Packages
 dc8003ba9043dc725eb21a2d51f70fd0f68a98398e0819083663de884cc73721 10726366 main/binary-mipsel/Packages.gz
 886bc8567cdd318d3380636c313f736e35220acc8be711584ea919d5265e96a8  7906936 main/binary-mipsel/Packages.xz
 56e88cdccc438d85773e9d9dcd4626dc93905cc85c28492cf1115e0f6d6d86c4      117 main/binary-mipsel/Release
 53f4716144d0126ec83ade49820c2737e4097d058c7ec55c26a94401aff90799 44671240 main/binary-ppc64el/Packages
 0d7e6d81bc985f84d71bfa9dc1568b5bacde58766499fb50c9f9615627eb64d9 10884852 main/binary-ppc64el/Packages.gz
 8bd383fa40a08bde86f78b7768a3c8eb8aff0a16f380fe3ba259258db8cd89dd  8031816 main/binary-ppc64el/Packages.xz
 32c55acd12e6699b68c50747b5d72a0d2252a1db5856ab75fea6771c8311ba21      118 main/binary-ppc64el/Release
 1e53bd7f1a45174fdb3db7ecebeaabfbfecfa0a88aaea4a9d060039c99b0580f 43340190 main/binary-s390x/Packages
 07462d6e7a7e6ef042830e993747f9d471ae8dc0ba792c3056811c64d37c0e6d 10686656 main/binary-s390x/Packages.gz
 be641a245bcbd2b2138762c88793df74b04bad687f2c8185137254e9cb6bb229  7877060 main/binary-s390x/Packages.xz
 612cf5c4ef5247bb112bcb8af86780ecfc13514729575fce1087ec12340965d7      116 main/binary-s390x/Release
 4f60d86324cc91f8ac32625dfd1f8750a7f79e866376a34a478d2d3f8033ce84    61160 main/debian-installer/binary-all/Packages
 1e0c3c1d9f21267ec4183fa21ffb26808808678d6393cde03820b5f8c677977c    16449 main/debian-installer/binary-all/Packages.gz
 3831da178354890a18394e5d531c28c77f70c6fcc628e369eb584fbf7ce28812    14676 main/debian-installer/binary-all/Packages.xz
 5fca0b091a4008553328742c4e5509375042ae86fd25e078e5641da80c6e35ed      114 main/debian-installer/binary-all/Release
 8e6eade3d4d6600d25629ef41a6e7d7f1735cb999923c20962ab96c4c60cab8b   274352 main/debian-installer/binary-amd64/Packages
 127cbf365fb6430a108efe73be70b65c93a156c3e9d54a26515fb0637fecf7a0    67349 main/debian-installer/binary-amd64/Packages.gz
 b15c72bd10652b7c5a456b8dbce9ee1002d9ee36b4c8377d5224bf71d7c343e5    56064 main/debian-installer/binary-amd64/Packages.xz
 ab78444b1bbaa56630b4f90edc8982f4fd965ac4db2b5530855b768c1c8fa9f9      116 main/debian-installer/binary-amd64/Release
 42d0cbedcd391dcd0ae974c2feb668676aa33b430b213d23a913e411c817f23f   257349 main/debian-installer/binary-arm64/Packages
 1e7d6c63aeeb7b5923f514df4586dd7c9a23415f318e4d99c03c435fed764ded    64271 main/debian-installer/binary-arm64/Packages.gz
 155a73d0f9cb8c70eb64cf86204fb88a81585d79136dec3399b54571307daf5d    53980 main/debian-installer/binary-arm64/Packages.xz
 fc1fcedbe9926a4b0b8eb49c4ad003eeb5d656f7a447864ebab16f026100f6f7      116 main/debian-installer/binary-arm64/Release
 01175829fcfa8f2d6599c49971251106ace55e9b660a6ab2b6cb84990b615f23   248363 main/debian-installer/binary-armel/Packages
 41e38adbe03f5e12ce7bb71a17a1afa385a19129f3e2c4fe064358e83c41f50f    63792 main/debian-installer/binary-armel/Packages.gz
 a669674d70b74c4f3928ee0824025cd032a2cd681bee9608194da11bd96140ee    53168 main/debian-installer/binary-armel/Packages.xz
 abb6c54c329433e32610e26704ca667256c1ad24cbdef67431ded86b67b9df8d      116 main/debian-installer/binary-armel/Release
 7805822347f4d4a5c174408573f6d212e6f639a8d2587c1358dd1273c1e4bfd1   251788 main/debian-installer/binary-armhf/Packages
 e39dc55b91aecd52890df43e9661536022c68301e6d2d46140f0d883ea0d4097    64864 main/debian-installer/binary-armhf/Packages.gz
 508561858e1d7d9533704014303d875ddecb6c8a9be3a5692e4db28b8673bd0f    53852 main/debian-installer/binary-armhf/Packages.xz
 07c1cebfbbc800619727cfabb5bbd313a65ff1ad3df60fe04b680de8c63846cf      116 main/debian-installer/binary-armhf/Release
 545fe891b7ccfa9058a34a9ca644eec47d4d1e32b8d19731577719914d57b1cf   349445 main/debian-installer/binary-i386/Packages
 b3dcfa8a62aa51c55cb0cd999fe2930828eec945d947c737a4e0251299d031a5    77230 main/debian-installer/binary-i386/Packages.gz
 bb6f1ba125b73e6031b0db1aff6666d674614b2900f829edc00f5422b71a9ba6    64124 main/debian-installer/binary-i386/Packages.xz
 598ab0b654f7296c5dd22bf8ebc2f1452e7585bb4fee5b0318d08a7700d59f39      115 main/debian-installer/binary-i386/Release
 e99d10f54387b1515192c78420b8320f19226950e45628b464419a16cbbe0851   364716 main/debian-installer/binary-mips64el/Packages
 c16ea980c78ef318d090f661bb8a32b013b9aba1e4e03cfc7a1fcdc710b315bb    79498 main/debian-installer/binary-mips64el/Packages.gz
 0fe50a043e08a0c0f92cb774acbaefc95f78d7123efa606770dd02f9fdeff404    66396 main/debian-installer/binary-mips64el/Packages.xz
 f3e83d91633067c9cc7c22a7b17331307039cb7a194534c86c45a0ae8b15e159      119 main/debian-installer/binary-mips64el/Release
 e9b79bdf2204d27512128a1f1d85e8455d94c402be68b815c24f66be4f496e8b   364202 main/debian-installer/binary-mipsel/Packages
 94265e6e880e2c55618fcde79440b3060922932eb14eac1beaa3c7b1c6865d17    79784 main/debian-installer/binary-mipsel/Packages.gz
 803db2a15312c03059f31f2a20cde06935f7a3ca6c3f35e043b3d1881eaed353    66500 main/debian-installer/binary-mipsel/Packages.xz
 56e88cdccc438d85773e9d9dcd4626dc93905cc85c28492cf1115e0f6d6d86c4      117 main/debian-installer/binary-mipsel/Release
 d779769699bad795292351e1d2bf4c294d0df53f43a8e812e607d2ef5d979fc6   256933 main/debian-installer/binary-ppc64el/Packages
 6d2b2b5ac8b21d5dcec79146959b1bc617b65c5fb69a72bde8fe9b494bf03e30    64920 main/debian-installer/binary-ppc64el/Packages.gz
 adf0f93f39ffbdf3efc60e423653d16ca020f9d40d76c51b153462d4c556fac0    53960 main/debian-installer/binary-ppc64el/Packages.xz
 32c55acd12e6699b68c50747b5d72a0d2252a1db5856ab75fea6771c8311ba21      118 main/debian-installer/binary-ppc64el/Release
 08fac5f6592875d7466899b2bab7a44d8eea409b2b05dd8a334f0bd4e7bac807   226275 main/debian-installer/binary-s390x/Packages
 dad6130f7794acf153f2654ef56ce0f51ad202a6652862332025ef08d299b092    60464 main/debian-installer/binary-s390x/Packages.gz
 255a06d1829ff337a371c2e3565ad96ea789703016ce91735b36a9dd6fab1647    50116 main/debian-installer/binary-s390x/Packages.xz
 612cf5c4ef5247bb112bcb8af86780ecfc13514729575fce1087ec12340965d7      116 main/debian-installer/binary-s390x/Release
 99d8d572b0219a7b37addc91ff4e4ff238a33b3452580d4bd2469588a2225cad 18520413 main/dep11/Components-amd64.yml
 9c5522d811abead85a73407f6b56b171207105bb3641e22d76f2146482d4750b  6213469 main/dep11/Components-amd64.yml.gz
 0b517038e27fe4864c35de9459537d91f5d274800a172be69f91e90bb3631589  4048504 main/dep11/Components-amd64.yml.xz
 ed767617ad156481cc8948fb72c2d699d6292bfd2d83fb2f24b2b155612dc539 18436837 main/dep11/Components-arm64.yml
 1732a30dff783f891da2245f955becf3a43be40f0400b722087ba626316e980a  6191092 main/dep11/Components-arm64.yml.gz
 a02d6259b836d37804838b6de8f40568332a9a78cb4bc7668b32208f6062e782  4033216 main/dep11/Components-arm64.yml.xz
 aa3eea13a49b29dba27956d6fb6093817775361e29fef3f751e8e70b7065e54d 17658848 main/dep11/Components-armel.yml
 ca3d41da75c25408834b265c9c95f700a1241189f6bf62270e14b85920f5cdc2  5952269 main/dep11/Components-armel.yml.gz
 5c90b5a79fb5cf11b4e822396183bd3b4d3712e5f8e9363c5fce4a3a6c42a58b  3879744 main/dep11/Components-armel.yml.xz
 9d95db48c33d5671c96a2931458a92b6290e9c3f880c7ec7d7aef2b23a681eb3 18205252 main/dep11/Components-armhf.yml
 55c47f2e4607828ad1d875c1ade2aea6565916e9dce3e043f6de2e85b6cd74c4  6110587 main/dep11/Components-armhf.yml.gz
 20797715d417813ddd77d1bf746b8ea9f6353ad0e8be2e67f1700813d992268d  3983180 main/dep11/Components-armhf.yml.xz
 5579083d9a290f05eeb86967fd664c46464b3bafc00c073887560523a1793a64 18485654 main/dep11/Components-i386.yml
 ac8dd6c8b9e575785646a7d41adc7783956e22bcc757a60c80f225328c769f08  6201776 main/dep11/Components-i386.yml.gz
 589f93188296c83e394c89ccdaae1565436dc203161958e96f3a5cf2797684ca  4041608 main/dep11/Components-i386.yml.xz
 2b028df6a795c2a4b058b0f239745da363ea0f8b9fb8ce1a7955bedf579cc8cc 17819116 main/dep11/Components-mips64el.yml
 0865e497ec87d5d45f84106166bb035610443e87528aacc1a43f13000542a3f5  5977494 main/dep11/Components-mips64el.yml.gz
 46745049532f14f438f41704b442c157ee0f2990baed5d06da8fda3b41501547  3896708 main/dep11/Components-mips64el.yml.xz
 c0e1c64172edc19edcc287b0e617adff28b31354028de4c755cdf1fd077de913 17947079 main/dep11/Components-ppc64el.yml
 ba4eb9c1ab3f03a7fd184e5fc47dce250c083a617d9e2ba49a70c920fd957b29  6023058 main/dep11/Components-ppc64el.yml.gz
 aa34918432eeb8a82d912d86f69d82e84a4bc0eb48056ebe321b83d2757d1052  3925796 main/dep11/Components-ppc64el.yml.xz
 dc222c504c71bbc9ff6b698bf5ef7942e098efff1031861e5eb8670afdd18452 17735785 main/dep11/Components-s390x.yml
 29584e8fd8bc91d9d9099893ae4951601430b1df4f55659e089d34e4525540e5  5976062 main/dep11/Components-s390x.yml.gz
 1f9ca828b916aabab9b41f75950df49f71dc5e8a42f674ff4cb2138f85274314  3894008 main/dep11/Components-s390x.yml.xz
 057f28adb7c2452ab2c810fdfbfce0305ba8143ffe2e24969b2ece077aba7e9f 13048320 main/dep11/icons-128x128.tar
 4f46415e13538a05743752a630c9b8795a9772d0ab4ebe83c9d7e19f0e4bf179 11409337 main/dep11/icons-128x128.tar.gz
 e0c306e3293ecdcb8392faa372b00f1fb979c327c3e4370452acf7713ab885a4  4878336 main/dep11/icons-48x48.tar
 93c4366d8b6ef489bb935434d9a2c56d842978922e941dd4ee716ede2a805494  3477622 main/dep11/icons-48x48.tar.gz
 910ec31c85f12f0edefbb43fa2514b9896d105ce7316272a4c55263af864c238  9378816 main/dep11/icons-64x64.tar
 a94629c3e4fbe9607fb2921e1c906f88343a7cadc484a1087983181ae6df66a3  7315395 main/dep11/icons-64x64.tar.gz
 e061ee16e4478c39875bc3d977fdd5f880a71a3ea97c9f5119ac127a4305579a     6191 main/i18n/Translation-ca
 ed06627194c667d774188bcf0d9b859625ec60d2098238ee3c1cd5e1c147c4f7     2673 main/i18n/Translation-ca.bz2
 857bef6538df7a4e2ae01a6ef40f8a5c9e0512797a769d8813caaa57ca867f29  1205166 main/i18n/Translation-cs
 bdd79636af5f08f4c40bb5266a41e4707b7bdc84d5458451df0255b787c380a6   323247 main/i18n/Translation-cs.bz2
 2c7c6d7013e3d04a62c457525567fac4ac2747ef59f1b2a93cad8c0904c960b9 20240560 main/i18n/Translation-da
 8935ec6ddfeaeb542fe444013ad9fefd6ffd2da2afe818efeb417fb50568b52e  4411163 main/i18n/Translation-da.bz2
 55e94848df1df7d0963f3cb02cfb4171031350c549e4ae64f6aed517ed08ca6d  7801238 main/i18n/Translation-de
 b68fe8718325ebd1e2a8dd30f52b17c003e315f3468f9b7890fe5b1b91c709cd  1717951 main/i18n/Translation-de.bz2
 284169348b8bd4e0de4cc5641eeb05577e80d2bd736452e454976c052cf3cbe2     1347 main/i18n/Translation-de_DE
 481a435ad350105b74c4972859c44f447b7a8b5edea0d42f6dd635792e00a461      830 main/i18n/Translation-de_DE.bz2
 9f3b3bc0da0653f0ac8484024a7f77aeda681474907f3a94b8a0a0933775d14d     6257 main/i18n/Translation-el
 807de361285151534654b83681415016d443e4abd1a7ba36e1e78b4ac337b973     1835 main/i18n/Translation-el.bz2
 87a5cc96d599e93f7cd76ea6f32b27e9742abd8027c9c76c40ad1a091e0d8950 30246698 main/i18n/Translation-en
 4d7cf2aa527bdd9129bd6e5974c41f574de06f1963d9062af0787972b4a76b7c  6240167 main/i18n/Translation-en.bz2
 abccaeb24d409c21b94883b74785053d0f8fad3e94449078ebe92af38861bc5a     2261 main/i18n/Translation-eo
 747ab457a83de3b107e25b9cc5536aea2f19e0fe1f08d5357475acea0d788fae     1196 main/i18n/Translation-eo.bz2
 38345d246390b3845920937338647a70b1a6a93f354615da725fbf426ac3e332  1325929 main/i18n/Translation-es
 d6bd3bb26fb52e553bdaa40a041aa167f8a0c207149ebf626bea65c90ff7e99f   317946 main/i18n/Translation-es.bz2
 80c3ff00f3b37b64e73c85b11eab47fe88901b6f8d9f189de0e95a387e02ebed    10093 main/i18n/Translation-eu
 7ce6c68ef8a577bd215da5f7a12153bee27268b0b6b9503aaf88244b225f20a1     3914 main/i18n/Translation-eu.bz2
 54c5db1926c3309513d37990460a51c586ae6f01bcaaf2732e537ae400b6f5f5   269212 main/i18n/Translation-fi
 a0c315c9c517ac029e5981f14a3c15fa022c7c0e1e86edf123e05027343974d7    75849 main/i18n/Translation-fi.bz2
 bd258bc1f5bbc6694e24f58fe4dfb5f5636afc86a431795b931225e9e336feb3 11857302 main/i18n/Translation-fr
 ef77125783dc8b1125ea85050ba00bfe042e6f38fa1f73613387fe30cae47c5c  2433064 main/i18n/Translation-fr.bz2
 ce1a70b1000909a09166e30d574c717f3d60ba173bb65ad65e768374dc73232d     1427 main/i18n/Translation-gl
 fa1eb924fc1473b81f7790ccd909de1dc274f4f266df8af544261f03e1d21079      824 main/i18n/Translation-gl.bz2
 22e19c218655a9a4d09e9930a66715aeb5d0b02bdc4d147e5816067873e71861    21069 main/i18n/Translation-hr
 04e538e90503a9238d071bba89039e563d4c03ee038c217708a4f8c8672c28d6     4695 main/i18n/Translation-hr.bz2
 a275d9da1b509fc6c1d8307ff33daea14669cec8b8f89bb4c4fdf4d50ff48135    65236 main/i18n/Translation-hu
 94827a9f6e251237fb3b093360f88ba469d2be8d4a7c2c02c84298c94faceaa5    22243 main/i18n/Translation-hu.bz2
 0f4bfaba954ffa37332a34df69c8844b7334cc0b61515e9510513e2c43e140b1     3983 main/i18n/Translation-id
 11aebe26133b1249ebc06ec6d1a8b76f5975b9a3630daf71ecb7e2f6521a2fd2     1780 main/i18n/Translation-id.bz2
 d965461960f14ff1f614bcd0ba757874e098cd460b8ae0e018fb4aba254ce641 24489940 main/i18n/Translation-it
 451a92cd21dc98889f43a39223dc8863284bd1a8e515bc58633bdb7bf96dd37c  4844227 main/i18n/Translation-it.bz2
 1cb8cbfe8b502cc64639b02150e6f805bdeebedae3eb69273146c03ca6c9287c  4511401 main/i18n/Translation-ja
 0c00e0a8cff6fb13bdc4ed3387e3faf4f9db94f3ed4ca8e72d324c0a03d8f018   803966 main/i18n/Translation-ja.bz2
 7238152be74233d91630f7100ef7ff2bb8a95598b5fbc11c21c7afeecfc0fecd    11879 main/i18n/Translation-km
 01577e06c8e41b3a914ae539147af0fcdc7a0f883f50d82b57b263cf62fe1bf8     2371 main/i18n/Translation-km.bz2
 232cb289feae187cf94ad451662d7ce36be8014c40b69e645d19b9534dd586df  2606190 main/i18n/Translation-ko
 894aba3a34a47f3d59deca3bda07f8aa288e9f4ed6ae92422eab3fd9dd370ad5   584643 main/i18n/Translation-ko.bz2
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 main/i18n/Translation-ml
 d3dda84eb03b9738d118eb2be78e246106900493c0ae07819ad60815134a8058       14 main/i18n/Translation-ml.bz2
 16be336bba03786450a43321709eca2fce7fa7b50a135a97da71e16eb5e7d60b     1193 main/i18n/Translation-nb
 fdec5fc00fe2d0e3c7730462f95273492d278eb8a6957c1b437969833366c217      738 main/i18n/Translation-nb.bz2
 ce65092fbb0a09286644912bfaf3a9535921705519e16d07617ad85ec44ccf3a   174332 main/i18n/Translation-nl
 e12b923a6f3f83636a31e6e1b2503d8a213e1e4112586a27700fc17bb48ce564    47973 main/i18n/Translation-nl.bz2
 8999184566c11a42f9a31c810d9252316dc4f52ba738db43e0be2cd760c823a1  2051811 main/i18n/Translation-pl
 17fe48deb79b044bdf5894d0d129823b1d86653b9759f848667a74b563625379   491993 main/i18n/Translation-pl.bz2
 2dbf3c4316bba32571abc589b177be93c8e72885131940c9993d3fb6b8d58cb4  1074959 main/i18n/Translation-pt
 991a66952f6395d7588f38e68e1032f4dcc72da61322a59460c34a24d7713400   272186 main/i18n/Translation-pt.bz2
 5d7ec6fe173a67789c445369b7ebf8709cbc9ce4f3e06a75cf36c562a16580a1  3306707 main/i18n/Translation-pt_BR
 1583cdd6a71e29b6eaea0d29dee9ce903fc8ced1f9f57e5ad4de154938799bd0   802734 main/i18n/Translation-pt_BR.bz2
 c90708ca8975ced4acf4be98a4ac1f5c8092fd826b4d928e35c3650e705553d4     1717 main/i18n/Translation-ro
 35f2449dba7bd93e0aece908f4c4de53cc864a48c8f7aeaa5a64f67384e1bcda      982 main/i18n/Translation-ro.bz2
 f8b907289a1970413a47a3450c59b04e166c08cb387ee3ae4f6c0d2e4774c379  3058931 main/i18n/Translation-ru
 8685feba7a33fef7ad8d7fe5db5f59e837eba69134deb87610742cf564e47258   494782 main/i18n/Translation-ru.bz2
 ee2a1713ba3ccf4aa7ef3ee1b5786874c38ecc15db012bc15c3efbf5ad8facd2  5984088 main/i18n/Translation-sk
 0dfec1c42d581b3fe8f95bbe26f649f45234d419c7e709dc881f1994bfb20974  1304539 main/i18n/Translation-sk.bz2
 5ff9c60997a547f07d212476a8f50b4942f012d7952765c6c1925c52495711d1   323953 main/i18n/Translation-sr
 b4608fc3c0c7f6aefe0f6e5e19d0fbe0d5035333e74044e29358b3e3efa99536    58385 main/i18n/Translation-sr.bz2
 5656d4e913760691e99cd4805e76c8f18c4441fe707a02e621a2a172da756d5b    85612 main/i18n/Translation-sv
 fbad8c083b9985e53a2a82d7e32f26f683bd5b8e2f1bf09a3e0fc3f8f7abf6da    27320 main/i18n/Translation-sv.bz2
 2e50dd5fdf1dd6157c0db51afb4457fcfbd427ebb6d1268aeeea1daf50da78f0    14670 main/i18n/Translation-tr
 401a0f8d754d92c562bafe54aa0cb2dd7686ca015425513b666b50b8c9dc36a7     5362 main/i18n/Translation-tr.bz2
 6c66f49d6c9df7ef28f92aaab2620a2151fa16f74bf96deb3b74987183e43b86  3740343 main/i18n/Translation-uk
 bd760427bda1a65895dd7b3bd6a3e2b2a0ee6b4060ce726ec4b7c02b89a72204   576766 main/i18n/Translation-uk.bz2
 c2207dfa8d62c7e2a31851842dd928739bc147515f69fb7a28db93196dd1a601    21882 main/i18n/Translation-vi
 e3eab47e1acdc01ee2d774dba5b0f9d29c98ff48b25a57d469eeecf60d3035ca     6510 main/i18n/Translation-vi.bz2
 7133134d1b1b6c869b4b700fed9778e93a0b774391402ad3399e9ff46984efff     2007 main/i18n/Translation-zh
 8cbeadbbcec613b8476f8e2aa40b15772909109e10a83317c111fcf7c28d0219     1215 main/i18n/Translation-zh.bz2
 d88628c7a7a16a042234daf91a709daa6d5f9de15406ec78530891354fa25c75   425199 main/i18n/Translation-zh_CN
 1ef87b145198090deb2d037bc16b5b940c0e757a2511f4ff84a7c750720b2723   113621 main/i18n/Translation-zh_CN.bz2
 564fdb3059cffbe78dde61697e77edd7bc94005a358cc4b5dffb436776d1b2b0    39965 main/i18n/Translation-zh_TW
 0a4d5ecccec7069a32b30de129018034b2f6f2b318f1530e1edc239182442cf8    14859 main/i18n/Translation-zh_TW.bz2
 343fe56ad4f39f517c6b504106ce828f6ab57b71fd8fe11ded31b5d217950b9a    58277 main/installer-amd64/20210731+deb11u7+b1/images/MD5SUMS
 3dddfa19f9ca9bd20c0f0249d68427e5a70cabb845c8dc9736f3949c96ec1188    78097 main/installer-amd64/20210731+deb11u7+b1/images/SHA256SUMS
 91e63d03c43f9feaed6c255a510c30c35c547c517f395c2574900b0119fad790    57705 main/installer-amd64/20210731/images/MD5SUMS
 a3a16cc4af2d688613ce8df4d224974629ad3383a1969350c24ea68bfdd5f1e5    77333 main/installer-amd64/20210731/images/SHA256SUMS
 343fe56ad4f39f517c6b504106ce828f6ab57b71fd8fe11ded31b5d217950b9a    58277 main/installer-amd64/current/images/MD5SUMS
 3dddfa19f9ca9bd20c0f0249d68427e5a70cabb845c8dc9736f3949c96ec1188    78097 main/installer-amd64/current/images/SHA256SUMS
 1df7955a3c09498e279431cb6304f4e616cb7ea5a8ee5d4b9db85ba9d2a05bed    69049 main/installer-arm64/20210731+deb11u7+b1/images/MD5SUMS
 fd710c158d06fae3de80d23198806c9101e7e6cc640fad6b366d3f06eed9e91f    94149 main/installer-arm64/20210731+deb11u7+b1/images/SHA256SUMS
 291e81049aa85b147063ec1aa5bec87da60d3196c06c3098de5210c3346837eb    68403 main/installer-arm64/20210731/images/MD5SUMS
 5dfc89487fc8717ab9a9b75cdaaf01a295ab3021cc3310d3fe9dd3e78fc1f666    93279 main/installer-arm64/20210731/images/SHA256SUMS
 1df7955a3c09498e279431cb6304f4e616cb7ea5a8ee5d4b9db85ba9d2a05bed    69049 main/installer-arm64/current/images/MD5SUMS
 fd710c158d06fae3de80d23198806c9101e7e6cc640fad6b366d3f06eed9e91f    94149 main/installer-arm64/current/images/SHA256SUMS
 54528ee7dfb52dc1ce6680b4a8b898d9454936c892012a677747465fa8f506d9    20678 main/installer-armel/20210731+deb11u7+b1/images/MD5SUMS
 86396ff61efdee365e4ab688b91f773409a12d6950f61a7e8671a9b64777458c    28882 main/installer-armel/20210731+deb11u7+b1/images/SHA256SUMS
 ee9f639b7a0304207f23c84f5396284720a6fc6c638ee7be6873944a0f224c95    20182 main/installer-armel/20210731/images/MD5SUMS
 07353d4c378ea579803ed8c1aca3fe6df2cbc89788736c7d01102a7b3ebad859    28194 main/installer-armel/20210731/images/SHA256SUMS
 54528ee7dfb52dc1ce6680b4a8b898d9454936c892012a677747465fa8f506d9    20678 main/installer-armel/current/images/MD5SUMS
 86396ff61efdee365e4ab688b91f773409a12d6950f61a7e8671a9b64777458c    28882 main/installer-armel/current/images/SHA256SUMS
 f899f04724b1fbce7e9a9060e82e1dcb942919914bdc808d120b7e52fb7b38b2    64380 main/installer-armhf/20210731+deb11u7+b1/images/MD5SUMS
 cf5b025aef61b2ea4e0c5f94d36e22e5ed26b01da945f498f9b6cb5156171b1f    92680 main/installer-armhf/20210731+deb11u7+b1/images/SHA256SUMS
 8c1f810a60fc7daf099e608b763cec563f59c82203a07bbf4469a6213a8946eb    64240 main/installer-armhf/20210731/images/MD5SUMS
 67c5b636e3fc02747ca9593e6fc7e906a3ec95d4947740fec81b1e942f0643ae    92476 main/installer-armhf/20210731/images/SHA256SUMS
 f899f04724b1fbce7e9a9060e82e1dcb942919914bdc808d120b7e52fb7b38b2    64380 main/installer-armhf/current/images/MD5SUMS
 cf5b025aef61b2ea4e0c5f94d36e22e5ed26b01da945f498f9b6cb5156171b1f    92680 main/installer-armhf/current/images/SHA256SUMS
 393b9f170f9732a04cee8abf0dc9d0a52272bd577c47d30310dd88c2552db5b7    56840 main/installer-i386/20210731+deb11u7+b1/images/MD5SUMS
 fb5c92b43fcaaa6850fe79473a5fac3c6a27e31b72a52d81297eb283fdbc46d1    76724 main/installer-i386/20210731+deb11u7+b1/images/SHA256SUMS
 96e8acb8eb827ce7032587400fbe848b6f53921c661d52e1b16fd243cb8e57aa    56286 main/installer-i386/20210731/images/MD5SUMS
 bced74c95a3688a9a2a28abb8190cb7efd7e1f6372dc8989e260771752ef571b    75978 main/installer-i386/20210731/images/SHA256SUMS
 393b9f170f9732a04cee8abf0dc9d0a52272bd577c47d30310dd88c2552db5b7    56840 main/installer-i386/current/images/MD5SUMS
 fb5c92b43fcaaa6850fe79473a5fac3c6a27e31b72a52d81297eb283fdbc46d1    76724 main/installer-i386/current/images/SHA256SUMS
 d1eb4b5cef71f7c78971aa99bf86ed4980ebcb8bab8d0e45835731d0ce173969      630 main/installer-mips64el/20210731+deb11u7+b1/images/MD5SUMS
 275fc83d164449c94cfc9c4039f38eb08e123bb11d6f6acc2724441f752a3727     1026 main/installer-mips64el/20210731+deb11u7+b1/images/SHA256SUMS
 af3b55dea76e91f1565bd54bc1af76a6a0bb4991eef9abe281a22d9fd8d54a7b      627 main/installer-mips64el/20210731/images/MD5SUMS
 995cda8278b101eb25849d56f3ef33290fb57a940fa1c6837f19df00ceafaaff     1023 main/installer-mips64el/20210731/images/SHA256SUMS
 d1eb4b5cef71f7c78971aa99bf86ed4980ebcb8bab8d0e45835731d0ce173969      630 main/installer-mips64el/current/images/MD5SUMS
 275fc83d164449c94cfc9c4039f38eb08e123bb11d6f6acc2724441f752a3727     1026 main/installer-mips64el/current/images/SHA256SUMS
 74028a1b5cf4c8a3e8b30fadaa3c4a2237b9032b93a3abfb3d3edb64667cbe61      630 main/installer-mipsel/20210731+deb11u7+b1/images/MD5SUMS
 1dd26a64b20327c1718dec6cf314168dbf68a225b1e68cedb2c8d4f4ee218087     1026 main/installer-mipsel/20210731+deb11u7+b1/images/SHA256SUMS
 ca77bbc823d1bf6999e141cd42c1bb4c18179cbe4a3fbb6da3e40e1055848ed7      627 main/installer-mipsel/20210731/images/MD5SUMS
 28589449e1b3ac9a73bdf6f266edc83e70ebbbca587a228b15b0dbe5e1a634fa     1023 main/installer-mipsel/20210731/images/SHA256SUMS
 74028a1b5cf4c8a3e8b30fadaa3c4a2237b9032b93a3abfb3d3edb64667cbe61      630 main/installer-mipsel/current/images/MD5SUMS
 1dd26a64b20327c1718dec6cf314168dbf68a225b1e68cedb2c8d4f4ee218087     1026 main/installer-mipsel/current/images/SHA256SUMS
 1703a54e2b260ec691ffecd444e7507f03bbefce7cb8341b73ad78ed16ca750c      576 main/installer-ppc64el/20210731+deb11u7+b1/images/MD5SUMS
 c234d16ddedfbb72bffb5cb22b32b981e03b3461f6720c10c7d5b8dc726e912c      972 main/installer-ppc64el/20210731+deb11u7+b1/images/SHA256SUMS
 d162b2da6777c1ea0643921cc1a3dde78ae48cf022711eb98c7e9dd030b89a44      576 main/installer-ppc64el/20210731/images/MD5SUMS
 73e281bce56df3c7512ffa1a1cb13886064759a461621db4acf9b1f71965c676      972 main/installer-ppc64el/20210731/images/SHA256SUMS
 1703a54e2b260ec691ffecd444e7507f03bbefce7cb8341b73ad78ed16ca750c      576 main/installer-ppc64el/current/images/MD5SUMS
 c234d16ddedfbb72bffb5cb22b32b981e03b3461f6720c10c7d5b8dc726e912c      972 main/installer-ppc64el/current/images/SHA256SUMS
 20b3ae961820dbc6df8275c2efa95d4ed34775cd22f9d5dc0d656bd699c9f99d      374 main/installer-s390x/20210731+deb11u7+b1/images/MD5SUMS
 1082cf1f5b94b3c234dea741a0ed81e03cf3f78b0a55affcf58d517bf37fee2d      674 main/installer-s390x/20210731+deb11u7+b1/images/SHA256SUMS
 b2c58a9c5b97a59742a8056e3e9d7f4f22d4d11e51c71d7a0051dc4649a717b9      374 main/installer-s390x/20210731/images/MD5SUMS
 61447263ea7318c444fde199afc718a8498fe67bc0e7116f2e1103cc65ef672b      674 main/installer-s390x/20210731/images/SHA256SUMS
 20b3ae961820dbc6df8275c2efa95d4ed34775cd22f9d5dc0d656bd699c9f99d      374 main/installer-s390x/current/images/MD5SUMS
 1082cf1f5b94b3c234dea741a0ed81e03cf3f78b0a55affcf58d517bf37fee2d      674 main/installer-s390x/current/images/SHA256SUMS
 de9a48c211839c666254f2eba37417143bf6d0db56abfe1d07e4c35609d3f04f      117 main/source/Release
 dced89e82fac92fdc1cb92f99321787f26c8c9b0d72da39ec091dd96234ae3d1 44655922 main/source/Sources
 006a5628b8afa45bf77cc449afa6f98647573b0e98b119a5944e65741094bdeb 11429086 main/source/Sources.gz
 a7e9e21d852dc2b685e9c28e0b06a9a4043220367cec57bd0e7043bd58c1a069  8633788 main/source/Sources.xz
 29cac69ab0fd86e224587eea8e2ed2fb9b1b2e3c936fb1dc7165b8ed8d00528a 17347341 non-free/Contents-all
 3b87590d0360ae141f3688fbafb5fdad35d4dd4b1a239888c911743c4357862d   888157 non-free/Contents-all.gz
 1335601f3e9b7f67c279a4c1619203dd6461fab7c16c29e1d71970a9bd023052  1097448 non-free/Contents-amd64
 df4bb7a18156a7f33c70f36d1709ae7ba48716d96ec1b940bd3bbb47ba432de7    79655 non-free/Contents-amd64.gz
 6f4902fb02e2f1092d88d8101024129a4af0fd245e75803b0b93b0475feef42e   499970 non-free/Contents-arm64
 c2715365833d3d97cb90e1fbf44df3c6835b323ef1e5dfd660b1cce148cf62e9    37376 non-free/Contents-arm64.gz
 386c53a056d4aedb9d48a332056c51a302e1b043480cc24fc9ea9053ff8fe002    95417 non-free/Contents-armel
 5fc23867def6ff06cf0c72080f1862ea142b20d25ca0a1e8e8b9c83ca3b82519     9298 non-free/Contents-armel.gz
 e2fe020c8c47e80e483acfe05462706e063c6932f9bb857e54d59383d415a44f   146124 non-free/Contents-armhf
 ac08720d4fc801273e1a8b2e0d7d7f80d07220f09089011a577ba47f12172ebb    13502 non-free/Contents-armhf.gz
 6468671814b9daa924278df786f198b0b34d8f525b7a9c0ff8cdd6db3dbc661a   343198 non-free/Contents-i386
 d85698eb7c99ba6fb568afcb497365ebbc59421c89dea8b6186b661e8c19fd12    29072 non-free/Contents-i386.gz
 6bdcba453cc1369f93e7157d5d7f9c67198edc62e4e194b079b0572186a95b34    91215 non-free/Contents-mips64el
 0986d6fc85dcf209edbf39b1ee2c84b370ea02dfe810ac33cd9cc89a2f3a2a18     8686 non-free/Contents-mips64el.gz
 5102cb8d1b74daa60d4d6444e563dbdaf73ffaa2b7ce71a304987ff575da7f4e    92244 non-free/Contents-mipsel
 53bd140b538ffea9c0bd8b6b073b3ef613ec1d452bb1bad5a5f86a029f11e3dc     9026 non-free/Contents-mipsel.gz
 03756e78d0f8004d0cdd2e4fe2238a6c851f94c42b0ca7064629b55a4ca494d6   716110 non-free/Contents-ppc64el
 e3321e93f91e779a59e4ca94c61d1eedd13d02a847824c459419c29203ca6959    49881 non-free/Contents-ppc64el.gz
 6d2b11e017bf520a64870b3ceecfac7944f991928095bd2715429987a342c37e    74537 non-free/Contents-s390x
 228df45a42a42dd62cc747f2abe99dccd25c384aa423c17896a6196955cd9c12     7407 non-free/Contents-s390x.gz
 1d53da6b88f2d7252351b65dafa6ec6453ef19326ce8490ea48d865557f30c52 10803369 non-free/Contents-source
 de64ec721f3e9589c6f7efc4f23c2713a40afcce15e033eddbfa0674dc81ae4c  1063443 non-free/Contents-source.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-all
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-all.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-amd64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-amd64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-arm64
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-arm64.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-armel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-armel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-armhf
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-armhf.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-i386
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-i386.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-mips64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-mips64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-mipsel
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-mipsel.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-ppc64el
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-ppc64el.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/Contents-udeb-s390x
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/Contents-udeb-s390x.gz
 68ddf090986f56743010180da8d3e05a41bd5185e0047a98c97adb038cc5fc4b   189021 non-free/binary-all/Packages
 569cc71a40dffea02aa6cf8b516370e08587ec71d34558cf6f1fe688c9629468    50928 non-free/binary-all/Packages.gz
 b9d8d7fb507a77a6222770fbe09815bc0cae22af92d0c16538d53b4576af6784    42996 non-free/binary-all/Packages.xz
 3f87c1d57bbb196bc7d6a2bec129e82e4f4296b3743a105f53104fa82e3d6f07      118 non-free/binary-all/Release
 41eae996375149a4854537915bf8162c5a22c77f3fa88c6466ce16d5f1b7d1d3   545576 non-free/binary-amd64/Packages
 6bebe66d1f22f6dc11b186fbd34d029402a0848057dfa5a8afa193cad65bc205   122225 non-free/binary-amd64/Packages.gz
 a108aa5d825e98f766b4e20d261c21c1fafd9340547006244aa6fbb51b77d837    97772 non-free/binary-amd64/Packages.xz
 9a0edbc466a3e91231c1ba756996d5fb598d3b14166a2a2b72899d4672f53a82      120 non-free/binary-amd64/Release
 514482332f1c35020f2ba2ac2cff8e956dc5ba0a9a5533251321cf3e2e50ff89   381335 non-free/binary-arm64/Packages
 c2b9e19b24c3c9f859da6a28fd8cf27bc1b698111d4bd48728a8b8cb093085b1    88201 non-free/binary-arm64/Packages.gz
 2ab2f8d500ce30e6b4e70fa5ef5678a3eef0743deaec93a24011949bc5911f75    72980 non-free/binary-arm64/Packages.xz
 76a1c234c80cbabd279f721e53350404c3cffb523962e44161ded825f87c673c      120 non-free/binary-arm64/Release
 f5738f5a5d9f4391ba0719b7bb175892d93561b688137917a4cdc75537ca70e5   227933 non-free/binary-armel/Packages
 89cb801437910d9b6076d9caf85f2144b224cb1eff7dfbd014219242df514b82    61822 non-free/binary-armel/Packages.gz
 bf2bfec078bdf2dcd2d0d411109257f3ec2d652087399062023d2fcce2e43710    51800 non-free/binary-armel/Packages.xz
 7148bdadd1b6755cc63ffebb30bb3f228e3d6d2565e18ae6641eb62cbc802fa1      120 non-free/binary-armel/Release
 4a9f94f9f510ff6c829677b8dd08ed0c5ff7b33f2118f152d2a4e6b410f8425a   259156 non-free/binary-armhf/Packages
 d7ae0acddc9f6a9acff311a662f78729a610fec44101cd8275fdbddebce7b5d4    67317 non-free/binary-armhf/Packages.gz
 21f37dc3d988493e921f40cd37cc6ef2391b2d7cccf5c83fbf1b037602c0e521    56272 non-free/binary-armhf/Packages.xz
 404c43c7b78d9a5b45b1d0c1851c58ac77a4b4ffe83c81d5c184b114c7c65804      120 non-free/binary-armhf/Release
 54c7fe6dbb5eba9498c1726c1e2119d86697ef32300d3bab99048f1b4141c482   422388 non-free/binary-i386/Packages
 54d73d03945551ef08f0c0b74828b3d78d2747a5f26c3a5d7d7fc446a79f383b    96319 non-free/binary-i386/Packages.gz
 3f0a14b592ba6bf04c31da2ccbbe82bf058d62e341c1777c02f3fd5c00aab76f    79344 non-free/binary-i386/Packages.xz
 fda2cc9eaf856a91a54c1c893a273d148234734ffea5e1ae811d3404c07700b8      119 non-free/binary-i386/Release
 f7e9a5d9f19cc5b819efa1aac30c9d833ed9e41dfdce9abf2bc48d0467abae1a   225506 non-free/binary-mips64el/Packages
 2d01bd458989434fd6555cdc4d4f9dc554881de09ced2db213fc26395f4108c8    61024 non-free/binary-mips64el/Packages.gz
 ed53056d18b6b8589fbbebffd26f8fbda708f71870e1bbffd4a4cfc7249283b2    51124 non-free/binary-mips64el/Packages.xz
 19a2da1050283b31ebd2f6664572c326fe39fa70de30821b9a5410e5e5ae0daa      123 non-free/binary-mips64el/Release
 c690e75e4633fad47565d5afcef96622ec6e02b2fa824e5c0508f1119044c906   226162 non-free/binary-mipsel/Packages
 fd05e8f63760b2163ba4b40cdf200a9b113edfbf81d5a2a318a2b5605812891d    61277 non-free/binary-mipsel/Packages.gz
 87cb9361adbac3f2604906109b21c6b685fda9caf3525395dd4ee057d7c4e43d    51364 non-free/binary-mipsel/Packages.xz
 7d90fbb38122b89666a80ad2665d91fc0eac09bab9f4f7603cc4547504abae06      121 non-free/binary-mipsel/Release
 74efb451a4beb4d707ceac0597842d515b78b7d9effb56a06663fb7428ef129e   381597 non-free/binary-ppc64el/Packages
 c4b451037905b8277fe0a2c0699c3e4ab0de2eb69559c19ac89361440f0439d5    86900 non-free/binary-ppc64el/Packages.gz
 7bc21cd6ac30fce563e47909e7ec989071941134e89b2d895100059749cf3a47    71812 non-free/binary-ppc64el/Packages.xz
 c83ec7a841e5fc039ecef935b1b67f91cebad518a361463db2f804fcb32aaf91      122 non-free/binary-ppc64el/Release
 79ebd2f1278b5db689359d517f88af2ae9acd8d493bf791e5cb5f73b9c81479d   220570 non-free/binary-s390x/Packages
 f7240f44940160f2d9b7cb553f6f47713186ebba6646c18a093e61bc4088e720    59856 non-free/binary-s390x/Packages.gz
 4a1d593c1cd1adb67b9ab6bd5c2558536c284486eb714f89b9ce09229bbb1eef    50216 non-free/binary-s390x/Packages.xz
 e51de0ad0c2a44d2a9054242a462481f42bf24e4da5f58fd0ef35993dd35693c      120 non-free/binary-s390x/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-all/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-all/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-all/Packages.xz
 3f87c1d57bbb196bc7d6a2bec129e82e4f4296b3743a105f53104fa82e3d6f07      118 non-free/debian-installer/binary-all/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-amd64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-amd64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-amd64/Packages.xz
 9a0edbc466a3e91231c1ba756996d5fb598d3b14166a2a2b72899d4672f53a82      120 non-free/debian-installer/binary-amd64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-arm64/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-arm64/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-arm64/Packages.xz
 76a1c234c80cbabd279f721e53350404c3cffb523962e44161ded825f87c673c      120 non-free/debian-installer/binary-arm64/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-armel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-armel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-armel/Packages.xz
 7148bdadd1b6755cc63ffebb30bb3f228e3d6d2565e18ae6641eb62cbc802fa1      120 non-free/debian-installer/binary-armel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-armhf/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-armhf/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-armhf/Packages.xz
 404c43c7b78d9a5b45b1d0c1851c58ac77a4b4ffe83c81d5c184b114c7c65804      120 non-free/debian-installer/binary-armhf/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-i386/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-i386/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-i386/Packages.xz
 fda2cc9eaf856a91a54c1c893a273d148234734ffea5e1ae811d3404c07700b8      119 non-free/debian-installer/binary-i386/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-mips64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-mips64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-mips64el/Packages.xz
 19a2da1050283b31ebd2f6664572c326fe39fa70de30821b9a5410e5e5ae0daa      123 non-free/debian-installer/binary-mips64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-mipsel/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-mipsel/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-mipsel/Packages.xz
 7d90fbb38122b89666a80ad2665d91fc0eac09bab9f4f7603cc4547504abae06      121 non-free/debian-installer/binary-mipsel/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-ppc64el/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-ppc64el/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-ppc64el/Packages.xz
 c83ec7a841e5fc039ecef935b1b67f91cebad518a361463db2f804fcb32aaf91      122 non-free/debian-installer/binary-ppc64el/Release
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/debian-installer/binary-s390x/Packages
 f61f27bd17de546264aa58f40f3aafaac7021e0ef69c17f6b1b4cd7664a037ec       20 non-free/debian-installer/binary-s390x/Packages.gz
 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275       32 non-free/debian-installer/binary-s390x/Packages.xz
 e51de0ad0c2a44d2a9054242a462481f42bf24e4da5f58fd0ef35993dd35693c      120 non-free/debian-installer/binary-s390x/Release
 e13d055f233a81a77666f0ff8dd9d748917b2829740756e1dc2b8a350309bcb0   278293 non-free/dep11/Components-amd64.yml
 f51b1a07cd72a36b2a9f36742ab26819a7808aa7765cbf3e2ff4abe6be66b50c    29634 non-free/dep11/Components-amd64.yml.gz
 e113163e116c137577fc9d3a4f7c95e0934ddbae7bdae5e083aaa1ce095435b6    17904 non-free/dep11/Components-amd64.yml.xz
 6177cb908c067306c11bd8728a5b65a205d999be63930c079e3ff4250a24ce8e   271451 non-free/dep11/Components-arm64.yml
 1b6107a1fa771a8fff50e0b182362fd679dc01f58f7a1f3fe9fe0183daf3be0d    27686 non-free/dep11/Components-arm64.yml.gz
 7ff5eda9a37e07b9bcfa479c89863d7b2b1aafbedbe4b37ea6c32a16f2eaa241    16392 non-free/dep11/Components-arm64.yml.xz
 f54eccd2dbf23fa45cab9e9e7abfafeb667397ea70b6197a3653e8499ffea8bf   271451 non-free/dep11/Components-armel.yml
 5581d7f4c159a5cbd33927294f7fc9918e7deaf04b313001965c83412b6a81f7    27606 non-free/dep11/Components-armel.yml.gz
 0830d150400c82255a52a74f6af9f1a11007bf4b92fc814513f9e13cfac0b22c    16448 non-free/dep11/Components-armel.yml.xz
 15d1524c660c8fb1ee911775a9b59cebbc66843eb97cc0a15a361009f153e6ff   271451 non-free/dep11/Components-armhf.yml
 3fa04d7715c8955987742dc376d10327a975f9583cf656da055d13895e460a67    27691 non-free/dep11/Components-armhf.yml.gz
 bbf5a05de96a53c0e10af6019cb7b053b83b0f5def488cde4d8359475adb08da    16364 non-free/dep11/Components-armhf.yml.xz
 716cec6e00d8303375812c8c9be7cbfa5fc858fdb3d9af3f0c72a696d8f7cb2d   280613 non-free/dep11/Components-i386.yml
 40f189b3b3a74bc85652829d0c67b21aad7e60ce389f26fe1959db1e1e8ec48c    31098 non-free/dep11/Components-i386.yml.gz
 18507e0a03c74ed39b9bec853eb9216b458f2fe2b7535c2622c126b9cd35301e    19156 non-free/dep11/Components-i386.yml.xz
 d82d6fadb06b6a1f0d36c155b70a02eb2281838aee3ce1b9bf51b7ae06136721   271451 non-free/dep11/Components-mips64el.yml
 25d788e157070218396bafba65ff087551830ba0d0ba3e3cec5342bb150aec57    27765 non-free/dep11/Components-mips64el.yml.gz
 2d0aa3979fd6093dc6de8ba902166a985235c8c4926e07cab7aa2a9b4ad0c11d    16380 non-free/dep11/Components-mips64el.yml.xz
 c55445f6f87fd566212bb018f9fae1a4eb43c1a66fe1b0e198b1c7d7e500b009   271451 non-free/dep11/Components-ppc64el.yml
 f525af23f1a1eb26ee786c36e2afd4aa5e4102b646f33f8c6788aee395b752bf    27592 non-free/dep11/Components-ppc64el.yml.gz
 0ee03164cca5098ec7c6f98a469818b40b61da7846451cc223d0b9e01585c57c    16576 non-free/dep11/Components-ppc64el.yml.xz
 359af9af71c00d90265395225b75313966435729cf1f6cfb1085fe1721b01e72   271451 non-free/dep11/Components-s390x.yml
 47ef508dff3dfdf17ceeed229d98a2e3992c1a26f28eb328a2d1958d2ddfe070    27558 non-free/dep11/Components-s390x.yml.gz
 181db8b5130910114256e8809ff9a1637efac55b1f33d1f516983521b8d51e7b    16356 non-free/dep11/Components-s390x.yml.xz
 601045de5331d63b7ef2a24f8f74a7452d7be785f94ae6c46002c5dc2608188f     8192 non-free/dep11/icons-128x128.tar
 4fb59feb5d5afe99980ea36c3d7c14577a4b5f11705e7d16524767708666ed54     2394 non-free/dep11/icons-128x128.tar.gz
 977a5470a45ec30f5e230361a446f4692f9cf9bc2abccf6eabac2df0291f1ee4     4096 non-free/dep11/icons-48x48.tar
 07a401f7b03554c2d8ab32dea5885c43b7da7badeea0569b9ce5c9dbbb7cf66f      741 non-free/dep11/icons-48x48.tar.gz
 159551b3012db94a70261cb8f88619a6bb148318da051479ade6df7211c41a34    36864 non-free/dep11/icons-64x64.tar
 872b7437de6fb938db8b26d9de9a3113bc722cd6ed682973151722e2b7a190be    27667 non-free/dep11/icons-64x64.tar.gz
 db924f2bd81a5875019d05bea92accc667c5a99099512ee11862db412c21d7fb   572893 non-free/i18n/Translation-en
 91ff4a231eff217916da9113aa017d4090fe442fa54f1edf21af3811e0bb255a    92419 non-free/i18n/Translation-en.bz2
 6372d37a918ae4dc1be5a748e9e02e57573e765e14a3c8aa0f37208b223555cc      121 non-free/source/Release
 2bd47d8b576397abf753f06eb5bec85b2036e84b80b8d8646a0e784380d0d53e   360307 non-free/source/Sources
 c9d5108699279e6cb2946d907c13655ebe8b6fce12986a4ba8b0ece0257977c1    98323 non-free/source/Sources.gz
 3f3f09477a76bf44bbd93e7efc74f55783f0841c6692d6188b91e8f58a0c7999    81280 non-free/source/Sources.xz
";
        let canonical = signed.canonicalize(Some(&keyring))?;
        assert_eq!(canonical.len(), 2);
        assert_eq!(
            canonical,
            &[
                (
                    "A7236886F3CCCAAD148A27F80E98404D386FA1D9".parse().ok(),
                    Signed {
                        content: BString::from(content.to_vec()),
                        signature: vec![
                            194, 193, 115, 4, 1, 1, 8, 0, 29, 22, 33, 4, 167, 35, 104, 134, 243,
                            204, 202, 173, 20, 138, 39, 248, 14, 152, 64, 77, 56, 111, 161, 217, 5,
                            2, 99, 157, 150, 185, 0, 10, 9, 16, 14, 152, 64, 77, 56, 111, 161, 217,
                            22, 120, 16, 0, 152, 109, 183, 65, 171, 109, 248, 107, 68, 49, 17, 233,
                            28, 138, 224, 159, 187, 176, 114, 109, 202, 60, 217, 208, 70, 213, 217,
                            80, 65, 216, 222, 122, 147, 134, 45, 212, 199, 78, 128, 115, 116, 166,
                            145, 215, 212, 54, 52, 92, 121, 28, 51, 35, 237, 65, 53, 64, 109, 167,
                            2, 26, 42, 168, 2, 221, 189, 245, 71, 165, 30, 229, 99, 250, 157, 246,
                            80, 159, 137, 4, 45, 225, 161, 247, 62, 215, 137, 184, 138, 198, 236,
                            139, 205, 89, 33, 215, 3, 196, 232, 235, 234, 16, 134, 173, 205, 254,
                            162, 85, 137, 230, 124, 85, 162, 151, 241, 109, 78, 101, 47, 8, 120,
                            234, 2, 191, 214, 63, 141, 76, 137, 109, 85, 24, 130, 119, 93, 232,
                            186, 96, 246, 39, 156, 148, 52, 92, 232, 98, 59, 117, 84, 125, 101, 4,
                            208, 34, 42, 191, 88, 199, 213, 61, 160, 55, 166, 124, 223, 255, 63,
                            105, 246, 150, 92, 108, 31, 248, 127, 40, 173, 144, 34, 79, 81, 103,
                            33, 164, 206, 139, 84, 229, 19, 103, 223, 38, 253, 40, 201, 194, 213,
                            249, 3, 139, 39, 40, 168, 62, 191, 36, 50, 247, 154, 238, 229, 122, 20,
                            175, 158, 65, 209, 22, 94, 63, 50, 46, 253, 22, 27, 95, 77, 18, 162,
                            234, 179, 201, 127, 34, 233, 185, 150, 10, 5, 159, 124, 117, 67, 159,
                            4, 187, 121, 234, 43, 166, 63, 22, 195, 183, 211, 213, 232, 207, 129,
                            11, 52, 174, 113, 70, 11, 247, 48, 210, 113, 238, 7, 75, 10, 75, 191,
                            40, 223, 221, 162, 52, 95, 185, 42, 235, 218, 178, 66, 89, 48, 21, 143,
                            66, 170, 35, 124, 238, 178, 105, 169, 136, 80, 235, 136, 214, 48, 137,
                            117, 61, 74, 157, 139, 115, 204, 5, 142, 17, 61, 28, 119, 151, 212,
                            204, 125, 244, 51, 108, 24, 249, 31, 52, 119, 66, 32, 48, 188, 179, 50,
                            37, 140, 145, 67, 240, 39, 231, 110, 7, 78, 106, 26, 100, 138, 10, 211,
                            132, 101, 249, 132, 63, 71, 1, 13, 93, 136, 109, 80, 187, 227, 110,
                            196, 26, 23, 191, 111, 145, 48, 15, 204, 80, 12, 226, 10, 203, 5, 193,
                            76, 105, 252, 76, 64, 67, 105, 133, 9, 136, 164, 42, 122, 151, 111, 2,
                            79, 97, 27, 16, 38, 102, 16, 83, 11, 183, 162, 191, 71, 151, 205, 216,
                            135, 199, 250, 68, 39, 109, 145, 53, 81, 210, 199, 87, 103, 17, 246,
                            236, 33, 202, 13, 148, 100, 158, 16, 130, 32, 157, 224, 89, 242, 97,
                            144, 64, 170, 149, 242, 183, 93, 142, 222, 141, 54, 187, 151, 244, 68,
                            80, 69, 215, 129, 154, 170, 232, 183, 210, 57, 203, 48, 78, 87, 34,
                            231, 199, 150, 47, 72, 164, 71, 165, 88, 232, 128, 214, 140, 78, 71,
                            244, 73, 64, 59, 154, 15, 101, 12, 243, 144, 48, 45, 145, 182, 208,
                            204, 203, 81, 7, 197, 16, 90, 145
                        ],
                    }
                ),
                (
                    "A4285295FC7B1A81600062A9605C66F00D6C9793".parse().ok(),
                    Signed {
                        content: BString::from(content.to_vec()),
                        signature: vec![
                            194, 193, 148, 4, 1, 1, 8, 0, 62, 22, 33, 4, 164, 40, 82, 149, 252,
                            123, 26, 129, 96, 0, 98, 169, 96, 92, 102, 240, 13, 108, 151, 147, 5,
                            2, 99, 157, 151, 212, 32, 28, 100, 101, 98, 105, 97, 110, 45, 114, 101,
                            108, 101, 97, 115, 101, 64, 108, 105, 115, 116, 115, 46, 100, 101, 98,
                            105, 97, 110, 46, 111, 114, 103, 0, 10, 9, 16, 96, 92, 102, 240, 13,
                            108, 151, 147, 195, 169, 15, 254, 46, 140, 202, 93, 155, 234, 96, 138,
                            35, 33, 103, 131, 69, 42, 252, 36, 117, 116, 27, 242, 103, 77, 57, 217,
                            111, 218, 56, 236, 91, 19, 90, 109, 192, 3, 222, 139, 48, 139, 34, 74,
                            27, 164, 171, 41, 60, 204, 141, 188, 231, 27, 40, 154, 131, 117, 38,
                            40, 58, 122, 152, 57, 173, 172, 130, 221, 165, 91, 138, 23, 120, 128,
                            135, 11, 116, 175, 78, 40, 117, 71, 142, 52, 102, 128, 215, 157, 225,
                            218, 110, 101, 188, 188, 227, 73, 116, 123, 38, 230, 2, 117, 227, 58,
                            26, 160, 174, 137, 16, 110, 37, 95, 37, 139, 57, 205, 14, 177, 183,
                            135, 95, 157, 124, 208, 19, 8, 245, 255, 255, 113, 89, 220, 95, 160,
                            117, 135, 127, 82, 126, 239, 83, 113, 80, 221, 65, 213, 154, 95, 207,
                            138, 216, 253, 255, 152, 208, 127, 42, 152, 123, 114, 186, 238, 189,
                            131, 58, 97, 34, 78, 88, 186, 90, 28, 80, 152, 155, 193, 248, 30, 86,
                            180, 88, 40, 22, 216, 15, 91, 120, 101, 123, 197, 3, 241, 118, 227,
                            155, 121, 121, 207, 167, 220, 116, 207, 201, 2, 4, 43, 41, 132, 155, 3,
                            133, 136, 74, 42, 200, 90, 81, 226, 116, 234, 237, 202, 111, 80, 188,
                            241, 231, 124, 171, 30, 152, 156, 239, 215, 54, 58, 120, 114, 244, 16,
                            184, 166, 204, 13, 121, 37, 218, 228, 253, 173, 254, 152, 239, 214,
                            117, 94, 113, 141, 158, 96, 192, 213, 120, 1, 185, 15, 240, 5, 104,
                            149, 254, 44, 46, 202, 150, 47, 92, 47, 51, 150, 241, 126, 179, 228,
                            167, 32, 70, 38, 117, 156, 139, 98, 121, 34, 179, 158, 240, 0, 156,
                            128, 166, 36, 111, 126, 115, 65, 235, 75, 126, 248, 16, 43, 150, 173,
                            162, 177, 86, 97, 169, 244, 188, 35, 2, 5, 45, 221, 47, 243, 182, 212,
                            220, 179, 146, 73, 172, 146, 146, 112, 167, 242, 48, 155, 244, 109, 62,
                            162, 17, 206, 105, 205, 93, 81, 70, 235, 79, 160, 191, 51, 124, 30,
                            168, 60, 92, 9, 245, 57, 232, 112, 27, 177, 124, 16, 42, 204, 51, 21,
                            207, 95, 86, 5, 74, 70, 15, 85, 204, 186, 78, 43, 214, 184, 52, 61,
                            142, 38, 6, 235, 194, 254, 120, 168, 12, 250, 115, 173, 19, 79, 197,
                            93, 85, 138, 176, 79, 166, 18, 194, 221, 232, 235, 218, 127, 198, 198,
                            148, 182, 208, 29, 151, 0, 221, 121, 192, 44, 147, 119, 74, 27, 68,
                            234, 142, 148, 216, 64, 75, 131, 208, 233, 250, 129, 179, 116, 70, 65,
                            130, 145, 85, 89, 53, 102, 224, 123, 145, 194, 190, 158, 85, 174, 151,
                            66, 229, 145, 34, 9, 213, 192, 12, 88, 34, 82, 15, 175, 129, 184, 245,
                            203, 85, 90, 148, 245, 63, 81, 68, 8, 87, 11, 23, 185, 94, 96, 138,
                            222, 24, 111, 222, 163, 169, 28, 69, 137, 117, 8, 32, 96, 22, 17, 124,
                            163
                        ],
                    }
                )
            ]
        );

        Ok(())
    }

    #[test]
    fn test_dash_escape_and_binary_safety() -> Result<()> {
        let mut buf = vec![];
        for x in 0..=255 {
            buf.push(x);
            buf.push(b'\n');
        }

        let signed = Signed {
            content: buf.into(),
            signature: vec![1],
        };

        let txt = signed.to_clear_signed()?;
        assert_eq!(
            txt,
            b"-----BEGIN PGP SIGNED MESSAGE-----

\x00\n\x01\n\x02\n\x03\n\x04\n\x05\n\x06\n\x07\n\x08\n\x09\n\x0a\n\x0b\n\x0c\n\x0d\n\x0e\n\x0f
\x10\n\x11\n\x12\n\x13\n\x14\n\x15\n\x16\n\x17\n\x18\n\x19\n\x1a\n\x1b\n\x1c\n\x1d\n\x1e\n\x1f
\x20\n\x21\n\x22\n\x23\n\x24\n\x25\n\x26\n\x27\n\x28\n\x29\n\x2a\n\x2b\n\x2c\n\x2d \x2d\n\x2e\n\x2f
\x30\n\x31\n\x32\n\x33\n\x34\n\x35\n\x36\n\x37\n\x38\n\x39\n\x3a\n\x3b\n\x3c\n\x3d\n\x3e\n\x3f
\x40\n\x41\n\x42\n\x43\n\x44\n\x45\n\x46\n\x47\n\x48\n\x49\n\x4a\n\x4b\n\x4c\n\x4d\n\x4e\n\x4f
\x50\n\x51\n\x52\n\x53\n\x54\n\x55\n\x56\n\x57\n\x58\n\x59\n\x5a\n\x5b\n\x5c\n\x5d\n\x5e\n\x5f
\x60\n\x61\n\x62\n\x63\n\x64\n\x65\n\x66\n\x67\n\x68\n\x69\n\x6a\n\x6b\n\x6c\n\x6d\n\x6e\n\x6f
\x70\n\x71\n\x72\n\x73\n\x74\n\x75\n\x76\n\x77\n\x78\n\x79\n\x7a\n\x7b\n\x7c\n\x7d\n\x7e\n\x7f
\x80\n\x81\n\x82\n\x83\n\x84\n\x85\n\x86\n\x87\n\x88\n\x89\n\x8a\n\x8b\n\x8c\n\x8d\n\x8e\n\x8f
\x90\n\x91\n\x92\n\x93\n\x94\n\x95\n\x96\n\x97\n\x98\n\x99\n\x9a\n\x9b\n\x9c\n\x9d\n\x9e\n\x9f
\xa0\n\xa1\n\xa2\n\xa3\n\xa4\n\xa5\n\xa6\n\xa7\n\xa8\n\xa9\n\xaa\n\xab\n\xac\n\xad\n\xae\n\xaf
\xb0\n\xb1\n\xb2\n\xb3\n\xb4\n\xb5\n\xb6\n\xb7\n\xb8\n\xb9\n\xba\n\xbb\n\xbc\n\xbd\n\xbe\n\xbf
\xc0\n\xc1\n\xc2\n\xc3\n\xc4\n\xc5\n\xc6\n\xc7\n\xc8\n\xc9\n\xca\n\xcb\n\xcc\n\xcd\n\xce\n\xcf
\xd0\n\xd1\n\xd2\n\xd3\n\xd4\n\xd5\n\xd6\n\xd7\n\xd8\n\xd9\n\xda\n\xdb\n\xdc\n\xdd\n\xde\n\xdf
\xe0\n\xe1\n\xe2\n\xe3\n\xe4\n\xe5\n\xe6\n\xe7\n\xe8\n\xe9\n\xea\n\xeb\n\xec\n\xed\n\xee\n\xef
\xf0\n\xf1\n\xf2\n\xf3\n\xf4\n\xf5\n\xf6\n\xf7\n\xf8\n\xf9\n\xfa\n\xfb\n\xfc\n\xfd\n\xfe\n\xff
-----BEGIN PGP SIGNATURE-----

AQ==
=5yUo
-----END PGP SIGNATURE-----
"
        );

        let (signed2, _) = Signed::from_bytes(&txt)?;
        assert_eq!(signed, signed2);

        Ok(())
    }

    #[test]
    fn test_release_no_final_newline() -> Result<()> {
        let content = b"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Wed, 03 Jul 2024 04:25:50 +0000
Architectures: amd64
Components: main
Description: Generated by update-apt script
MD5Sum:
 367c2064db4d7381ad9c3ebaba5f0900 309659 main/binary-amd64/Packages
 2555166c9f8c3fcf263bed1780d3214c 64652 main/binary-amd64/Packages.gz
 fc7c26c533cff1978147c24aa468000c 57201 main/binary-amd64/Packages.bz2
 b342b94b4c37c2c3d7e8ef1d39dac67a 58444 main/binary-amd64/Packages.xz
 db8aee13877134f794b225cfb7693351 25076 main/Contents-amd64
 3b5112b5a0da0fc3e178be1b393ad7b0 2039 main/Contents-amd64.gz
 465d036058c655a15adaef094f9286bb 1749 main/Contents-amd64.bz2
 7946f3339f79d17faddcaa0203b0f97e 1904 main/Contents-amd64.xz
 d8c35b55bc8e48e267b9ccdaf383976d 85 main/binary-amd64/Release
 2e9782caa73a260c91ba9bb28a7fb716 84 main/binary-amd64/Release.gz
 564810f1411d179c193cc9f28f78c939 101 main/binary-amd64/Release.bz2
 c7ddb24e1d0b64ca584392d71403b3cb 128 main/binary-amd64/Release.xz
SHA1:
 61c7f4e2f521983011f7bfbf487710c2437df3a0 309659 main/binary-amd64/Packages
 182b735c97dc4d73a98c736f5a87010a19b69b21 64652 main/binary-amd64/Packages.gz
 2b315a75313e08a7147443ecaec2319c58a6e08e 57201 main/binary-amd64/Packages.bz2
 fc796ff95f712a82fce57fcacf7906d6f215d075 58444 main/binary-amd64/Packages.xz
 e19b50fedca995916d7643083134cc7b66ea72c0 25076 main/Contents-amd64
 e6f19033bae7266e50dfcb3725de8ed347e88b49 2039 main/Contents-amd64.gz
 b6de2e9e9445e26ce72f79ce00d86f94b16b07be 1749 main/Contents-amd64.bz2
 b58c520d24b6af04a95fc12f560cd05c6864c17c 1904 main/Contents-amd64.xz
 992cb9cd8a0af2d9ad81d2b45342656d41157202 85 main/binary-amd64/Release
 32230bb251530e6563c378abd4bbf187af5aa904 84 main/binary-amd64/Release.gz
 9a096aed53faad9054f79670507cd3da197801a7 101 main/binary-amd64/Release.bz2
 ba7c389834035e903744b153a1c54e2dc5966b01 128 main/binary-amd64/Release.xz
SHA256:
 88730d9436f17ed233d1b92d5f5d9f53b4144ffac2e83bb91f8864c0b55650c0 309659 main/binary-amd64/Packages
 d8704f58be01ed834143c678d43f1be22b5b768acb747d7aed8f17c9e5eb859e 64652 main/binary-amd64/Packages.gz
 907e3769de05e2dd69fb911b45aba8b5404b5b6c10ac1a2a1c845880322f7f1e 57201 main/binary-amd64/Packages.bz2
 3be11ada16114f21aef8684b11bf4cdc879ca4602b68056fcba359f8dcb223e6 58444 main/binary-amd64/Packages.xz
 94abd755acbd600ae822b26f9ebab2aa0bf23715ab2063a08f8733c51c642957 25076 main/Contents-amd64
 1ccf7551453fd411bd815e9cb91292512c46968d880d622297c33d07da2d7ca5 2039 main/Contents-amd64.gz
 b030dd088aab2ed17e9d8cd545dddb4ae79e5bfa50c2a40e3c2685ee2e8e76d2 1749 main/Contents-amd64.bz2
 7d071594d1b3d3df39d2ccd0dd40070102395fbced8d971c51af776e5914a87d 1904 main/Contents-amd64.xz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9 85 main/binary-amd64/Release
 3e263cd1d7393e90f5db0cf5f2f4c82bdea525e3acb119c7aae5d64aac402594 84 main/binary-amd64/Release.gz
 2559188d2ba8299dbc8942023ba941d40e71759f678090e944603343fb818ef6 101 main/binary-amd64/Release.bz2
 78da08aaa862fcdd4946b033fe22adddd1e57bf0f0a59040cf5381914c7a1cbf 128 main/binary-amd64/Release.xz
SHA512:
 19e5830781cfdb3a3b606159b94312cbdfed829a5d33990140001f1e0ac5b429b6dae2941be6cc8ee991cd04da993cf3f0d0c729a2e2842c4541bc2a1b51e746 309659 main/binary-amd64/Packages
 5e3dac7df6e28bbf026d4ace79626b850d7a583106cbc7e52546da3ed1466df348f52e2f267ef52f8787cb5f99be6b3b54e45490c401482fa8c437806ce52d6c 64652 main/binary-amd64/Packages.gz
 7136b4d6986ba6e2e2bcc0a36be6f20d8cd8835e400b9f381c6db34e67f0f7209ab00cfda7d8fa0dc6ac9863b295e6a2eae233aba9b3c5ac0de81cb3284ea707 57201 main/binary-amd64/Packages.bz2
 27d8dd4ed7b470cdcb46517954b77aca1e1a8713783d1fa1a1a7f14379ef4509b1b9604e186d16a93e1313d0ed02e5a88f073749f6ef7cc9413f999622c84707 58444 main/binary-amd64/Packages.xz
 95f2bdbfac6769737aa51546f83ab4b14c8cf289657e509c004de6c781fc04c7c38f5270c6ac478531a5cd3d8c1b1a834c7dc9dc53ef309f882414b4878853db 25076 main/Contents-amd64
 1636d5437c35c1a78d71ab9b38d35c90399110b43d5920ef065a2b433d8013476c184abd3aca87e422b4be12c4db8d877badad581e4ad34c89fdacf7595b1c2e 2039 main/Contents-amd64.gz
 c2e4c9db2f98bc65ab4d22f6da023c7b2f4c10b013f8e1efbac1d519035c299117a6e1d8a8a37cc8b2f50ef6588b03ccd3f1f587d280fa85696e78b9f62ed65f 1749 main/Contents-amd64.bz2
 16134ecd6a8ed69bc74f21a76e029feca04dd57a9eb90b0529d7984073e42db4c9806af5c78bf7746505b1c6d26201a7e8792b2988b9e949c35ee24ec23a2d06 1904 main/Contents-amd64.xz
 3bdd91456dd4be348fc772ee4b2bef3b77467c1405b63332e2e531a98c6f44de88b2f3a8b42f28ff0b24f133a8e50e756de1200ba51c7ba74331e3eab136b489 85 main/binary-amd64/Release
 b4f4204a7587db0a61e4bd6b420091c37b3863a5d5c6ddc5deb699c20036496705cd28f7e6358510ac79c91dab7cec6f39342f0af8e81a7c61559e797edb6971 84 main/binary-amd64/Release.gz
 79b5d47081f0425501f3b98536f5174c8e1730f3ac3d466a9773563aab8fc708a613a29f4c028edce95bb45bb73c6176f7b7f669c0bb2cb102baeb87b9badb21 101 main/binary-amd64/Release.bz2
 43d6fae55651c3e884a86cc9361e4a930dc001183847a28f436ea420a4385cadebb18c69286e2cd22129260a64f223660852d3eb825c8a3cfe4b9197329617e0 128 main/binary-amd64/Release.xz
-----BEGIN PGP SIGNATURE-----

wsFzBAEBCAAnBQJmhNLTCRDZgKF0V/b7BhYhBNuja1GB0MgW9jDoidmAoXRX9vsG
AAAMPg/+P/QDpcKnVNJ6qTAewL2c6852c8yloZes83wr1hD/cMdOWs7wKUpgZKCm
WNG+0GtrE/HeHEWtqxz4yoAbO5ZImoV90a0XviIa76csHOlKULnp+qioi4X90kIX
crhKZL7PGXVj4oOXlhO/Qk+25P5x/uKpUGkH9tFVdSORJ2iVHiLUQk5kfBG7VMWv
tmiFLCy8a+AXG3S/smMzasZq1ihdqc0pkg8uUr1yxEQR42+0e/BJdjkdZfCFdrb7
LYvmSFLvFI3Aq8bo0Z2kEFe370oa+a3VOdTfEMoTJVnmAJONngpwc/CrRvrEWBVm
q58qPcEWrygFqa6Uxo6QqygoFjrhvUvaPpxsRCfbUkeEfDIOmhpq+yY7Xo5niIUZ
d71jg+nfd/qh3amvzjTZRQ80F6667y0JoLN9RpjxXZbfeg5rPWWdrU2FaC/cXdaj
emLBsCFonme9IzBNXi9VoHkW5RQ8xY0cS0IwfGNoVVWi2FXjoGzdzWHS2qQem7Zo
mES/hOg4z5+tyyOkj9hn1xqE2F0zIDrltqK6xY2tnUZiJo9GbSsTQuj826K2FASn
n6XHHgZs+FZmCNUSAxzSfM3Y8l55scuKbr7PwhOwLmx2WNVd/RQ8K0VoJAmAnoN5
TQb+9OlSI0ZCZxiegW3IMDL6Qy6u/4nySGfFk21y7t3sc8W0+68=
=JjIx
-----END PGP SIGNATURE-----";
        let (signed, remaining) = Signed::from_bytes(content)?;
        assert_eq!(remaining, b"");
        assert_eq!(
            signed,
            Signed {
                content: BString::from(b"Origin: . xenial
Label: . xenial
Suite: xenial
Codename: xenial
Date: Wed, 03 Jul 2024 04:25:50 +0000
Architectures: amd64
Components: main
Description: Generated by update-apt script
MD5Sum:
 367c2064db4d7381ad9c3ebaba5f0900 309659 main/binary-amd64/Packages
 2555166c9f8c3fcf263bed1780d3214c 64652 main/binary-amd64/Packages.gz
 fc7c26c533cff1978147c24aa468000c 57201 main/binary-amd64/Packages.bz2
 b342b94b4c37c2c3d7e8ef1d39dac67a 58444 main/binary-amd64/Packages.xz
 db8aee13877134f794b225cfb7693351 25076 main/Contents-amd64
 3b5112b5a0da0fc3e178be1b393ad7b0 2039 main/Contents-amd64.gz
 465d036058c655a15adaef094f9286bb 1749 main/Contents-amd64.bz2
 7946f3339f79d17faddcaa0203b0f97e 1904 main/Contents-amd64.xz
 d8c35b55bc8e48e267b9ccdaf383976d 85 main/binary-amd64/Release
 2e9782caa73a260c91ba9bb28a7fb716 84 main/binary-amd64/Release.gz
 564810f1411d179c193cc9f28f78c939 101 main/binary-amd64/Release.bz2
 c7ddb24e1d0b64ca584392d71403b3cb 128 main/binary-amd64/Release.xz
SHA1:
 61c7f4e2f521983011f7bfbf487710c2437df3a0 309659 main/binary-amd64/Packages
 182b735c97dc4d73a98c736f5a87010a19b69b21 64652 main/binary-amd64/Packages.gz
 2b315a75313e08a7147443ecaec2319c58a6e08e 57201 main/binary-amd64/Packages.bz2
 fc796ff95f712a82fce57fcacf7906d6f215d075 58444 main/binary-amd64/Packages.xz
 e19b50fedca995916d7643083134cc7b66ea72c0 25076 main/Contents-amd64
 e6f19033bae7266e50dfcb3725de8ed347e88b49 2039 main/Contents-amd64.gz
 b6de2e9e9445e26ce72f79ce00d86f94b16b07be 1749 main/Contents-amd64.bz2
 b58c520d24b6af04a95fc12f560cd05c6864c17c 1904 main/Contents-amd64.xz
 992cb9cd8a0af2d9ad81d2b45342656d41157202 85 main/binary-amd64/Release
 32230bb251530e6563c378abd4bbf187af5aa904 84 main/binary-amd64/Release.gz
 9a096aed53faad9054f79670507cd3da197801a7 101 main/binary-amd64/Release.bz2
 ba7c389834035e903744b153a1c54e2dc5966b01 128 main/binary-amd64/Release.xz
SHA256:
 88730d9436f17ed233d1b92d5f5d9f53b4144ffac2e83bb91f8864c0b55650c0 309659 main/binary-amd64/Packages
 d8704f58be01ed834143c678d43f1be22b5b768acb747d7aed8f17c9e5eb859e 64652 main/binary-amd64/Packages.gz
 907e3769de05e2dd69fb911b45aba8b5404b5b6c10ac1a2a1c845880322f7f1e 57201 main/binary-amd64/Packages.bz2
 3be11ada16114f21aef8684b11bf4cdc879ca4602b68056fcba359f8dcb223e6 58444 main/binary-amd64/Packages.xz
 94abd755acbd600ae822b26f9ebab2aa0bf23715ab2063a08f8733c51c642957 25076 main/Contents-amd64
 1ccf7551453fd411bd815e9cb91292512c46968d880d622297c33d07da2d7ca5 2039 main/Contents-amd64.gz
 b030dd088aab2ed17e9d8cd545dddb4ae79e5bfa50c2a40e3c2685ee2e8e76d2 1749 main/Contents-amd64.bz2
 7d071594d1b3d3df39d2ccd0dd40070102395fbced8d971c51af776e5914a87d 1904 main/Contents-amd64.xz
 e593f5bb98e0b6dbf5d0636ebff298b905b98a00402e2b20173fdb5da85c46d9 85 main/binary-amd64/Release
 3e263cd1d7393e90f5db0cf5f2f4c82bdea525e3acb119c7aae5d64aac402594 84 main/binary-amd64/Release.gz
 2559188d2ba8299dbc8942023ba941d40e71759f678090e944603343fb818ef6 101 main/binary-amd64/Release.bz2
 78da08aaa862fcdd4946b033fe22adddd1e57bf0f0a59040cf5381914c7a1cbf 128 main/binary-amd64/Release.xz
SHA512:
 19e5830781cfdb3a3b606159b94312cbdfed829a5d33990140001f1e0ac5b429b6dae2941be6cc8ee991cd04da993cf3f0d0c729a2e2842c4541bc2a1b51e746 309659 main/binary-amd64/Packages
 5e3dac7df6e28bbf026d4ace79626b850d7a583106cbc7e52546da3ed1466df348f52e2f267ef52f8787cb5f99be6b3b54e45490c401482fa8c437806ce52d6c 64652 main/binary-amd64/Packages.gz
 7136b4d6986ba6e2e2bcc0a36be6f20d8cd8835e400b9f381c6db34e67f0f7209ab00cfda7d8fa0dc6ac9863b295e6a2eae233aba9b3c5ac0de81cb3284ea707 57201 main/binary-amd64/Packages.bz2
 27d8dd4ed7b470cdcb46517954b77aca1e1a8713783d1fa1a1a7f14379ef4509b1b9604e186d16a93e1313d0ed02e5a88f073749f6ef7cc9413f999622c84707 58444 main/binary-amd64/Packages.xz
 95f2bdbfac6769737aa51546f83ab4b14c8cf289657e509c004de6c781fc04c7c38f5270c6ac478531a5cd3d8c1b1a834c7dc9dc53ef309f882414b4878853db 25076 main/Contents-amd64
 1636d5437c35c1a78d71ab9b38d35c90399110b43d5920ef065a2b433d8013476c184abd3aca87e422b4be12c4db8d877badad581e4ad34c89fdacf7595b1c2e 2039 main/Contents-amd64.gz
 c2e4c9db2f98bc65ab4d22f6da023c7b2f4c10b013f8e1efbac1d519035c299117a6e1d8a8a37cc8b2f50ef6588b03ccd3f1f587d280fa85696e78b9f62ed65f 1749 main/Contents-amd64.bz2
 16134ecd6a8ed69bc74f21a76e029feca04dd57a9eb90b0529d7984073e42db4c9806af5c78bf7746505b1c6d26201a7e8792b2988b9e949c35ee24ec23a2d06 1904 main/Contents-amd64.xz
 3bdd91456dd4be348fc772ee4b2bef3b77467c1405b63332e2e531a98c6f44de88b2f3a8b42f28ff0b24f133a8e50e756de1200ba51c7ba74331e3eab136b489 85 main/binary-amd64/Release
 b4f4204a7587db0a61e4bd6b420091c37b3863a5d5c6ddc5deb699c20036496705cd28f7e6358510ac79c91dab7cec6f39342f0af8e81a7c61559e797edb6971 84 main/binary-amd64/Release.gz
 79b5d47081f0425501f3b98536f5174c8e1730f3ac3d466a9773563aab8fc708a613a29f4c028edce95bb45bb73c6176f7b7f669c0bb2cb102baeb87b9badb21 101 main/binary-amd64/Release.bz2
 43d6fae55651c3e884a86cc9361e4a930dc001183847a28f436ea420a4385cadebb18c69286e2cd22129260a64f223660852d3eb825c8a3cfe4b9197329617e0 128 main/binary-amd64/Release.xz
"),
                signature: vec![
                    194, 193, 115, 4, 1, 1, 8, 0, 39, 5, 2, 102, 132, 210, 211, 9, 16, 217, 128,
                    161, 116, 87, 246, 251, 6, 22, 33, 4, 219, 163, 107, 81, 129, 208, 200, 22,
                    246, 48, 232, 137, 217, 128, 161, 116, 87, 246, 251, 6, 0, 0, 12, 62, 15, 254,
                    63, 244, 3, 165, 194, 167, 84, 210, 122, 169, 48, 30, 192, 189, 156, 235, 206,
                    118, 115, 204, 165, 161, 151, 172, 243, 124, 43, 214, 16, 255, 112, 199, 78,
                    90, 206, 240, 41, 74, 96, 100, 160, 166, 88, 209, 190, 208, 107, 107, 19, 241,
                    222, 28, 69, 173, 171, 28, 248, 202, 128, 27, 59, 150, 72, 154, 133, 125, 209,
                    173, 23, 190, 34, 26, 239, 167, 44, 28, 233, 74, 80, 185, 233, 250, 168, 168,
                    139, 133, 253, 210, 66, 23, 114, 184, 74, 100, 190, 207, 25, 117, 99, 226, 131,
                    151, 150, 19, 191, 66, 79, 182, 228, 254, 113, 254, 226, 169, 80, 105, 7, 246,
                    209, 85, 117, 35, 145, 39, 104, 149, 30, 34, 212, 66, 78, 100, 124, 17, 187,
                    84, 197, 175, 182, 104, 133, 44, 44, 188, 107, 224, 23, 27, 116, 191, 178, 99,
                    51, 106, 198, 106, 214, 40, 93, 169, 205, 41, 146, 15, 46, 82, 189, 114, 196,
                    68, 17, 227, 111, 180, 123, 240, 73, 118, 57, 29, 101, 240, 133, 118, 182, 251,
                    45, 139, 230, 72, 82, 239, 20, 141, 192, 171, 198, 232, 209, 157, 164, 16, 87,
                    183, 239, 74, 26, 249, 173, 213, 57, 212, 223, 16, 202, 19, 37, 89, 230, 0,
                    147, 141, 158, 10, 112, 115, 240, 171, 70, 250, 196, 88, 21, 102, 171, 159, 42,
                    61, 193, 22, 175, 40, 5, 169, 174, 148, 198, 142, 144, 171, 40, 40, 22, 58,
                    225, 189, 75, 218, 62, 156, 108, 68, 39, 219, 82, 71, 132, 124, 50, 14, 154,
                    26, 106, 251, 38, 59, 94, 142, 103, 136, 133, 25, 119, 189, 99, 131, 233, 223,
                    119, 250, 161, 221, 169, 175, 206, 52, 217, 69, 15, 52, 23, 174, 186, 239, 45,
                    9, 160, 179, 125, 70, 152, 241, 93, 150, 223, 122, 14, 107, 61, 101, 157, 173,
                    77, 133, 104, 47, 220, 93, 214, 163, 122, 98, 193, 176, 33, 104, 158, 103, 189,
                    35, 48, 77, 94, 47, 85, 160, 121, 22, 229, 20, 60, 197, 141, 28, 75, 66, 48,
                    124, 99, 104, 85, 85, 162, 216, 85, 227, 160, 108, 221, 205, 97, 210, 218, 164,
                    30, 155, 182, 104, 152, 68, 191, 132, 232, 56, 207, 159, 173, 203, 35, 164,
                    143, 216, 103, 215, 26, 132, 216, 93, 51, 32, 58, 229, 182, 162, 186, 197, 141,
                    173, 157, 70, 98, 38, 143, 70, 109, 43, 19, 66, 232, 252, 219, 162, 182, 20, 4,
                    167, 159, 165, 199, 30, 6, 108, 248, 86, 102, 8, 213, 18, 3, 28, 210, 124, 205,
                    216, 242, 94, 121, 177, 203, 138, 110, 190, 207, 194, 19, 176, 46, 108, 118,
                    88, 213, 93, 253, 20, 60, 43, 69, 104, 36, 9, 128, 158, 131, 121, 77, 6, 254,
                    244, 233, 82, 35, 70, 66, 103, 24, 158, 129, 109, 200, 48, 50, 250, 67, 46,
                    174, 255, 137, 242, 72, 103, 197, 147, 109, 114, 238, 221, 236, 115, 197, 180,
                    251, 175
                ],
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_from_reader() -> Result<()> {
        let canonical = Signed::from_reader(&mut &IN_RELEASE[..]).await?;
        let canonical = canonical.to_clear_signed()?;
        assert_eq!(BStr::new(&canonical), BStr::new(IN_RELEASE));
        Ok(())
    }
}
