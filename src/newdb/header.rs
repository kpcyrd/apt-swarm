use crate::errors::*;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub type HashLength = u16;
pub type DataLength = u64;

#[derive(Debug, PartialEq)]
pub struct CryptoHash(pub String);

impl CryptoHash {
    #[inline]
    fn split_marker(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
        let offset = memchr::memchr(b':', bytes).context("Failed to find hash id marker `:`")?;
        let (hash_id, hash_data) = bytes.split_at(offset + 1);
        Ok((hash_id, hash_data))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        // determine the `sha256:` and binary boundary
        let (hash_id, hash_data) = Self::split_marker(bytes)?;

        // allocate memory for our decoded hash
        let mut hash = hash_id.to_owned();
        hash.resize(hash.len() + hash_data.len() * 2, 0u8);

        // decode binary to hex
        hex::encode_to_slice(hash_data, &mut hash[hash_id.len()..])
            .context("Failed to encode header hash into buffer")?;

        // ensure everything is utf8 and return
        let hash = String::from_utf8(hash).context("Decoded crypto hash is invalid utf8")?;
        Ok(CryptoHash(hash))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        // determine the `sha256:` and hex boundary
        let (hash_id, hash_data) = Self::split_marker(self.0.as_bytes())?;

        // allocate memory for our encoded hash
        let mut hash = hash_id.to_owned();
        hash.resize(hash.len() + hash_data.len().div_ceil(2), 0u8);

        // encode binary to hex
        hex::decode_to_slice(hash_data, &mut hash[hash_id.len()..])
            .context("Failed to decode header hash into buffer")?;

        Ok(hash)
    }
}

#[derive(Debug, PartialEq)]
pub struct BlockHeader {
    pub hash: CryptoHash,
    pub length: u64,
}

impl BlockHeader {
    pub async fn parse<R: AsyncRead + Unpin>(mut reader: R) -> Result<(Self, usize)> {
        let mut n = 0;

        // read hash length field
        let mut hash_length_bytes = [0u8; HashLength::BITS as usize / 8];
        n += reader
            .read_exact(&mut hash_length_bytes)
            .await
            .context("Failed to read hash length")?;
        let hash_length = HashLength::from_be_bytes(hash_length_bytes);

        // read hash bytes
        let mut hash_bytes = vec![0u8; hash_length as usize];
        n += reader
            .read_exact(&mut hash_bytes)
            .await
            .context("Failed to read hash bytes")?;
        let hash = CryptoHash::decode(&hash_bytes)?;

        // read data length field
        let mut data_length_bytes = [0u8; DataLength::BITS as usize / 8];
        n += reader
            .read_exact(&mut data_length_bytes)
            .await
            .context("Failed to read data length")?;
        let data_length = DataLength::from_be_bytes(data_length_bytes);

        Ok((
            BlockHeader {
                hash,
                length: data_length,
            },
            n,
        ))
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, mut writer: W) -> Result<usize> {
        let mut n = 0;

        let encoded = self.hash.encode()?;
        let hash_length_bytes = HashLength::to_be_bytes(encoded.len() as u16);
        writer.write_all(&hash_length_bytes).await?;
        n += hash_length_bytes.len();

        writer.write_all(&encoded).await?;
        n += encoded.len();

        let data_length_bytes = DataLength::to_be_bytes(self.length);
        writer.write_all(&data_length_bytes).await?;
        n += data_length_bytes.len();

        Ok(n)
    }

    pub fn calculate(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        Self {
            hash: CryptoHash(format!("sha256:{result:x}")),
            length: bytes.len() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_header() {
        let mut bytes = Vec::<u8>::new();
        bytes.extend(39u16.to_be_bytes());
        bytes.extend(b"sha256:");
        bytes.extend(&[
            0xe8, 0x47, 0x12, 0x23, 0x87, 0x09, 0x39, 0x8f, 0x6d, 0x34, 0x9d, 0xc2, 0x25, 0x0b,
            0x0e, 0xfc, 0xa4, 0xb7, 0x2d, 0x8c, 0x2b, 0xfb, 0x7b, 0x74, 0x33, 0x9d, 0x30, 0xba,
            0x94, 0x05, 0x6b, 0x14,
        ]);
        bytes.extend(4u64.to_be_bytes());
        // data is not part of the header
        // bytes.extend(b"ohai");
        let (header, bytes_read) = BlockHeader::parse(&bytes[..]).await.unwrap();
        assert_eq!(
            header,
            BlockHeader {
                hash: CryptoHash(
                    "sha256:e84712238709398f6d349dc2250b0efca4b72d8c2bfb7b74339d30ba94056b14"
                        .to_string()
                ),
                length: 4,
            }
        );
        assert_eq!(bytes_read, 49);
    }

    #[tokio::test]
    async fn test_write_header() {
        let header = BlockHeader {
            hash: CryptoHash(
                "sha256:e84712238709398f6d349dc2250b0efca4b72d8c2bfb7b74339d30ba94056b14"
                    .to_string(),
            ),
            length: 4,
        };
        let mut buf = Vec::new();
        header.write(&mut buf).await.unwrap();

        let mut expected = Vec::<u8>::new();
        expected.extend(39u16.to_be_bytes());
        expected.extend(b"sha256:");
        expected.extend(&[
            0xe8, 0x47, 0x12, 0x23, 0x87, 0x09, 0x39, 0x8f, 0x6d, 0x34, 0x9d, 0xc2, 0x25, 0x0b,
            0x0e, 0xfc, 0xa4, 0xb7, 0x2d, 0x8c, 0x2b, 0xfb, 0x7b, 0x74, 0x33, 0x9d, 0x30, 0xba,
            0x94, 0x05, 0x6b, 0x14,
        ]);
        expected.extend(4u64.to_be_bytes());

        assert_eq!(buf, expected);
    }

    #[test]
    fn test_hash_decode_encode() {
        let mut bytes = Vec::<u8>::new();
        bytes.extend(b"sha256:");
        bytes.extend(&[
            0xe8, 0x47, 0x12, 0x23, 0x87, 0x09, 0x39, 0x8f, 0x6d, 0x34, 0x9d, 0xc2, 0x25, 0x0b,
            0x0e, 0xfc, 0xa4, 0xb7, 0x2d, 0x8c, 0x2b, 0xfb, 0x7b, 0x74, 0x33, 0x9d, 0x30, 0xba,
            0x94, 0x05, 0x6b, 0x14,
        ]);

        let hash = CryptoHash::decode(&bytes).unwrap();
        assert_eq!(
            hash,
            CryptoHash(
                "sha256:e84712238709398f6d349dc2250b0efca4b72d8c2bfb7b74339d30ba94056b14"
                    .to_string()
            )
        );

        let encoded = hash.encode().unwrap();
        assert_eq!(encoded, bytes);
    }
}
