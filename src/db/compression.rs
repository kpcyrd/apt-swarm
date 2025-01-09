use crate::errors::*;
use std::io::{Read, Write};

const CHUNK_SIZE: usize = 4096;

pub async fn compress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut compressed = Vec::new();

    let mut writer = lz4_flex::frame::FrameEncoder::new(&mut compressed);
    for chunk in bytes.chunks(CHUNK_SIZE) {
        writer.write_all(chunk)?;

        // yield in between chunks to avoid hanging the process
        tokio::task::yield_now().await;
    }
    writer.finish()?;

    Ok(compressed)
}

pub async fn decompress(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut data = Vec::new();

    let mut reader = lz4_flex::frame::FrameDecoder::new(compressed);
    let mut buf = [0u8; CHUNK_SIZE];
    loop {
        let n = reader
            .read(&mut buf)
            .context("Failed to read from decompression stream")?;
        if n == 0 {
            break;
        }
        data.extend(&buf[..n]);

        // yield in between chunks to avoid hanging the process
        tokio::task::yield_now().await;
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_round_trip() {
        let txt = b"hello world, around the world, around the world, around the world :)";
        let compressed = compress(txt).await.unwrap();
        let buf = decompress(&compressed).await.unwrap();
        assert_eq!(&buf, txt);
    }

    #[tokio::test]
    async fn test_compress() {
        let buf = compress(b"hello world, around the world, around the world, around the world :)")
            .await
            .unwrap();
        assert_eq!(
            buf,
            b"\x04\"M\x18`@\x82#\0\0\0\xff\x08hello world, around the\x12\0\x14`rld :)\0\0\0\0"
        );
    }

    #[tokio::test]
    async fn test_decompress() {
        let compressed =
            b"\x04\"M\x18`@\x82#\0\0\0\xff\x08hello world, around the\x12\0\x14`rld :)\0\0\0\0";
        let buf = decompress(compressed).await.unwrap();
        assert_eq!(
            buf,
            b"hello world, around the world, around the world, around the world :)"
        );
    }
}
