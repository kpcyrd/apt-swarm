use crate::errors::*;
use advisory_lock::{AdvisoryFileLock, FileLockMode};
use std::path::Path;
use tokio::fs::File;

#[derive(Debug)]
pub struct Lock {
    #[allow(dead_code)]
    file: File,
}

impl Lock {
    pub async fn acquire(path: &Path) -> Result<Self> {
        debug!("Acquiring exclusive lock on directory: {path:?}");
        let file = File::open(path)
            .await
            .with_context(|| anyhow!("Failed to open directory: {path:?}"))?;
        let file = file.into_std().await;
        AdvisoryFileLock::try_lock(&file, FileLockMode::Exclusive)
            .with_context(|| anyhow!("Failed to acquire exclusive lock for: {path:?}"))?;
        debug!("Successfully acquired exclusive lock");
        let file = file.into();
        Ok(Self { file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lock_directory() {
        let dir = tempfile::tempdir().unwrap();
        let _lock = Lock::acquire(dir.path()).await.unwrap();
        let err = Lock::acquire(dir.path()).await.err().unwrap().to_string();
        let (err, _) = err.split_once(": ").unwrap();
        assert_eq!(err, "Failed to acquire exclusive lock for");
    }

    #[tokio::test]
    async fn test_release_lock() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _lock = Lock::acquire(dir.path()).await.unwrap();
            let err = Lock::acquire(dir.path()).await.err().unwrap().to_string();
            let (err, _) = err.split_once(": ").unwrap();
            assert_eq!(err, "Failed to acquire exclusive lock for");
        }
        let _lock = Lock::acquire(dir.path()).await.unwrap();
    }
}
