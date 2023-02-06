use crate::errors::*;
use std::path::PathBuf;

pub struct Config {}

impl Config {
    pub fn apt_swarm_path(&self) -> Result<PathBuf> {
        let data_dir = dirs::data_dir().context("Failed to detect data directory")?;
        let path = data_dir.join("apt-swarm");
        Ok(path)
    }

    pub fn database_path(&self) -> Result<PathBuf> {
        let data_dir = self.apt_swarm_path()?;
        let path = data_dir.join("db");
        Ok(path)
    }
}
