use crate::errors::*;
use std::net::SocketAddr;

pub const DNS_SEEDS: &[&str] = &["dnsseed.apt-swarm.orca.toys"];

pub async fn resolve(dns: &str) -> Result<impl Iterator<Item = SocketAddr>> {
    info!("Resolving dns name: {dns:?}");
    let host = format!("{dns}:16169");
    let stream = tokio::net::lookup_host(host.clone())
        .await
        .context(anyhow!("Failed to resolve: {host:?}"))?;
    Ok(stream)
}
