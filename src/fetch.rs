use crate::config;
use crate::config::Repository;
use crate::db::DatabaseClient;
use crate::errors::*;
use crate::keyring::Keyring;
use crate::signed::Signed;
use sequoia_openpgp::Fingerprint;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

pub const DEFAULT_CONCURRENCY: usize = 4;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);

async fn fetch_repository_updates(
    client: &reqwest::Client,
    keyring: &Option<Keyring>,
    repository: &config::Repository,
) -> Result<Vec<(Option<Fingerprint>, Signed)>> {
    let mut out = Vec::new();

    for source in &repository.urls {
        let Ok(signed) = source
            .fetch(client)
            .await
            .inspect_err(|err| error!("Error fetching latest release: {err:#}"))
        else {
            continue;
        };

        for item in signed.canonicalize(keyring.as_ref())? {
            out.push(item);
        }
    }

    Ok(out)
}

pub async fn fetch_updates<D: DatabaseClient>(
    db: &mut D,
    keyring: Arc<Option<Keyring>>,
    concurrency: Option<usize>,
    repositories: Vec<Repository>,
    proxy: Option<SocketAddr>,
) -> Result<()> {
    let concurrency = concurrency.unwrap_or(DEFAULT_CONCURRENCY);
    let mut queue = repositories.into_iter();
    let mut pool = JoinSet::new();
    let mut client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT);
    if let Some(proxy) = proxy {
        let proxy = format!("socks5h://{proxy:?}");
        let proxy = reqwest::Proxy::all(&proxy)
            .with_context(|| anyhow!("Failed to parse as proxy: {proxy:?}"))?;
        client = client.proxy(proxy);
    }
    let client = client.build().context("Failed to setup http client")?;

    loop {
        while pool.len() < concurrency {
            if let Some(repository) = queue.next() {
                let client = client.clone();
                let keyring = keyring.clone();
                pool.spawn(async move {
                    fetch_repository_updates(&client, &keyring, &repository).await
                });
            } else {
                // no more tasks to schedule
                break;
            }
        }
        if let Some(join) = pool.join_next().await {
            match join.context("Failed to join task")? {
                Ok(list) => {
                    for (fp, variant) in list {
                        let fp = fp.context(
                            "Signature can't be imported because the signature is unverified",
                        )?;
                        db.add_release(&fp, &variant).await?;
                    }
                }
                Err(err) => error!("Error fetching latest release: {err:#}"),
            }
        } else {
            // no more tasks in pool
            break;
        }
    }
    db.flush().await.context("Failed to flush database")?;

    Ok(())
}
