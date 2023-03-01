use crate::args::ContainerUpdateCheck;
use crate::errors::*;
use crate::p2p;
use crate::plumbing::update;
use std::convert::Infallible;
use tokio::time;

pub async fn spawn_update_check(image: String, commit: String) -> Result<Infallible> {
    let mut interval = time::interval(p2p::UPDATE_CHECK_INTERVAL);
    debug!("Delaying first update check");
    time::sleep(p2p::UPDATE_CHECK_DEBOUNCE).await;
    let check = ContainerUpdateCheck { image, commit };
    loop {
        interval.tick().await;
        match update::check(&check).await {
            Ok(update::Updates::Available { current, latest }) => {
                warn!(
                    "We're running an outdated version of {:?}, going to shutdown in some minutes... (current={:?}, latest={:?})",
                    check.image, current, latest
                );
                time::sleep(p2p::UPDATE_SHUTDOWN_DELAY).await;
                bail!("Sending shutdown signal to request container image update");
            }
            Ok(_) => (),
            Err(err) => {
                warn!("Update check failed: {err:#}");
            }
        }
    }
}
