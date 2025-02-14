use tokio::time::{self, Duration, Instant, Interval};

pub struct EasedInterval {
    started: Option<Instant>,
    delay: Duration,
    interval: Interval,
}

impl EasedInterval {
    pub fn new(delay: Duration, interval: Duration) -> Self {
        Self {
            started: Some(Instant::now()),
            delay,
            interval: time::interval(interval),
        }
    }

    pub async fn tick(&mut self) {
        if let Some(started) = &self.started {
            let elapsed = Instant::now().duration_since(*started);
            if let Some(remaining) = self.delay.checked_sub(elapsed) {
                time::sleep(remaining).await;
            }
            self.started = None;
            self.interval.reset();
        } else {
            self.interval.tick().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_eased_interval() {
        let mut interval =
            EasedInterval::new(Duration::from_millis(100), Duration::from_millis(50));
        tokio::select! {
            _ = interval.tick() => panic!("interval is not expected to tick yet"),
            _ = time::sleep(Duration::from_millis(50)) => (),
        };
        tokio::select! {
            _ = interval.tick() => (),
            _ = time::sleep(Duration::from_millis(75)) => panic!("interval was expected to tick"),
        };
        tokio::select! {
            _ = interval.tick() => panic!("interval is not expected to tick yet"),
            _ = time::sleep(Duration::from_millis(35)) => (),
        };
        tokio::select! {
            _ = interval.tick() => (),
            _ = time::sleep(Duration::from_millis(25)) => panic!("interval was expected to tick"),
        };
        tokio::select! {
            _ = interval.tick() => (),
            _ = time::sleep(Duration::from_millis(60)) => panic!("interval was expected to tick"),
        };
    }
}
