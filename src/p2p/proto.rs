use crate::errors::*;
use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub struct PeerGossip {
    pub fp: sequoia_openpgp::Fingerprint,
    pub idx: String,
    pub count: u64,
    pub addrs: Vec<SocketAddr>,
}

impl FromStr for PeerGossip {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s
            .strip_prefix("[sync] ")
            .context("Message is missing the [sync] tag")?;

        let mut split = s.split(' ');
        let fp = split
            .next()
            .context("Missing mandatory attribute: fingerprint")?;
        let fp = fp
            .strip_prefix("fp=")
            .with_context(|| anyhow!("First attribute is expected to be fingerprint: {fp:?}"))?;
        let fp = fp
            .parse()
            .with_context(|| anyhow!("Failed to parse as fingerprint: {fp:?}"))?;

        let idx = split.next().context("Missing mandatory attribute: index")?;
        let idx = idx
            .strip_prefix("idx=")
            .with_context(|| anyhow!("First attribute is expected to be index: {idx:?}"))?
            .to_string();

        let count = split.next().context("Missing mandatory attribute: count")?;
        let count = count
            .strip_prefix("count=")
            .with_context(|| anyhow!("First attribute is expected to be count: {count:?}"))?;
        let count = count
            .parse()
            .with_context(|| anyhow!("Failed to parse as count: {count:?}"))?;

        let mut addrs = Vec::new();

        for extra in split {
            if let Some(addr) = extra.strip_prefix("addr=") {
                let addr = addr
                    .parse()
                    .with_context(|| anyhow!("Failed to parse as address: {addr:?}"))?;
                addrs.push(addr);
            }
        }

        Ok(PeerGossip {
            fp,
            idx,
            count,
            addrs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_irc_no_addrs() -> Result<()> {
        let s = "[sync] fp=ED541312A33F1128F10B1C6C54404762BBB6E853 idx=sha256:1994bea786a499ec72ce94a45e2830ce31746a5ef4fb7a2b73ba0934e4a046ac count=180";
        let gi = s.parse::<PeerGossip>()?;
        assert_eq!(
            gi,
            PeerGossip {
                fp: "ED541312A33F1128F10B1C6C54404762BBB6E853".parse()?,
                idx: "sha256:1994bea786a499ec72ce94a45e2830ce31746a5ef4fb7a2b73ba0934e4a046ac"
                    .to_string(),
                count: 180,
                addrs: Vec::new(),
            }
        );
        Ok(())
    }

    #[test]
    fn test_parse_irc_multiple_addrs() -> Result<()> {
        let s = "[sync] fp=2265EB4CB2BF88D900AE8D1B74A941BA219EC810 idx=sha256:55a00753512036f55ccc421217e008e4922c66592e6281b09de2fcba4dbd59ce count=12 addr=192.0.2.146:16169 addr=[2001:db8:c010:8f3a::1]:16169";
        let gi = s.parse::<PeerGossip>()?;
        assert_eq!(
            gi,
            PeerGossip {
                fp: "2265EB4CB2BF88D900AE8D1B74A941BA219EC810".parse()?,
                idx: "sha256:55a00753512036f55ccc421217e008e4922c66592e6281b09de2fcba4dbd59ce"
                    .to_string(),
                count: 12,
                addrs: vec![
                    "192.0.2.146:16169".parse()?,
                    "[2001:db8:c010:8f3a::1]:16169".parse()?,
                ],
            }
        );
        Ok(())
    }
}
