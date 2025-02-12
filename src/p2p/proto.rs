use crate::errors::*;
use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub enum SyncRequest {
    Gossip(PeerGossip),
    Addr(PeerAddr),
}

#[derive(Debug, PartialEq)]
pub struct PeerGossip {
    pub fp: sequoia_openpgp::Fingerprint,
    pub idx: String,
    pub count: u64,
    pub addrs: Vec<PeerAddr>,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerAddr {
    Inet(SocketAddr),
    Onion((String, u16)),
}

impl PeerAddr {
    pub fn xor_distance(&self, other: &PeerAddr) -> Option<u128> {
        match (self, other) {
            (PeerAddr::Inet(SocketAddr::V4(value)), PeerAddr::Inet(SocketAddr::V4(other))) => {
                let value = u32::from_be_bytes(value.ip().octets());
                let other = u32::from_be_bytes(other.ip().octets());
                let distance = (value ^ other) as u128;
                Some(distance << 96)
            }
            (PeerAddr::Inet(SocketAddr::V6(value)), PeerAddr::Inet(SocketAddr::V6(other))) => {
                let value = value.ip().to_bits();
                let other = other.ip().to_bits();
                Some(value ^ other)
            }
            // key distance doesn't make sense here
            (PeerAddr::Onion(_), PeerAddr::Onion(_)) => Some(1),
            _ => None,
        }
    }
}

impl FromStr for PeerAddr {
    type Err = Error;

    fn from_str(addr: &str) -> Result<Self> {
        if addr.starts_with('[') {
            // IPv6 address
            let addr = addr.parse()?;
            Ok(PeerAddr::Inet(addr))
        } else {
            let Some((host, port)) = addr.rsplit_once(':') else {
                bail!("Missing port in peer address: {addr:?}");
            };
            let port = port
                .parse()
                .with_context(|| anyhow!("Failed to parse port: {addr:?}"))?;

            if host.ends_with(".onion") {
                // .onion address
                Ok(PeerAddr::Onion((host.to_string(), port)))
            } else {
                // IPv4 address
                let host = host
                    .parse()
                    .with_context(|| anyhow!("Failed to parse ip address: {addr:?}"))?;
                Ok(PeerAddr::Inet(SocketAddr::new(host, port)))
            }
        }
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

    #[test]
    fn test_parse_irc_with_onion() -> Result<()> {
        let s = "[sync] fp=2265EB4CB2BF88D900AE8D1B74A941BA219EC810 idx=sha256:55a00753512036f55ccc421217e008e4922c66592e6281b09de2fcba4dbd59ce count=12 addr=192.0.2.146:16169 addr=3wisi2bfpxplne5wlwz4l5ucvsbaozbteaqnm62oxzmgwhb2qqxvsuyd.onion:16169";
        let gi = s.parse::<PeerGossip>()?;
        assert_eq!(
            gi,
            PeerGossip {
                fp: "2265EB4CB2BF88D900AE8D1B74A941BA219EC810".parse()?,
                idx: "sha256:55a00753512036f55ccc421217e008e4922c66592e6281b09de2fcba4dbd59ce"
                    .to_string(),
                count: 12,
                addrs: vec![
                    PeerAddr::Inet("192.0.2.146:16169".parse()?),
                    PeerAddr::Onion((
                        "3wisi2bfpxplne5wlwz4l5ucvsbaozbteaqnm62oxzmgwhb2qqxvsuyd.onion"
                            .to_string(),
                        16169
                    )),
                ],
            }
        );
        Ok(())
    }

    #[test]
    fn test_ipv4_xor_distance() {
        let base = "192.168.1.2:16169".parse::<PeerAddr>().unwrap();
        assert_eq!(
            base.xor_distance(&"192.168.1.2:16169".parse::<PeerAddr>().unwrap()),
            Some(0)
        );
        assert_eq!(
            base.xor_distance(&"192.168.1.2:443".parse::<PeerAddr>().unwrap()),
            Some(0)
        );
        assert_eq!(
            base.xor_distance(&"192.168.1.1:16169".parse::<PeerAddr>().unwrap()),
            Some(3 << 96)
        );
        assert_eq!(
            base.xor_distance(&"192.168.1.3:16169".parse::<PeerAddr>().unwrap()),
            Some(1 << 96)
        );
        assert_eq!(
            base.xor_distance(&"192.168.2.0:16169".parse::<PeerAddr>().unwrap()),
            Some(770 << 96)
        );
        assert_eq!(
            base.xor_distance(&"1.0.0.1:16169".parse::<PeerAddr>().unwrap()),
            Some(3_249_012_995 << 96)
        );
        assert_eq!(
            base.xor_distance(&"255.255.255.255:16169".parse::<PeerAddr>().unwrap()),
            Some(1_062_731_517 << 96)
        );
        assert_eq!(
            base.xor_distance(
                &"[2001:db8:3333:4444:5555:6666:7777:8888]:16169"
                    .parse::<PeerAddr>()
                    .unwrap()
            ),
            None
        );
    }

    #[test]
    fn test_ipv6_xor_distance() {
        let base = "[2001:db8:3333:4444:5555:6666:7777:8888]:16169"
            .parse::<PeerAddr>()
            .unwrap();
        assert_eq!(
            base.xor_distance(
                &"[2001:db8:3333:4444:5555:6666:7777:8888]:16169"
                    .parse::<PeerAddr>()
                    .unwrap()
            ),
            Some(0)
        );
        assert_eq!(
            base.xor_distance(
                &"[2001:db8:3333:4444:5555:6666:7777:8888]:443"
                    .parse::<PeerAddr>()
                    .unwrap()
            ),
            Some(0)
        );
        assert_eq!(
            base.xor_distance(&"[2001:db8::]:16169".parse::<PeerAddr>().unwrap()),
            Some(15_845_713_099_137_310_197_519_190_152)
        );
        assert_eq!(
            base.xor_distance(&"[fe80::1a2b:3c4d:5e6f]:16169".parse::<PeerAddr>().unwrap()),
            Some(295_758_699_624_154_779_744_216_564_213_718_111_975)
        );
    }
}
