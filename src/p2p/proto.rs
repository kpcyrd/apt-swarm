use crate::errors::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub struct SyncRequest {
    pub hint: Option<SyncHint>,
    pub addrs: Vec<PeerAddr>,
}

#[derive(Debug, PartialEq)]
pub struct SyncHint {
    pub fp: sequoia_openpgp::Fingerprint,
    pub idx: String,
}

impl From<PeerGossip> for SyncRequest {
    fn from(gossip: PeerGossip) -> Self {
        Self {
            hint: Some(SyncHint {
                fp: gossip.fp,
                idx: gossip.idx,
            }),
            addrs: gossip.addrs,
        }
    }
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

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PeerAddr {
    Inet(SocketAddr),
    Onion((String, u16)),
}

impl PeerAddr {
    fn inet_to_u128(addr: IpAddr) -> u128 {
        match addr {
            // IPv4 has most significant bit set to 0
            IpAddr::V4(ip) => (ip.to_bits() as u128) << 95,
            // IPv6 has most significant bit set to 1
            IpAddr::V6(ip) => (ip.to_bits() >> 1) | (1 << 127),
        }
    }

    pub fn xor_distance(&self, other: &PeerAddr) -> u128 {
        match (self, other) {
            (PeerAddr::Inet(value), PeerAddr::Inet(other)) => {
                let value = Self::inet_to_u128(value.ip());
                let other = Self::inet_to_u128(other.ip());
                value ^ other
            }
            // key distance doesn't make sense here
            (PeerAddr::Onion(_), PeerAddr::Onion(_)) => 1,
            _ => u128::MAX,
        }
    }
}

impl fmt::Debug for PeerAddr {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerAddr::Inet(addr) => fmt::Debug::fmt(addr, w),
            PeerAddr::Onion((host, port)) => {
                write!(w, "\"{}:{}\"", host.escape_debug(), port)?;
                Ok(())
            }
        }
    }
}

impl fmt::Display for PeerAddr {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerAddr::Inet(addr) => fmt::Display::fmt(addr, w),
            PeerAddr::Onion((host, port)) => {
                write!(w, "{host}:{port}")?;
                Ok(())
            }
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
                if !host.chars().all(|c| c.is_alphanumeric() || c == '.') {
                    bail!("Onion address contains invalid characters");
                }
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

impl Serialize for PeerAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            PeerAddr::Inet(addr) => {
                let addr = addr.to_string();
                addr.serialize(serializer)
            }
            PeerAddr::Onion((host, port)) => format!("{host}:{port}").serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for PeerAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: String = Deserialize::deserialize(deserializer)?;
        value
            .parse()
            .map_err(|err| serde::de::Error::custom(format!("{err:#}")))
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
            0
        );
        assert_eq!(
            base.xor_distance(&"192.168.1.2:443".parse::<PeerAddr>().unwrap()),
            0
        );
        assert_eq!(
            base.xor_distance(&"192.168.1.1:16169".parse::<PeerAddr>().unwrap()),
            3 << 95
        );
        assert_eq!(
            base.xor_distance(&"192.168.1.3:16169".parse::<PeerAddr>().unwrap()),
            1 << 95
        );
        assert_eq!(
            base.xor_distance(&"192.168.2.0:16169".parse::<PeerAddr>().unwrap()),
            770 << 95
        );
        assert_eq!(
            base.xor_distance(&"1.0.0.1:16169".parse::<PeerAddr>().unwrap()),
            3_249_012_995 << 95
        );
        assert_eq!(
            base.xor_distance(&"255.255.255.255:16169".parse::<PeerAddr>().unwrap()),
            1_062_731_517 << 95
        );
        assert_eq!(
            base.xor_distance(
                &"[2001:db8:3333:4444:5555:6666:7777:8888]:16169"
                    .parse::<PeerAddr>()
                    .unwrap()
            ),
            319_453_597_143_525_594_717_699_116_388_956_488_772,
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
            0
        );
        assert_eq!(
            base.xor_distance(
                &"[2001:db8:3333:4444:5555:6666:7777:8888]:443"
                    .parse::<PeerAddr>()
                    .unwrap()
            ),
            0
        );
        assert_eq!(
            base.xor_distance(&"[2001:db8::]:16169".parse::<PeerAddr>().unwrap()),
            7_922_856_549_568_655_098_759_595_076
        );
        assert_eq!(
            base.xor_distance(&"[fe80::1a2b:3c4d:5e6f]:16169".parse::<PeerAddr>().unwrap()),
            147_879_349_812_077_389_872_108_282_106_859_055_987
        );
        assert_eq!(
            base.xor_distance(&"192.168.1.3:16169".parse::<PeerAddr>().unwrap()),
            319_453_597_183_139_675_974_831_285_185_728_463_940
        );
    }

    #[test]
    fn test_peer_addr_serialize() {
        let addr =
            serde_json::to_string(&PeerAddr::Inet("[2001:db8::]:16169".parse().unwrap())).unwrap();
        assert_eq!(addr, "\"[2001:db8::]:16169\"");

        let addr = serde_json::to_string(&PeerAddr::Onion((
            "3wisi2bfpxplne5wlwz4l5ucvsbaozbteaqnm62oxzmgwhb2qqxvsuyd.onion".to_string(),
            16169,
        )))
        .unwrap();
        assert_eq!(
            addr,
            "\"3wisi2bfpxplne5wlwz4l5ucvsbaozbteaqnm62oxzmgwhb2qqxvsuyd.onion:16169\""
        );
    }

    #[test]
    fn test_peer_addr_deserialize() {
        let addr = serde_json::from_str::<PeerAddr>("\"[2001:db8::]:16169\"").unwrap();
        assert_eq!(addr, PeerAddr::Inet("[2001:db8::]:16169".parse().unwrap()));

        let addr = serde_json::from_str::<PeerAddr>(
            "\"3wisi2bfpxplne5wlwz4l5ucvsbaozbteaqnm62oxzmgwhb2qqxvsuyd.onion:16169\"",
        )
        .unwrap();
        assert_eq!(
            addr,
            PeerAddr::Onion((
                "3wisi2bfpxplne5wlwz4l5ucvsbaozbteaqnm62oxzmgwhb2qqxvsuyd.onion".to_string(),
                16169
            ))
        );
    }

    #[test]
    fn test_peer_addr_debug_inet() {
        let addr = PeerAddr::Inet("[2001:db8::]:16169".parse().unwrap());
        assert_eq!(format!("{addr:?}"), "[2001:db8::]:16169");
    }

    #[test]
    fn test_peer_addr_debug_onion() {
        let addr = PeerAddr::Onion((
            "3wisi2bfpxplne5wlwz4l5ucvsbaozbteaqnm62oxzmgwhb2qqxvsuyd.onion".to_string(),
            16169,
        ));
        assert_eq!(
            format!("{addr:?}"),
            "\"3wisi2bfpxplne5wlwz4l5ucvsbaozbteaqnm62oxzmgwhb2qqxvsuyd.onion:16169\""
        );
    }

    #[test]
    fn test_detect_invalid_onion_address() {
        let addr = "3wisi2b\nfpxplne5wlwz4l5ucvsbaozbteaqnm62oxzmgwhb2qqxvsuyd.onion:16169";
        assert!(addr.parse::<PeerAddr>().is_err());
    }
}
