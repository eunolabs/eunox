//! IP prefixes and range sets, as published by agent operators.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// An IPv4 or IPv6 prefix such as `20.171.206.0/24`.
///
/// Host bits are cleared on construction, so `10.0.0.7/8` equals `10.0.0.0/8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

/// Why a prefix string was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpNetError(String);

impl fmt::Display for IpNetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IP prefix: {}", self.0)
    }
}

impl std::error::Error for IpNetError {}

impl IpNet {
    /// Build a prefix, rejecting a length longer than the address.
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, IpNetError> {
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(IpNetError(format!("{addr}/{prefix}")));
        }
        let addr = match addr {
            IpAddr::V4(a) => IpAddr::V4((u32::from(a) & mask_v4(prefix)).into()),
            IpAddr::V6(a) => IpAddr::V6((u128::from(a) & mask_v6(prefix)).into()),
        };
        Ok(Self { addr, prefix })
    }

    /// Whether `ip` falls inside this prefix. IPv4-mapped IPv6 addresses
    /// (`::ffff:1.2.3.4`) match IPv4 prefixes, since that's how a dual-stack
    /// listener often reports an IPv4 client.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                u32::from(ip) & mask_v4(self.prefix) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                u128::from(ip) & mask_v6(self.prefix) == u128::from(net)
            }
            _ => false,
        }
    }
}

impl FromStr for IpNet {
    type Err = IpNetError;

    /// Parse `addr/len`, or a bare address as a single-host prefix.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || IpNetError(s.to_owned());
        let (addr, prefix) = match s.trim().split_once('/') {
            Some((a, p)) => (
                a.parse::<IpAddr>().map_err(|_| bad())?,
                Some(p.parse::<u8>().map_err(|_| bad())?),
            ),
            None => (s.trim().parse::<IpAddr>().map_err(|_| bad())?, None),
        };
        let prefix = prefix.unwrap_or(if addr.to_canonical().is_ipv4() {
            32
        } else {
            128
        });
        Self::new(addr, prefix)
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn mask_v4(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask_v6(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

/// Published IP range sets, keyed by the set id an [`crate::Agent`] names.
/// Implemented by the `directory` crate.
pub trait IpRanges {
    /// Whether `ip` is in range set `set`, or `None` if that set hasn't been
    /// loaded (yet). `None` must never be read as "not in range": at startup,
    /// before the first fetch, that would mark every real crawler as spoofed.
    fn contains(&self, set: &str, ip: IpAddr) -> Option<bool>;
}

impl IpRanges for HashMap<String, Vec<IpNet>> {
    fn contains(&self, set: &str, ip: IpAddr) -> Option<bool> {
        self.get(set)
            .map(|nets| nets.iter().any(|n| n.contains(ip)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_prefixes() {
        let net: IpNet = "20.171.206.0/24".parse().unwrap();
        assert!(net.contains(ip("20.171.206.1")));
        assert!(net.contains(ip("20.171.206.255")));
        assert!(!net.contains(ip("20.171.207.0")));
        assert!(!net.contains(ip("::1")));
    }

    #[test]
    fn host_bits_are_cleared() {
        let a: IpNet = "10.1.2.3/8".parse().unwrap();
        assert_eq!(a, "10.0.0.0/8".parse().unwrap());
        assert_eq!(a.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn edge_lengths() {
        let all: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(ip("255.255.255.255")));
        let host: IpNet = "1.2.3.4".parse().unwrap();
        assert!(host.contains(ip("1.2.3.4")));
        assert!(!host.contains(ip("1.2.3.5")));
        let all6: IpNet = "::/0".parse().unwrap();
        assert!(all6.contains(ip("2001:db8::1")));
    }

    #[test]
    fn v6_prefixes() {
        let net: IpNet = "2600:1f28:365:80b0::/60".parse().unwrap();
        assert!(net.contains(ip("2600:1f28:365:80bf:ffff::1")));
        assert!(!net.contains(ip("2600:1f28:365:80c0::1")));
    }

    #[test]
    fn v4_mapped_v6_client_matches_v4_prefix() {
        let net: IpNet = "66.249.64.0/19".parse().unwrap();
        assert!(net.contains(ip("::ffff:66.249.66.1")));
    }

    #[test]
    fn rejects_bad_prefixes() {
        for bad in ["1.2.3.0/33", "::/129", "1.2.3/24", "nope", "1.2.3.4/x", ""] {
            assert!(bad.parse::<IpNet>().is_err(), "{bad}");
        }
    }

    #[test]
    fn unloaded_set_is_unknown_not_false() {
        let mut sets: HashMap<String, Vec<IpNet>> = HashMap::new();
        sets.insert("a".into(), vec!["1.2.3.0/24".parse().unwrap()]);
        assert_eq!(sets.contains("a", ip("1.2.3.4")), Some(true));
        assert_eq!(sets.contains("a", ip("9.9.9.9")), Some(false));
        assert_eq!(sets.contains("b", ip("1.2.3.4")), None);
    }
}
