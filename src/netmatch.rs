use std::net::IpAddr;

/// A single IP or CIDR range (IPv4 or IPv6) parsed from configuration.
/// A bare IP (`1.2.3.4`, `::1`) is treated as a full-length prefix.
#[derive(Clone, Debug)]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

impl IpCidr {
    /// Parse `"1.2.3.4"`, `"10.0.0.0/8"`, `"::1"` or `"2001:db8::/32"`.
    /// Returns `None` for empty/invalid input or an out-of-range prefix.
    pub fn parse(s: &str) -> Option<IpCidr> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (addr_s, prefix_s) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_s.parse().ok()?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix_s {
            Some(p) => {
                let v: u8 = p.parse().ok()?;
                if v > max {
                    return None;
                }
                v
            }
            None => max,
        };
        Some(IpCidr { addr, prefix })
    }

    /// Whether `ip` falls inside this range. Address families never match
    /// across each other (an IPv4 range does not contain IPv6 addresses).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                self.prefix == 0
                    || (u32::from(net) ^ u32::from(ip)) >> (32 - self.prefix as u32) == 0
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                self.prefix == 0
                    || (u128::from(net) ^ u128::from(ip)) >> (128 - self.prefix as u32) == 0
            }
            _ => false,
        }
    }
}

/// Parse a comma-separated list of IPs/CIDRs, skipping (and logging) invalid entries.
pub fn parse_cidr_list(s: &str) -> Vec<IpCidr> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .filter_map(|p| match IpCidr::parse(p) {
            Some(c) => Some(c),
            None => {
                tracing::warn!(entry = p, "Ignoring invalid IP/CIDR in configuration");
                None
            }
        })
        .collect()
}

/// Whether the textual IP `ip_str` matches any range in `list`.
/// Unparseable IPs never match (fail open for allowlists, fail closed for denylists
/// is the caller's concern; both lists simply see "no match").
pub fn ip_in_list(ip_str: &str, list: &[IpCidr]) -> bool {
    if list.is_empty() {
        return false;
    }
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    list.iter().any(|c| c.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_ips() {
        assert!(IpCidr::parse("1.2.3.4").is_some());
        assert!(IpCidr::parse("::1").is_some());
        assert!(IpCidr::parse(" 8.8.8.8 ").is_some());
    }

    #[test]
    fn parses_cidrs() {
        assert!(IpCidr::parse("10.0.0.0/8").is_some());
        assert!(IpCidr::parse("192.168.1.0/24").is_some());
        assert!(IpCidr::parse("2001:db8::/32").is_some());
        assert!(IpCidr::parse("0.0.0.0/0").is_some());
    }

    #[test]
    fn rejects_invalid() {
        assert!(IpCidr::parse("").is_none());
        assert!(IpCidr::parse("not-an-ip").is_none());
        assert!(IpCidr::parse("1.2.3.4/33").is_none());
        assert!(IpCidr::parse("::1/129").is_none());
        assert!(IpCidr::parse("1.2.3.4/abc").is_none());
    }

    #[test]
    fn bare_ip_matches_only_itself() {
        let c = IpCidr::parse("1.2.3.4").unwrap();
        assert!(c.contains("1.2.3.4".parse().unwrap()));
        assert!(!c.contains("1.2.3.5".parse().unwrap()));
    }

    #[test]
    fn v4_cidr_matching() {
        let c = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(c.contains("10.255.255.255".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));

        let c24 = IpCidr::parse("192.168.1.0/24").unwrap();
        assert!(c24.contains("192.168.1.200".parse().unwrap()));
        assert!(!c24.contains("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn v6_cidr_matching() {
        let c = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains("2001:db8::1".parse().unwrap()));
        assert!(c.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!c.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn zero_prefix_matches_everything_in_family() {
        let c = IpCidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains("255.255.255.255".parse().unwrap()));
        assert!(c.contains("1.2.3.4".parse().unwrap()));
        // ...but not the other family.
        assert!(!c.contains("::1".parse().unwrap()));
    }

    #[test]
    fn families_do_not_cross_match() {
        let v4 = IpCidr::parse("1.2.3.4").unwrap();
        assert!(!v4.contains("::ffff:102:304".parse().unwrap()));
        let v6 = IpCidr::parse("::1").unwrap();
        assert!(!v6.contains("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn list_parsing_skips_invalid_entries() {
        let list = parse_cidr_list("1.2.3.4, bogus, 10.0.0.0/8,, ::1");
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn ip_in_list_matching() {
        let list = parse_cidr_list("10.0.0.0/8,192.168.1.5");
        assert!(ip_in_list("10.9.9.9", &list));
        assert!(ip_in_list("192.168.1.5", &list));
        assert!(!ip_in_list("8.8.8.8", &list));
        assert!(!ip_in_list("garbage", &list));
        assert!(!ip_in_list("10.0.0.1", &[]));
    }
}
