//! Host-controlled outbound probe policy. Never trust a hub's target string.
use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

#[derive(Clone, Default)]
pub(crate) struct Policy(Vec<Rule>);
#[derive(Clone)]
struct Rule {
    network: IpAddr,
    prefix: u8,
    port: Option<u16>,
}

pub(crate) fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        _ => ip,
    }
}

pub(crate) fn normalize(target: &str) -> Result<(String, u16, String)> {
    if target.len() > 320 || target.chars().any(char::is_control) {
        bail!("invalid probe target");
    }
    let target = target.trim();
    let (host, port) = if let Some(v6) = target.strip_prefix('[') {
        let (host, port) = v6.split_once("]:").context("IPv6 target needs [address]:port")?;
        (unmapped(host.parse::<Ipv6Addr>().context("invalid IPv6 target")?.into()).to_string(), port)
    } else {
        let (host, port) = target.rsplit_once(':').context("target needs host:port")?;
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty()
            || host.len() > 253
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            bail!("invalid probe hostname");
        }
        (host, port)
    };
    let port: u16 = port.parse().context("invalid probe port")?;
    if port == 0 {
        bail!("probe port must be nonzero");
    }
    let normalized = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    Ok((host, port, normalized))
}

impl Policy {
    /// Comma-separated IP or CIDR, optionally followed by @port. IPv6 is
    /// unbracketed here; @ keeps its port suffix unambiguous.
    pub(crate) fn parse(input: &str) -> Result<Self> {
        if input.len() > 8192 || input.chars().any(char::is_control) {
            bail!("invalid probe allowlist");
        }
        let mut rules = Vec::new();
        for entry in input.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if rules.len() >= 128 {
                bail!("too many probe allow rules");
            }
            let (cidr, port) = match entry.rsplit_once('@') {
                Some((cidr, port)) => {
                    let port = port.parse::<u16>().context("invalid allowlist port")?;
                    if port == 0 {
                        bail!("allowlist port must be nonzero");
                    }
                    (cidr, Some(port))
                }
                None => (entry, None),
            };
            let (ip, prefix) = cidr.split_once('/').map_or((cidr, None), |(ip, n)| (ip, Some(n)));
            let ip: IpAddr = ip.parse().context("allowlist needs IP or CIDR")?;
            let width = if ip.is_ipv4() { 32 } else { 128 };
            let prefix =
                prefix.map(str::parse::<u8>).transpose().context("invalid CIDR prefix")?.unwrap_or(width);
            if prefix > width {
                bail!("invalid CIDR prefix");
            }
            // Avoid ambiguous mapped-v6 masks; use the IPv4 CIDR spelling.
            if unmapped(ip) != ip {
                bail!("use IPv4 CIDR for mapped IPv6");
            }
            rules.push(Rule { network: ip, prefix, port });
        }
        Ok(Self(rules))
    }

    pub(crate) fn allows(&self, address: SocketAddr) -> bool {
        let ip = unmapped(address.ip());
        self.0.iter().any(|r| {
            r.port.is_none_or(|port| port == address.port())
                && match (r.network, ip) {
                    (IpAddr::V4(net), IpAddr::V4(ip)) => {
                        let shift = 32 - u32::from(r.prefix);
                        (u32::from(net) as u64 >> shift) == (u32::from(ip) as u64 >> shift)
                    }
                    (IpAddr::V6(net), IpAddr::V6(ip)) => {
                        r.prefix == 0
                            || (u128::from(net) >> (128 - r.prefix)) == (u128::from(ip) >> (128 - r.prefix))
                    }
                    _ => false,
                }
        }) || public_destination(ip)
    }
}

fn public_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254) || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || b == 0 || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113)
                // Azure platform virtual IP; metadata/link-local is covered above.
                || ip.octets() == [168, 63, 129, 16])
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            // Conservative globally routed unicast only; reject transition,
            // documentation, Teredo and 6to4 ranges which can embed private v4.
            segments[0] & 0xe000 == 0x2000
                && !(segments[0] == 0x2001 && (segments[1] < 0x200 || segments[1] == 0xdb8))
                && segments[0] != 0x2002
                && !(segments[0] == 0x3fff && segments[1] < 0x1000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deny_sensitive_and_mapped_addresses_unless_locally_opted_in() {
        let policy = Policy::default();
        for addr in [
            "127.0.0.1:80",
            "10.1.2.3:443",
            "169.254.169.254:80",
            "[::1]:80",
            "[fd00::1]:80",
            "[::ffff:10.1.2.3]:443",
            "168.63.129.16:80",
            "[2002:a00:1::]:80",
        ] {
            assert!(!policy.allows(addr.parse().unwrap()), "{addr}");
        }
        assert!(policy.allows("8.8.8.8:443".parse().unwrap()));
        let local = Policy::parse("10.0.0.0/8@443,fd00::/8@8443").unwrap();
        assert!(local.allows("[::ffff:10.1.2.3]:443".parse().unwrap()));
        assert!(!local.allows("10.1.2.3:80".parse().unwrap()));
        assert!(local.allows("[fd01::2]:8443".parse().unwrap()));
    }
    #[test]
    fn targets_are_canonical_and_reject_controls_and_oversize() {
        assert_eq!(normalize(" EXAMPLE.COM.:00080 ").unwrap().2, "example.com:80");
        assert_eq!(normalize("[0:0::1]:80").unwrap().2, "[::1]:80");
        assert_eq!(normalize("[::ffff:10.1.2.3]:80").unwrap().2, "10.1.2.3:80");
        for bad in ["a\n:80", "a:0", "a:65536", "http://a:80", "a@b:80", "a :80"] {
            assert!(normalize(bad).is_err());
        }
        assert!(normalize(&format!("{}:80", "a".repeat(321))).is_err());
    }
}
