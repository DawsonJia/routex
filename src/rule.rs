//! The rules of the routing policy, which choose the tables a packet is
//! routed by.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use crate::TABLE_MAIN;

/// The longest interface name, `IFNAMSIZ` less its terminating NUL.
const MAX_IFNAME_LEN: usize = 15;

/// A rule of the routing policy: the packets it selects take its `action`.
/// The kernel tries the rules of the family of a packet by priority, lowest
/// first, until one routes or drops the packet.
///
/// Every selector a rule leaves unset, a prefix of 0 included, selects every
/// packet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rule {
    /// Where among the rules it is tried. The kernel picks one when unset,
    /// so a rule with its own can be told apart from the others, and deleted
    /// by it.
    pub priority: Option<u32>,
    /// Packets from `from/from_prefix`. The family of `from` is the rule's.
    pub from: IpAddr,
    pub from_prefix: u8,
    /// Packets to `to/to_prefix`, of the family of `from`.
    pub to: IpAddr,
    pub to_prefix: u8,
    /// Packets whose firewall mark, under the mask, is the mark: `(mark,
    /// mask)`.
    pub fwmark: Option<(u32, u32)>,
    /// Packets that came in on the interface of this name, `lo` for those
    /// of the host. The interface need not exist yet.
    pub iif: Option<String>,
    /// Packets of a socket bound to the interface of this name
    /// (`SO_BINDTODEVICE`). The interface need not exist yet.
    pub oif: Option<String>,
    /// Packets of a socket of a user in this range; the kernel takes the
    /// uids below `u32::MAX`.
    pub uid_range: Option<RangeInclusive<u32>>,
    /// Packets of this IP protocol, an `IPPROTO_*`.
    pub ip_proto: Option<u8>,
    /// Packets from a port in this range; the kernel takes the ports 1 to
    /// 65534.
    pub sport: Option<RangeInclusive<u16>>,
    /// Packets to a port in this range, of the ports 1 to 65534.
    pub dport: Option<RangeInclusive<u16>>,
    /// Selects the packets the selectors above do not (`not`).
    pub invert: bool,
    pub action: RuleAction,
    /// Rejects a route the lookup finds whose prefix is this long or
    /// shorter, so that the rules after go on; 0 rejects the default route.
    pub suppress_prefixlength: Option<u8>,
}

/// What a packet that a [`Rule`] selects takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleAction {
    /// Routes it by this table. When the table has no route for it, or
    /// throws it, the rules after go on.
    Lookup(u32),
    /// Drops it; a local sender gets `EINVAL`.
    Blackhole,
    /// Drops it as unreachable; a local sender gets `ENETUNREACH`.
    Unreachable,
    /// Drops it as prohibited; a local sender gets `EACCES`.
    Prohibit,
}

impl Rule {
    /// The IPv4 rule that selects every packet and looks up the main table,
    /// as `ip rule add` does without arguments.
    pub fn v4() -> Rule {
        Rule::all(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    /// The IPv6 rule that selects every packet and looks up the main table.
    pub fn v6() -> Rule {
        Rule::all(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    }

    fn all(unspecified: IpAddr) -> Rule {
        Rule {
            priority: None,
            from: unspecified,
            from_prefix: 0,
            to: unspecified,
            to_prefix: 0,
            fwmark: None,
            iif: None,
            oif: None,
            uid_range: None,
            ip_proto: None,
            sport: None,
            dport: None,
            invert: false,
            action: RuleAction::Lookup(TABLE_MAIN),
            suppress_prefixlength: None,
        }
    }

    pub fn priority(mut self, priority: u32) -> Rule {
        self.priority = Some(priority);
        self
    }

    pub fn from(mut self, from: IpAddr, prefix: u8) -> Rule {
        self.from = from;
        self.from_prefix = prefix;
        self
    }

    pub fn to(mut self, to: IpAddr, prefix: u8) -> Rule {
        self.to = to;
        self.to_prefix = prefix;
        self
    }

    /// Packets whose mark, under `mask`, is `mark`; `u32::MAX` compares the
    /// whole mark.
    pub fn fwmark(mut self, mark: u32, mask: u32) -> Rule {
        self.fwmark = Some((mark, mask));
        self
    }

    pub fn iif(mut self, name: impl Into<String>) -> Rule {
        self.iif = Some(name.into());
        self
    }

    pub fn oif(mut self, name: impl Into<String>) -> Rule {
        self.oif = Some(name.into());
        self
    }

    pub fn uid_range(mut self, uids: RangeInclusive<u32>) -> Rule {
        self.uid_range = Some(uids);
        self
    }

    pub fn ip_proto(mut self, protocol: u8) -> Rule {
        self.ip_proto = Some(protocol);
        self
    }

    pub fn sport(mut self, ports: RangeInclusive<u16>) -> Rule {
        self.sport = Some(ports);
        self
    }

    pub fn dport(mut self, ports: RangeInclusive<u16>) -> Rule {
        self.dport = Some(ports);
        self
    }

    /// Selects the packets that the selectors do not.
    pub fn invert(mut self) -> Rule {
        self.invert = true;
        self
    }

    pub fn action(mut self, action: RuleAction) -> Rule {
        self.action = action;
        self
    }

    pub fn suppress_prefixlength(mut self, prefix: u8) -> Rule {
        self.suppress_prefixlength = Some(prefix);
        self
    }

    /// The longest prefix of the family of the rule.
    fn max_prefix(&self) -> u8 {
        match self.from {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        let invalid = |message: String| Err(io::Error::new(io::ErrorKind::InvalidInput, message));

        if std::mem::discriminant(&self.from) != std::mem::discriminant(&self.to) {
            return invalid(format!(
                "rule from {} to {} mixes address families",
                self.from, self.to
            ));
        }
        for (address, prefix) in [(self.from, self.from_prefix), (self.to, self.to_prefix)] {
            if prefix > self.max_prefix() {
                return invalid(format!("invalid prefix {prefix} for {address}"));
            }
        }
        if let Some(prefix) = self.suppress_prefixlength
            && prefix > self.max_prefix()
        {
            return invalid(format!("invalid suppress_prefixlength {prefix}"));
        }

        // The kernel takes both for no selector, which selects every packet.
        if let Some((_, 0)) = self.fwmark {
            return invalid("a fwmark under mask 0 selects every packet".into());
        }
        if self.ip_proto == Some(0) {
            return invalid("IP protocol 0 selects every packet".into());
        }

        // Only the bounds of a range go to the kernel, and those of one that
        // was iterated to its end are not empty.
        if let Some(uids) = &self.uid_range
            && uids.is_empty()
        {
            return invalid(format!("empty uid_range {uids:?}"));
        }
        for ports in [&self.sport, &self.dport].into_iter().flatten() {
            if ports.is_empty() {
                return invalid(format!("empty port range {ports:?}"));
            }
        }

        for name in [&self.iif, &self.oif].into_iter().flatten() {
            if name.is_empty() || name.len() > MAX_IFNAME_LEN || name.contains('\0') {
                return invalid(format!("invalid interface name {name:?}"));
            }
        }

        if self.action == RuleAction::Lookup(0) {
            return invalid("table 0 is not a table".into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_invalid(rule: Rule) {
        assert_eq!(
            rule.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "{rule:?}"
        );
    }

    #[test]
    fn a_rule_is_of_one_family() {
        let v4 = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));

        assert!(Rule::v4().from(v4, 15).to(v4, 24).validate().is_ok());
        assert!(Rule::v6().from(v6, 32).validate().is_ok());
        assert_invalid(Rule::v4().from(v6, 32));
        assert_invalid(Rule::v6().to(v4, 15));
    }

    #[test]
    fn prefixes_fit_the_family() {
        let v4 = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0));

        assert!(
            Rule::v4()
                .from(v4, 32)
                .suppress_prefixlength(32)
                .validate()
                .is_ok()
        );
        assert!(Rule::v6().suppress_prefixlength(128).validate().is_ok());
        assert_invalid(Rule::v4().from(v4, 33));
        assert_invalid(Rule::v4().to(v4, 33));
        assert_invalid(Rule::v4().suppress_prefixlength(33));
        assert_invalid(Rule::v6().suppress_prefixlength(129));
    }

    #[test]
    fn a_selector_that_would_select_every_packet_is_invalid() {
        assert!(Rule::v4().fwmark(0, u32::MAX).validate().is_ok());
        assert!(Rule::v4().ip_proto(17).validate().is_ok());
        assert_invalid(Rule::v4().fwmark(0x5100, 0));
        assert_invalid(Rule::v4().ip_proto(0));
    }

    #[test]
    fn a_range_selects_some_value() {
        let mut uids = 1000..=1000;
        let mut ports = 53..=53;
        assert!(
            Rule::v4()
                .uid_range(uids.clone())
                .sport(ports.clone())
                .dport(ports.clone())
                .validate()
                .is_ok()
        );
        uids.next();
        ports.next();

        assert_invalid(Rule::v4().uid_range(uids));
        assert_invalid(Rule::v4().uid_range(RangeInclusive::new(5, 4)));
        assert_invalid(Rule::v4().sport(ports.clone()));
        assert_invalid(Rule::v4().dport(ports));
        assert_invalid(Rule::v6().dport(RangeInclusive::new(100, 50)));
    }

    #[test]
    fn interface_names_fit_ifnamsiz() {
        assert!(Rule::v4().iif("lo").oif("a".repeat(15)).validate().is_ok());
        assert_invalid(Rule::v4().iif(""));
        assert_invalid(Rule::v4().oif("a".repeat(16)));
        assert_invalid(Rule::v4().iif("l\0o"));
    }

    #[test]
    fn a_lookup_names_a_table() {
        assert!(
            Rule::v4()
                .action(RuleAction::Lookup(51888))
                .validate()
                .is_ok()
        );
        assert_invalid(Rule::v4().action(RuleAction::Lookup(0)));
    }
}
