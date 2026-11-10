//! The netlink messages of the rules of the routing policy.

use netlink_packet_route::rule::{
    RuleAction as NetlinkRuleAction, RuleAttribute, RuleFlags, RuleMessage, RulePortRange,
    RuleUidRange,
};

use super::address_family;
use crate::{Rule, RuleAction};

/// RT_TABLE_UNSPEC, for a table that only fits in the attribute.
const TABLE_UNSPEC: u8 = 0;

/// A message that adds `rule`, or deletes the rule that it selects.
pub(super) fn rule_message(rule: &Rule) -> RuleMessage {
    let mut message = RuleMessage::default();
    let header = &mut message.header;
    header.family = address_family(rule.from);
    header.src_len = rule.from_prefix;
    header.dst_len = rule.to_prefix;
    if rule.invert {
        header.flags = RuleFlags::Invert;
    }
    header.action = match rule.action {
        RuleAction::Lookup(table) => {
            // Tables above 255 only fit in the attribute.
            header.table = u8::try_from(table).unwrap_or(TABLE_UNSPEC);
            if table > u32::from(u8::MAX) {
                message.attributes.push(RuleAttribute::Table(table));
            }
            NetlinkRuleAction::ToTable
        }
        RuleAction::Blackhole => NetlinkRuleAction::Blackhole,
        RuleAction::Unreachable => NetlinkRuleAction::Unreachable,
        RuleAction::Prohibit => NetlinkRuleAction::Prohibit,
    };

    let attributes = &mut message.attributes;
    if rule.from_prefix > 0 {
        attributes.push(RuleAttribute::Source(rule.from));
    }
    if rule.to_prefix > 0 {
        attributes.push(RuleAttribute::Destination(rule.to));
    }
    if let Some(priority) = rule.priority {
        attributes.push(RuleAttribute::Priority(priority));
    }
    if let Some((mark, mask)) = rule.fwmark {
        attributes.push(RuleAttribute::FwMark(mark));
        attributes.push(RuleAttribute::FwMask(mask));
    }
    if let Some(name) = &rule.iif {
        attributes.push(RuleAttribute::Iifname(name.clone()));
    }
    if let Some(name) = &rule.oif {
        attributes.push(RuleAttribute::Oifname(name.clone()));
    }
    if let Some(uids) = &rule.uid_range {
        attributes.push(RuleAttribute::UidRange(RuleUidRange {
            start: *uids.start(),
            end: *uids.end(),
        }));
    }
    if let Some(protocol) = rule.ip_proto {
        attributes.push(RuleAttribute::IpProtocol(protocol.into()));
    }
    if let Some(ports) = &rule.sport {
        attributes.push(RuleAttribute::SourcePortRange(port_range(ports)));
    }
    if let Some(ports) = &rule.dport {
        attributes.push(RuleAttribute::DestinationPortRange(port_range(ports)));
    }
    if let Some(prefix) = rule.suppress_prefixlength {
        attributes.push(RuleAttribute::SuppressPrefixLen(prefix.into()));
    }

    message
}

fn port_range(ports: &std::ops::RangeInclusive<u16>) -> RulePortRange {
    RulePortRange {
        start: *ports.start(),
        end: *ports.end(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use netlink_packet_core::{Emitable, Parseable};
    use netlink_packet_route::{AddressFamily, IpProtocol, rule::RuleMessageBuffer};

    use super::*;
    use crate::TABLE_MAIN;

    /// `rule` as the kernel reads it off the wire.
    fn on_the_wire(rule: &Rule) -> RuleMessage {
        let message = rule_message(rule);
        let mut bytes = vec![0; message.buffer_len()];
        message.emit(&mut bytes);
        RuleMessage::parse(&RuleMessageBuffer::new(&bytes)).unwrap()
    }

    #[test]
    fn suppress_rule_looks_up_main_in_the_header() {
        let message = on_the_wire(&Rule::v4().priority(5200).suppress_prefixlength(0));

        assert_eq!(message.header.family, AddressFamily::Inet);
        assert_eq!(message.header.action, NetlinkRuleAction::ToTable);
        assert_eq!(message.header.table, TABLE_MAIN as u8);
        assert_eq!((message.header.src_len, message.header.dst_len), (0, 0));
        assert_eq!(message.header.flags, RuleFlags::empty());
        assert_eq!(
            message.attributes,
            [
                RuleAttribute::Priority(5200),
                RuleAttribute::SuppressPrefixLen(0)
            ]
        );
    }

    #[test]
    fn inverted_fwmark_rule_looks_up_a_table_above_255_in_the_attribute() {
        let rule = Rule::v6()
            .priority(5210)
            .invert()
            .fwmark(0x5100, u32::MAX)
            .action(RuleAction::Lookup(51888));

        let message = on_the_wire(&rule);

        assert_eq!(message.header.family, AddressFamily::Inet6);
        assert_eq!(message.header.flags, RuleFlags::Invert);
        assert_eq!(message.header.action, NetlinkRuleAction::ToTable);
        assert_eq!(message.header.table, TABLE_UNSPEC);
        assert_eq!(
            message.attributes,
            [
                RuleAttribute::Table(51888),
                RuleAttribute::Priority(5210),
                RuleAttribute::FwMark(0x5100),
                RuleAttribute::FwMask(u32::MAX),
            ]
        );
    }

    #[test]
    fn every_selector_is_on_the_wire() {
        let from = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0));
        let to = IpAddr::V4(Ipv4Addr::new(198, 19, 1, 0));
        let rule = Rule::v4()
            .from(from, 15)
            .to(to, 24)
            .fwmark(0x5100, 0xff00)
            .iif("lo")
            .oif("Hymn")
            .uid_range(1000..=1999)
            .ip_proto(17)
            .sport(1024..=2048)
            .dport(53..=53)
            .action(RuleAction::Lookup(200));

        let message = on_the_wire(&rule);

        assert_eq!((message.header.src_len, message.header.dst_len), (15, 24));
        assert_eq!(message.header.table, 200);
        assert_eq!(
            message.attributes,
            [
                RuleAttribute::Source(from),
                RuleAttribute::Destination(to),
                RuleAttribute::FwMark(0x5100),
                RuleAttribute::FwMask(0xff00),
                RuleAttribute::Iifname("lo".into()),
                RuleAttribute::Oifname("Hymn".into()),
                RuleAttribute::UidRange(RuleUidRange {
                    start: 1000,
                    end: 1999
                }),
                RuleAttribute::IpProtocol(IpProtocol::Udp),
                RuleAttribute::SourcePortRange(RulePortRange {
                    start: 1024,
                    end: 2048
                }),
                RuleAttribute::DestinationPortRange(RulePortRange { start: 53, end: 53 }),
            ]
        );
    }

    #[test]
    fn ipv6_prefixes_are_on_the_wire() {
        let from = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        let message = on_the_wire(&Rule::v6().from(from, 32));

        assert_eq!(message.header.src_len, 32);
        assert_eq!(message.attributes, [RuleAttribute::Source(from)]);
    }

    #[test]
    fn rules_that_drop_name_no_table() {
        for (action, expected) in [
            (RuleAction::Blackhole, NetlinkRuleAction::Blackhole),
            (RuleAction::Unreachable, NetlinkRuleAction::Unreachable),
            (RuleAction::Prohibit, NetlinkRuleAction::Prohibit),
        ] {
            let message = on_the_wire(&Rule::v4().priority(1).action(action));
            assert_eq!(message.header.action, expected);
            assert_eq!(message.header.table, TABLE_UNSPEC);
            assert_eq!(message.attributes, [RuleAttribute::Priority(1)]);
        }
    }
}
