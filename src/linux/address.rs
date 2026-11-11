//! The netlink messages of the addresses of an interface.

use std::net::IpAddr;

use netlink_packet_route::address::{AddressAttribute, AddressMessage, AddressScope};

use super::address_family;
use crate::Address;

/// A message that adds `address` to its interface, or deletes it from it.
pub(super) fn address_message(address: &Address) -> AddressMessage {
    let mut message = AddressMessage::default();
    message.header.family = address_family(address.ip);
    message.header.prefix_len = address.prefix;
    // As `ip addr` has it: an address of the loopback net is the host's own,
    // and no source for what leaves the host. The kernel finds the scope of
    // an IPv6 address itself.
    message.header.scope = match address.ip {
        IpAddr::V4(ip) if ip.is_loopback() => AddressScope::Host,
        _ => AddressScope::Universe,
    };
    message.header.index = address.ifindex;
    // IFA_ADDRESS is the peer of a point-to-point address, and of any other
    // the address itself, which IFA_LOCAL always is.
    message.attributes.push(AddressAttribute::Address(
        address.peer.unwrap_or(address.ip),
    ));
    message.attributes.push(AddressAttribute::Local(address.ip));

    message
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use netlink_packet_core::{Emitable, Parseable};
    use netlink_packet_route::{AddressFamily, address::AddressMessageBuffer};

    use super::*;

    /// `address` as the kernel reads it off the wire.
    fn on_the_wire(address: &Address) -> AddressMessage {
        let message = address_message(address);
        let mut bytes = vec![0; message.buffer_len()];
        message.emit(&mut bytes);
        AddressMessage::parse(&AddressMessageBuffer::new(&bytes)).unwrap()
    }

    #[test]
    fn an_address_without_a_peer_is_its_own_ifa_address() {
        let v4 = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        for (ip, prefix, family) in [
            (v4, 24, AddressFamily::Inet),
            (v6, 64, AddressFamily::Inet6),
        ] {
            let message = on_the_wire(&Address::new(7, ip, prefix));

            assert_eq!(message.header.family, family);
            assert_eq!(message.header.prefix_len, prefix);
            assert_eq!(message.header.scope, AddressScope::Universe);
            assert_eq!(message.header.index, 7);
            assert_eq!(
                message.attributes,
                [AddressAttribute::Address(ip), AddressAttribute::Local(ip)]
            );
        }
    }

    #[test]
    fn a_peer_is_the_ifa_address_of_a_local_address() {
        let v4 = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
        let v4_peer = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let v6_peer = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        for (ip, prefix, peer) in [(v4, 32, v4_peer), (v6, 128, v6_peer)] {
            let message = on_the_wire(&Address::new(7, ip, prefix).peer(peer));

            assert_eq!(
                message.attributes,
                [AddressAttribute::Address(peer), AddressAttribute::Local(ip)]
            );
        }
    }

    #[test]
    fn an_address_of_the_loopback_net_is_of_host_scope() {
        let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let message = on_the_wire(&Address::new(1, loopback, 8));

        assert_eq!(message.header.scope, AddressScope::Host);
    }
}
