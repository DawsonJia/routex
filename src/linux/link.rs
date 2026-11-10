//! The netlink messages of the links: the interfaces themselves.

use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};

/// A message that selects the link `ifindex`.
pub(super) fn link_message(ifindex: u32) -> LinkMessage {
    let mut message = LinkMessage::default();
    message.header.index = ifindex;
    message
}

/// A message that sets the MTU of the link `ifindex`.
pub(super) fn mtu_message(ifindex: u32, mtu: u32) -> LinkMessage {
    let mut message = link_message(ifindex);
    message.attributes.push(LinkAttribute::Mtu(mtu));
    message
}

/// A message that brings the link `ifindex` up or down, and leaves its other
/// flags as they are.
pub(super) fn up_message(ifindex: u32, up: bool) -> LinkMessage {
    let mut message = link_message(ifindex);
    if up {
        message.header.flags = LinkFlags::Up;
    }
    message.header.change_mask = LinkFlags::Up;
    message
}

/// The MTU of the link that `message` describes.
pub(super) fn mtu(message: &LinkMessage) -> Option<u32> {
    message.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::Mtu(mtu) => Some(*mtu),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use netlink_packet_core::{Emitable, Parseable};
    use netlink_packet_route::link::LinkMessageBuffer;

    use super::*;

    /// `message` as the kernel reads it off the wire.
    fn on_the_wire(message: LinkMessage) -> LinkMessage {
        let mut bytes = vec![0; message.buffer_len()];
        message.emit(&mut bytes);
        LinkMessage::parse(&LinkMessageBuffer::new(&bytes)).unwrap()
    }

    #[test]
    fn an_mtu_message_changes_no_flag() {
        let message = on_the_wire(mtu_message(7, 1400));

        assert_eq!(message.header.index, 7);
        assert_eq!(message.header.change_mask, LinkFlags::empty());
        assert_eq!(message.attributes, [LinkAttribute::Mtu(1400)]);
        assert_eq!(mtu(&message), Some(1400));
    }

    #[test]
    fn an_up_message_changes_the_up_flag_alone() {
        for (up, flags) in [(true, LinkFlags::Up), (false, LinkFlags::empty())] {
            let message = on_the_wire(up_message(7, up));

            assert_eq!(message.header.index, 7);
            assert_eq!(message.header.flags, flags);
            assert_eq!(message.header.change_mask, LinkFlags::Up);
            assert!(message.attributes.is_empty());
            assert_eq!(mtu(&message), None);
        }
    }
}
