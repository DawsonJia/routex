use std::{
    collections::VecDeque,
    io,
    net::IpAddr,
    num::NonZeroI32,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
};

use libc::{
    AF_NETLINK, NETLINK_ROUTE, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE, SOCK_CLOEXEC, SOCK_RAW,
    sockaddr_nl,
};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{
        RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteMessage, RouteProtocol,
        RouteScope, RouteType,
    },
};

use crate::{Route, RouteChange, fd};

/// Holds any datagram: the kernel sizes a dump datagram to the larger of
/// 8 KiB and the reader's buffer.
const RECV_BUF_LEN: usize = 16384;

/// A netlink socket that changes and queries the main routing table.
pub struct RouteSock {
    fd: OwnedFd,
    port_id: u32,
    sequence: u32,
}

impl AsFd for RouteSock {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for RouteSock {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl RouteSock {
    pub fn new() -> io::Result<Self> {
        let fd = socket()?;
        bind(fd.as_fd(), 0)?;
        let port_id = port_id(fd.as_fd())?;

        Ok(Self {
            fd,
            port_id,
            sequence: 0,
        })
    }

    pub fn add(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let (sequence, port_id) = (self.next_sequence(), self.port_id);
        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE | NLM_F_ACK;
        nl_hdr.sequence_number = sequence;
        nl_hdr.port_number = port_id;

        let mut rt_msg = route_change_message(route);
        rt_msg.header.table = RouteHeader::RT_TABLE_MAIN;
        rt_msg.header.protocol = RouteProtocol::Boot;
        rt_msg.header.scope = RouteScope::Universe;
        rt_msg.header.kind = RouteType::Unicast;

        add_route_selectors(&mut rt_msg, route);
        if route.gateway.is_none() && route.ifindex.is_some() {
            rt_msg.header.scope = RouteScope::Link;
        }

        let mut req = NetlinkMessage::new(
            nl_hdr,
            NetlinkPayload::from(RouteNetlinkMessage::NewRoute(rt_msg)),
        );
        req.finalize();

        let mut buf = [0u8; 4096];
        req.serialize(&mut buf[..req.buffer_len()]);
        fd::send(self.fd.as_fd(), &buf[..req.buffer_len()])?;
        self.recv_ack(sequence, port_id)
    }

    pub fn delete(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let (sequence, port_id) = (self.next_sequence(), self.port_id);
        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_ACK;
        nl_hdr.sequence_number = sequence;
        nl_hdr.port_number = port_id;

        let mut rt_msg = route_change_message(route);
        rt_msg.header.table = RouteHeader::RT_TABLE_MAIN;
        rt_msg.header.scope = RouteScope::NoWhere;
        add_route_selectors(&mut rt_msg, route);

        let mut req = NetlinkMessage::new(
            nl_hdr,
            NetlinkPayload::from(RouteNetlinkMessage::DelRoute(rt_msg)),
        );
        req.finalize();

        let mut buf = [0u8; 4096];
        req.serialize(&mut buf[..req.buffer_len()]);
        fd::send(self.fd.as_fd(), &buf[..req.buffer_len()])?;
        self.recv_ack(sequence, port_id)
    }

    pub fn get(&mut self, route: &Route) -> io::Result<Route> {
        route.validate()?;

        // The kernel answers a lookup of the unspecified address with the
        // loopback route, so the default route comes from a table dump.
        if route.destination.is_unspecified() && route.prefix == 0 {
            return self.default_route(route);
        }

        let (sequence, port_id) = (self.next_sequence(), self.port_id);
        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST;
        nl_hdr.sequence_number = sequence;
        nl_hdr.port_number = port_id;

        let rt_msg = route_lookup_message(route);

        let mut req = NetlinkMessage::new(
            nl_hdr,
            NetlinkPayload::from(RouteNetlinkMessage::GetRoute(rt_msg)),
        );
        req.finalize();
        let mut buf = [0u8; 4096];
        req.serialize(&mut buf[..req.buffer_len()]);
        fd::send(self.fd.as_fd(), &buf[..req.buffer_len()])?;

        self.recv_route_response(sequence, port_id)
    }

    fn next_sequence(&mut self) -> u32 {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        self.sequence
    }

    fn recv_route_response(&mut self, sequence: u32, port_id: u32) -> io::Result<Route> {
        loop {
            let mut rbuf = [0u8; RECV_BUF_LEN];
            let n = fd::recv(self.fd.as_fd(), &mut rbuf)?;
            for nlmsg in parse_nlmsgs(&rbuf[..n])? {
                if !response_matches(&nlmsg.header, sequence, port_id) {
                    continue;
                }

                match nlmsg.payload {
                    NetlinkPayload::Done(_) => {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
                    }
                    NetlinkPayload::Error(e) => {
                        if let Some(e) = e.code {
                            return Err(netlink_error(e));
                        }
                        return Err(io::Error::other("received an ACK without a route response"));
                    }
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(rt_msg)) => {
                        return route_from_message(&rt_msg).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "non-IP route response")
                        });
                    }
                    payload => {
                        return Err(io::Error::other(format!(
                            "unexpected netlink route response: {payload:?}"
                        )));
                    }
                }
            }
        }
    }

    fn default_route(&mut self, route: &Route) -> io::Result<Route> {
        let (sequence, port_id) = (self.next_sequence(), self.port_id);
        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
        nl_hdr.sequence_number = sequence;
        nl_hdr.port_number = port_id;

        let mut rt_msg = RouteMessage::default();
        rt_msg.header.address_family = address_family(route.destination);

        let mut req = NetlinkMessage::new(
            nl_hdr,
            NetlinkPayload::from(RouteNetlinkMessage::GetRoute(rt_msg)),
        );
        req.finalize();
        let mut buf = [0u8; 4096];
        req.serialize(&mut buf[..req.buffer_len()]);
        fd::send(self.fd.as_fd(), &buf[..req.buffer_len()])?;

        let mut best: Option<(u32, Route)> = None;
        loop {
            let mut rbuf = [0u8; RECV_BUF_LEN];
            let n = fd::recv(self.fd.as_fd(), &mut rbuf)?;
            for nlmsg in parse_nlmsgs(&rbuf[..n])? {
                if !response_matches(&nlmsg.header, sequence, port_id) {
                    continue;
                }

                match nlmsg.payload {
                    NetlinkPayload::Done(_) => {
                        return best.map(|(_, route)| route).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotFound, "no default route")
                        });
                    }
                    NetlinkPayload::Error(e) => {
                        return Err(e.code.map_or_else(
                            || io::Error::other("received an ACK instead of a route dump"),
                            netlink_error,
                        ));
                    }
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(rt_msg)) => {
                        if let Some((metric, candidate)) = default_route_candidate(&rt_msg, route)
                            && best
                                .as_ref()
                                .is_none_or(|(best_metric, _)| metric < *best_metric)
                        {
                            best = Some((metric, candidate));
                        }
                    }
                    payload => {
                        return Err(io::Error::other(format!(
                            "unexpected netlink route dump: {payload:?}"
                        )));
                    }
                }
            }
        }
    }

    fn recv_ack(&mut self, sequence: u32, port_id: u32) -> io::Result<()> {
        loop {
            let mut rbuf = [0u8; RECV_BUF_LEN];
            let n = fd::recv(self.fd.as_fd(), &mut rbuf)?;
            if let Some(result) = ack_from_messages(&parse_nlmsgs(&rbuf[..n])?, sequence, port_id) {
                return result;
            }
        }
    }
}

/// A netlink socket that reports the changes to the main routing table.
pub struct RouteMonitor {
    fd: OwnedFd,
    buf: Box<[u8]>,
    pending: VecDeque<(RouteChange, Route)>,
}

impl AsFd for RouteMonitor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for RouteMonitor {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl RouteMonitor {
    pub fn new() -> io::Result<Self> {
        const ROUTE_GROUPS: u32 = nl_mgrp(RTNLGRP_IPV4_ROUTE) | nl_mgrp(RTNLGRP_IPV6_ROUTE);

        let fd = socket()?;
        bind(fd.as_fd(), ROUTE_GROUPS)?;

        Ok(Self {
            fd,
            buf: vec![0; RECV_BUF_LEN].into_boxed_slice(),
            pending: VecDeque::new(),
        })
    }

    /// Blocks until the next change to the main routing table.
    pub fn recv(&mut self) -> io::Result<(RouteChange, Route)> {
        loop {
            if let Some(change) = self.pending.pop_front() {
                return Ok(change);
            }

            let n = fd::recv(self.fd.as_fd(), &mut self.buf)?;
            enqueue_route_changes(parse_nlmsgs(&self.buf[..n])?, &mut self.pending)?;
        }
    }
}

fn socket() -> io::Result<OwnedFd> {
    let fd = syscall!(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE))?;

    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn bind(fd: BorrowedFd<'_>, groups: u32) -> io::Result<()> {
    let mut local = unsafe { std::mem::zeroed::<sockaddr_nl>() };
    local.nl_family = AF_NETLINK as u16;
    local.nl_groups = groups;
    syscall!(bind(
        fd.as_raw_fd(),
        (&local as *const sockaddr_nl).cast(),
        std::mem::size_of::<sockaddr_nl>() as _
    ))?;

    Ok(())
}

/// The port the kernel assigned to `fd` when it was bound.
fn port_id(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut assigned = unsafe { std::mem::zeroed::<sockaddr_nl>() };
    let mut assigned_len = std::mem::size_of::<sockaddr_nl>() as libc::socklen_t;
    syscall!(getsockname(
        fd.as_raw_fd(),
        (&mut assigned as *mut sockaddr_nl).cast(),
        &mut assigned_len
    ))?;
    if assigned_len < std::mem::size_of::<sockaddr_nl>() as libc::socklen_t
        || assigned.nl_family != AF_NETLINK as u16
        || assigned.nl_pid == 0
    {
        return Err(io::Error::other(
            "kernel assigned an invalid netlink address",
        ));
    }

    Ok(assigned.nl_pid)
}

fn netlink_error(code: NonZeroI32) -> io::Error {
    let raw = code.get();
    io::Error::from_raw_os_error(if raw < 0 { -raw } else { raw })
}

fn route_change_message(route: &Route) -> RouteMessage {
    let mut rt_msg = RouteMessage::default();
    rt_msg.header.address_family = address_family(route.destination);
    rt_msg.header.destination_prefix_length = route.prefix;
    rt_msg
        .attributes
        .push(RouteAttribute::Destination(route_address(
            route.destination,
        )));
    rt_msg
}

fn add_route_selectors(rt_msg: &mut RouteMessage, route: &Route) {
    if let Some(gateway) = route.gateway {
        rt_msg
            .attributes
            .push(RouteAttribute::Gateway(route_address(gateway)));
    }

    if let Some(index) = route.ifindex {
        rt_msg.attributes.push(RouteAttribute::Oif(index));
    }
}

fn route_lookup_message(route: &Route) -> RouteMessage {
    let mut rt_msg = RouteMessage::default();
    rt_msg.header.address_family = address_family(route.destination);
    rt_msg.header.destination_prefix_length = route.prefix;
    rt_msg
        .attributes
        .push(RouteAttribute::Destination(route_address(
            route.destination,
        )));

    if let Some(index) = route.ifindex {
        rt_msg.attributes.push(RouteAttribute::Oif(index));
    }
    // Answer with the matching table entry, as macOS and Windows do, rather
    // than with the destination as a /32 host route.
    rt_msg.header.flags = RouteFlags::FibMatch;

    rt_msg
}

fn route_from_message(rt_msg: &RouteMessage) -> Option<Route> {
    let mut route = Route::new(
        unspecified(rt_msg.header.address_family),
        rt_msg.header.destination_prefix_length,
    );

    for attr in &rt_msg.attributes {
        match attr {
            RouteAttribute::Destination(addr) => route.destination = ip_addr(addr)?,
            RouteAttribute::Gateway(addr) => route.gateway = Some(ip_addr(addr)?),
            RouteAttribute::Oif(index) => route.ifindex = Some(*index),
            _ => {}
        }
    }

    Some(route)
}

/// Whether `rt_msg` is a unicast route of the main table, the only table
/// this crate adds to and deletes from.
fn in_main_table(rt_msg: &RouteMessage) -> bool {
    // Tables above 255 only fit in the attribute.
    let table = rt_msg
        .attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(rt_msg.header.table.into());

    rt_msg.header.kind == RouteType::Unicast && table == u32::from(RouteHeader::RT_TABLE_MAIN)
}

/// A live main-table default route matching the selectors of `route`, with
/// the metric the kernel ranks it by.
fn default_route_candidate(rt_msg: &RouteMessage, route: &Route) -> Option<(u32, Route)> {
    if rt_msg.header.destination_prefix_length != 0
        || rt_msg.header.flags.contains(RouteFlags::Dead)
        || !in_main_table(rt_msg)
    {
        return None;
    }

    let candidate = route_from_message(rt_msg)?;
    let selected = route
        .gateway
        .is_none_or(|gateway| candidate.gateway == Some(gateway))
        && route
            .ifindex
            .is_none_or(|ifindex| candidate.ifindex == Some(ifindex));
    let metric = rt_msg
        .attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::Priority(metric) => Some(*metric),
            _ => None,
        })
        .unwrap_or(0);

    selected.then_some((metric, candidate))
}

fn parse_nlmsgs(bytes: &[u8]) -> io::Result<Vec<NetlinkMessage<RouteNetlinkMessage>>> {
    const NETLINK_HEADER_LEN: usize = 16;

    let mut messages = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < NETLINK_HEADER_LEN {
            return Err(io::Error::other("truncated netlink header"));
        }

        let message = <NetlinkMessage<RouteNetlinkMessage>>::deserialize(remaining)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let length = message.header.length as usize;
        if length < NETLINK_HEADER_LEN || length > remaining.len() {
            return Err(io::Error::other(format!(
                "invalid netlink message length {length}"
            )));
        }

        messages.push(message);
        let message_end = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::other("netlink message length overflow"))?;
        let aligned_end = offset
            .checked_add(nlmsg_align(length))
            .ok_or_else(|| io::Error::other("netlink message length overflow"))?;
        if aligned_end > bytes.len() {
            if message_end == bytes.len() {
                break;
            }
            return Err(io::Error::other("truncated netlink message padding"));
        }
        offset = aligned_end;
    }

    Ok(messages)
}

fn response_matches(header: &NetlinkHeader, sequence: u32, port_id: u32) -> bool {
    header.port_number == port_id && header.sequence_number == sequence
}

fn ack_from_messages(
    messages: &[NetlinkMessage<RouteNetlinkMessage>],
    sequence: u32,
    port_id: u32,
) -> Option<io::Result<()>> {
    messages
        .iter()
        .find(|message| response_matches(&message.header, sequence, port_id))
        .map(|message| match &message.payload {
            NetlinkPayload::Error(error) => match error.code {
                Some(code) => Err(netlink_error(code)),
                None => Ok(()),
            },
            payload => Err(io::Error::other(format!(
                "unexpected netlink ACK response: {payload:?}"
            ))),
        })
}

fn enqueue_route_changes(
    messages: Vec<NetlinkMessage<RouteNetlinkMessage>>,
    pending: &mut VecDeque<(RouteChange, Route)>,
) -> io::Result<()> {
    for message in messages {
        let (change, rt_msg) = match message.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(rt_msg)) => {
                (RouteChange::Add, rt_msg)
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(rt_msg)) => {
                (RouteChange::Delete, rt_msg)
            }
            NetlinkPayload::Error(error) => {
                if let Some(code) = error.code {
                    return Err(netlink_error(code));
                }
                continue;
            }
            NetlinkPayload::Overrun(_) => {
                return Err(io::Error::other("netlink route monitor overrun"));
            }
            _ => continue,
        };

        if in_main_table(&rt_msg)
            && let Some(route) = route_from_message(&rt_msg)
        {
            pending.push_back((change, route));
        }
    }

    Ok(())
}

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

fn address_family(addr: IpAddr) -> AddressFamily {
    match addr {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    }
}

fn unspecified(family: AddressFamily) -> IpAddr {
    match family {
        AddressFamily::Inet6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        _ => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    }
}

fn route_address(addr: IpAddr) -> RouteAddress {
    match addr {
        IpAddr::V4(addr) => RouteAddress::Inet(addr),
        IpAddr::V6(addr) => RouteAddress::Inet6(addr),
    }
}

fn ip_addr(addr: &RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(addr) => Some(IpAddr::V4(*addr)),
        RouteAddress::Inet6(addr) => Some(IpAddr::V6(*addr)),
        _ => None,
    }
}

const fn nl_mgrp(group: u32) -> u32 {
    if group > 31 {
        panic!("Use setsockopt NETLINK_ADD_MEMBERSHIP for this group");
    }

    if group == 0 { 0 } else { 1 << (group - 1) }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, net::Ipv4Addr};

    use netlink_packet_core::ErrorMessage;

    use super::*;

    fn message(
        sequence: u32,
        port_number: u32,
        payload: NetlinkPayload<RouteNetlinkMessage>,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut header = NetlinkHeader::default();
        header.sequence_number = sequence;
        header.port_number = port_number;
        let mut message = NetlinkMessage::new(header, payload);
        message.finalize();
        message
    }

    fn ack(
        sequence: u32,
        port_number: u32,
        error: Option<i32>,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut ack = ErrorMessage::default();
        ack.code = error.and_then(NonZeroI32::new);
        message(sequence, port_number, NetlinkPayload::Error(ack))
    }

    fn main_table_message(route: &Route) -> RouteMessage {
        let mut rt_msg = route_change_message(route);
        add_route_selectors(&mut rt_msg, route);
        rt_msg.header.table = RouteHeader::RT_TABLE_MAIN;
        rt_msg.header.kind = RouteType::Unicast;
        rt_msg
    }

    fn route_message(destination: Ipv4Addr, deleted: bool) -> NetlinkMessage<RouteNetlinkMessage> {
        let rt_msg = main_table_message(&Route::new(IpAddr::V4(destination), 32));
        let payload = if deleted {
            RouteNetlinkMessage::DelRoute(rt_msg)
        } else {
            RouteNetlinkMessage::NewRoute(rt_msg)
        };
        message(0, 0, NetlinkPayload::InnerMessage(payload))
    }

    fn default_route(gateway: Ipv4Addr, ifindex: u32, metric: Option<u32>) -> RouteMessage {
        let route = Route::default()
            .gateway(IpAddr::V4(gateway))
            .ifindex(ifindex);
        let mut rt_msg = main_table_message(&route);
        // The kernel leaves out the destination of a /0 route.
        rt_msg
            .attributes
            .retain(|attr| !matches!(attr, RouteAttribute::Destination(_)));
        if let Some(metric) = metric {
            rt_msg.attributes.push(RouteAttribute::Priority(metric));
        }
        rt_msg
    }

    fn serialize(messages: &[NetlinkMessage<RouteNetlinkMessage>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for message in messages {
            let start = bytes.len();
            let length = message.buffer_len();
            bytes.resize(start + nlmsg_align(length), 0);
            message.serialize(&mut bytes[start..start + length]);
        }
        bytes
    }

    #[test]
    fn response_matching_requires_local_port_and_expected_sequence() {
        let mut header = NetlinkHeader::default();
        header.sequence_number = 7;
        header.port_number = 42;
        assert!(!response_matches(&header, 7, 99));

        header.sequence_number = 6;
        assert!(!response_matches(&header, 7, 42));

        header.sequence_number = 7;
        assert!(response_matches(&header, 7, 42));
    }

    #[test]
    fn ack_filter_skips_foreign_messages_and_preserves_kernel_errors() {
        let messages = [ack(9, 123, None), ack(8, 777, None), ack(9, 777, None)];
        assert!(ack_from_messages(&messages, 9, 777).unwrap().is_ok());

        let messages = [ack(9, 777, Some(-libc::EPERM))];
        let error = ack_from_messages(&messages, 9, 777).unwrap().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn multi_message_datagram_queues_every_route_change() {
        let add = route_message(Ipv4Addr::new(10, 0, 0, 1), false);
        let delete = route_message(Ipv4Addr::new(10, 0, 0, 2), true);
        let parsed = parse_nlmsgs(&serialize(&[add, delete])).unwrap();
        assert_eq!(parsed.len(), 2);

        let mut pending = VecDeque::new();
        enqueue_route_changes(parsed, &mut pending).unwrap();

        let (change, route) = pending.pop_front().unwrap();
        assert_eq!(change, RouteChange::Add);
        assert_eq!(route.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let (change, route) = pending.pop_front().unwrap();
        assert_eq!(change, RouteChange::Delete);
        assert_eq!(route.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(pending.is_empty());
    }

    #[test]
    fn route_changes_outside_the_main_table_are_skipped() {
        let mut local = main_table_message(&Route::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32));
        local.header.table = 255;
        local.header.kind = RouteType::Local;
        let mut policy = main_table_message(&Route::default());
        // RT_TABLE_COMPAT: the real table only fits in the attribute.
        policy.header.table = 252;
        policy.attributes.push(RouteAttribute::Table(51820));
        let main = route_message(Ipv4Addr::new(10, 0, 0, 1), false);
        let messages = [local, policy]
            .into_iter()
            .map(|rt_msg| {
                message(
                    0,
                    0,
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(rt_msg)),
                )
            })
            .chain([main])
            .collect();

        let mut pending = VecDeque::new();
        enqueue_route_changes(messages, &mut pending).unwrap();

        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].1.destination,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn default_route_candidates_follow_selectors_and_metric() {
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let any = Route::default();

        let (metric, route) =
            default_route_candidate(&default_route(gateway, 2, Some(100)), &any).unwrap();
        assert_eq!(metric, 100);
        assert_eq!(route.destination, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(route.prefix, 0);
        assert_eq!(route.gateway, Some(IpAddr::V4(gateway)));
        assert_eq!(route.ifindex, Some(2));
        assert_eq!(
            default_route_candidate(&default_route(gateway, 2, None), &any)
                .unwrap()
                .0,
            0
        );

        assert!(
            default_route_candidate(&default_route(gateway, 2, None), &any.ifindex(3)).is_none()
        );
        let mut dead = default_route(gateway, 2, None);
        dead.header.flags = RouteFlags::Dead;
        assert!(default_route_candidate(&dead, &any).is_none());
        let mut host = default_route(gateway, 2, None);
        host.header.destination_prefix_length = 32;
        assert!(default_route_candidate(&host, &any).is_none());
    }

    #[test]
    fn delete_message_keeps_nowhere_scope_and_includes_selectors() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24)
            .gateway(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .ifindex(7);
        let mut message = route_change_message(&route);
        message.header.scope = RouteScope::NoWhere;
        add_route_selectors(&mut message, &route);

        assert_eq!(message.header.scope, RouteScope::NoWhere);
        assert!(message.attributes.iter().any(|attribute| {
            matches!(attribute, RouteAttribute::Gateway(RouteAddress::Inet(address)) if *address == Ipv4Addr::new(10, 0, 0, 1))
        }));
        assert!(
            message
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, RouteAttribute::Oif(7)))
        );
    }

    #[test]
    #[ignore = "black-box check against the live Linux routing table"]
    fn default_route_lookup_returns_the_default_route() {
        let mut socket = RouteSock::new().unwrap();

        let route = socket.get(&Route::default()).unwrap();

        assert_eq!(route.destination, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(route.prefix, 0);
        assert!(route.ifindex.is_some());
        assert_ne!(route.ifindex, crate::if_nametoindex("lo"));
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN and temporarily installs a reserved test route"]
    fn add_get_delete_round_trip_through_the_main_table() {
        let lo = crate::if_nametoindex("lo").unwrap();
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 255, 0)), 24).ifindex(lo);
        let mut socket = RouteSock::new().unwrap();

        socket.add(&route).unwrap();
        let duplicate = socket.add(&route);
        let found = socket.get(&Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 255, 7)), 32));
        let cleanup = socket.delete(&route);

        cleanup.unwrap();
        assert_eq!(duplicate.unwrap_err().raw_os_error(), Some(libc::EEXIST));
        let found = found.unwrap();
        assert_eq!(found.destination, route.destination);
        assert_eq!(found.prefix, 24);
        assert_eq!(found.ifindex, Some(lo));
        assert_eq!(
            socket.delete(&route).unwrap_err().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN and temporarily installs a reserved test route"]
    fn monitor_reports_an_added_and_deleted_route() {
        let lo = crate::if_nametoindex("lo").unwrap();
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 254, 0)), 24).ifindex(lo);
        let mut monitor = RouteMonitor::new().unwrap();
        let mut socket = RouteSock::new().unwrap();

        socket.add(&route).unwrap();
        socket.delete(&route).unwrap();

        let mut next = || loop {
            let change = monitor.recv().unwrap();
            if change.1.destination == route.destination {
                return change;
            }
        };
        assert_eq!(next(), (RouteChange::Add, route));
        assert_eq!(next(), (RouteChange::Delete, route));
    }
}
