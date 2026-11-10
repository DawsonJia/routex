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
    ErrorMessage, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_EXCL, NLM_F_REQUEST,
    NetlinkHeader, NetlinkMessage, NetlinkPayload, Nla,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{
        RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteMessage, RouteNextHopFlags,
        RouteProtocol, RouteScope, RouteType, RouteVia,
    },
};

use crate::{Route, RouteChange, RouteKind, Rule, fd, missing_route};

mod rule;

/// Holds any datagram: the kernel sizes a dump datagram to the larger of
/// 8 KiB and the reader's buffer.
const RECV_BUF_LEN: usize = 16384;

/// A netlink socket that changes and queries the routing tables, and
/// changes the rules that choose between them.
pub struct Handle {
    fd: OwnedFd,
    port_id: u32,
    sequence: u32,
}

impl AsFd for Handle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Handle {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Handle {
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

    /// Adds `route` to `route.table`; fails with `AlreadyExists` if it is
    /// there.
    pub fn add_route(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let sequence = self.request(
            NLM_F_EXCL | NLM_F_CREATE | NLM_F_ACK,
            RouteNetlinkMessage::NewRoute(add_message(route)),
        )?;
        self.replies(sequence, |message| Some(ack(message.payload)))
    }

    /// Deletes the route of `route.kind` to `route.destination/prefix` from
    /// `route.table`, through the gateway and interface of `route` where they
    /// are set; fails with `NotFound` if there is none.
    pub fn delete_route(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let mut rt_msg = change_message(route);
        // Any scope.
        rt_msg.header.scope = RouteScope::NoWhere;

        let sequence = self.request(NLM_F_ACK, RouteNetlinkMessage::DelRoute(rt_msg))?;
        self.replies(sequence, |message| Some(ack(message.payload)))
            .map_err(missing_route)
    }

    /// How the kernel routes `route.destination`, out of `route.ifindex` if
    /// it is set: the route it picks, for the destination as a host route,
    /// with the table and kind of the entry it found through the rules, or
    /// table 0 if it routed the destination by none. The unspecified address with prefix 0 asks for the default route of
    /// `route.kind` in `route.table` instead, through the gateway and
    /// interface of `route` where they are set; one that leaves through
    /// several live next hops, or a nexthop object, is an error.
    pub fn get_route(&mut self, route: &Route) -> io::Result<Route> {
        route.validate()?;

        // The kernel answers a lookup of the unspecified address with the
        // loopback route, so the default route comes from a table dump.
        if route.destination.is_unspecified() && route.prefix == 0 {
            return self.default_route(route);
        }

        // Not RTM_F_FIB_MATCH: the table entry of a multipath route has every
        // next hop, while a lookup answers with the one the kernel picks.
        // Without RTM_F_LOOKUP_TABLE, IPv4 reports any table as main.
        let mut rt_msg = route_message(route);
        rt_msg.header.flags = RouteFlags::LookupTable;
        let sequence = self.request(0, RouteNetlinkMessage::GetRoute(rt_msg))?;
        self.replies(sequence, |message| {
            Some(match message.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(rt_msg)) => {
                    route_from_message(&rt_msg)
                        .map_err(|reason| io::Error::new(io::ErrorKind::Unsupported, reason))
                }
                payload => Err(unexpected_reply(payload)),
            })
        })
    }

    /// Adds `rule`; fails with `AlreadyExists` if a rule with its
    /// priority, selectors and action is there, whether or not it inverts
    /// them.
    pub fn add_rule(&mut self, rule: &Rule) -> io::Result<()> {
        rule.validate()?;

        let sequence = self.request(
            NLM_F_EXCL | NLM_F_CREATE | NLM_F_ACK,
            RouteNetlinkMessage::NewRule(rule::rule_message(rule)),
        )?;
        self.replies(sequence, |message| Some(ack(message.payload)))
    }

    /// Deletes the first rule, by priority, with the action of `rule` and
    /// every selector that `rule` sets, and its priority if set; fails with
    /// `NotFound` if there is none. The kernel matches a rule that inverts
    /// its selectors whether or not `rule` does.
    pub fn delete_rule(&mut self, rule: &Rule) -> io::Result<()> {
        rule.validate()?;

        let sequence = self.request(
            NLM_F_ACK,
            RouteNetlinkMessage::DelRule(rule::rule_message(rule)),
        )?;
        self.replies(sequence, |message| Some(ack(message.payload)))
    }

    fn default_route(&mut self, route: &Route) -> io::Result<Route> {
        let mut dump = RouteMessage::default();
        dump.header.address_family = address_family(route.destination);
        let sequence = self.request(NLM_F_DUMP, RouteNetlinkMessage::GetRoute(dump))?;

        let mut best: Option<(u32, Result<Route, &'static str>)> = None;
        let mut interrupted = false;
        self.replies(sequence, |message| {
            // The kernel flags the messages of a dump that a change to the
            // table made inconsistent. The dump is still read to its end: one
            // left unread makes the kernel refuse the next with EBUSY.
            interrupted |= message.header.flags & NLM_F_DUMP_INTR != 0;

            match message.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(rt_msg)) => {
                    if let Some((metric, candidate)) = default_route_candidate(&rt_msg, route)
                        && best.is_none_or(|(best_metric, _)| metric < best_metric)
                    {
                        best = Some((metric, candidate));
                    }
                    None
                }
                // A dump that fails partway ends with its error.
                NetlinkPayload::Done(done) => Some(match (NonZeroI32::new(done.code), best) {
                    (Some(code), _) => Err(netlink_error(code)),
                    _ if interrupted => Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "the routing table changed during the dump",
                    )),
                    (None, Some((_, Ok(route)))) => Ok(route),
                    (None, Some((_, Err(reason)))) => {
                        Err(io::Error::new(io::ErrorKind::Unsupported, reason))
                    }
                    (None, None) => {
                        Err(io::Error::new(io::ErrorKind::NotFound, "no default route"))
                    }
                }),
                payload => Some(Err(unexpected_reply(payload))),
            }
        })
    }

    /// Sends `message` as a request with `flags` and returns its sequence.
    fn request(&mut self, flags: u16, message: RouteNetlinkMessage) -> io::Result<u32> {
        self.sequence = self.sequence.wrapping_add(1).max(1);

        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | flags;
        header.sequence_number = self.sequence;
        header.port_number = self.port_id;
        let mut request = NetlinkMessage::new(header, NetlinkPayload::from(message));
        request.finalize();

        let mut buf = vec![0; request.buffer_len()];
        request.serialize(&mut buf);
        fd::send(self.fd.as_fd(), &buf)?;
        Ok(self.sequence)
    }

    /// Feeds the replies to request `sequence` to `reply` until it returns
    /// a result.
    fn replies<T>(
        &mut self,
        sequence: u32,
        mut reply: impl FnMut(NetlinkMessage<RouteNetlinkMessage>) -> Option<io::Result<T>>,
    ) -> io::Result<T> {
        let mut buf = [0u8; RECV_BUF_LEN];
        loop {
            let n = fd::recv(self.fd.as_fd(), &mut buf)?;
            for message in parse_nlmsgs(&buf[..n])? {
                if response_matches(&message.header, sequence, self.port_id)
                    && let Some(result) = reply(message)
                {
                    return result;
                }
            }
        }
    }
}

/// A netlink socket that reports the changes to the routing tables.
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

    /// Blocks until the next change to a routing table.
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

/// A message that selects `route` by destination and interface.
fn route_message(route: &Route) -> RouteMessage {
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

    rt_msg
}

/// A message that adds `route` to its table.
fn add_message(route: &Route) -> RouteMessage {
    let mut rt_msg = change_message(route);
    rt_msg.header.protocol = RouteProtocol::Boot;
    rt_msg.header.scope = match route.kind {
        RouteKind::Local => RouteScope::Host,
        // Without a gateway, the destination is on the link of the interface.
        RouteKind::Unicast if route.gateway.is_none() && route.ifindex.is_some() => {
            RouteScope::Link
        }
        _ => RouteScope::Universe,
    };

    rt_msg
}

/// A message that selects `route` in its table, to add or delete it.
fn change_message(route: &Route) -> RouteMessage {
    let mut rt_msg = route_message(route);
    rt_msg.header.kind = route_type(route.kind);
    // Tables above 255 only fit in the attribute.
    rt_msg.header.table = u8::try_from(route.table).unwrap_or(RouteHeader::RT_TABLE_UNSPEC);
    if route.table > u32::from(u8::MAX) {
        rt_msg.attributes.push(RouteAttribute::Table(route.table));
    }
    if let Some(gateway) = route.gateway {
        rt_msg
            .attributes
            .push(RouteAttribute::Gateway(route_address(gateway)));
    }

    rt_msg
}

/// A next hop: its gateway, none when on-link, and its interface. The
/// gateway is an error when a `Route` cannot hold it.
type NextHop = (Result<Option<IpAddr>, &'static str>, Option<u32>);

/// `rt_msg` as a route, or why a `Route` cannot hold it.
fn route_from_message(rt_msg: &RouteMessage) -> Result<Route, &'static str> {
    let (entry, (gateway, ifindex)) = parse_route(rt_msg)?;

    Ok(Route {
        gateway: gateway?,
        ifindex,
        ..entry
    })
}

/// The destination, kind and table of `rt_msg`, as a route through no next
/// hop, and the next hop that its own attributes name, as against those in
/// RTA_MULTIPATH.
fn parse_route(rt_msg: &RouteMessage) -> Result<(Route, NextHop), &'static str> {
    let family = rt_msg.header.address_family;
    let kind = route_kind(rt_msg.header.kind).ok_or("a Route cannot hold a route of this type")?;
    let mut entry = Route::new(unspecified(family), rt_msg.header.destination_prefix_length)
        .kind(kind)
        .table(table(rt_msg));
    let mut ifindex = None;
    for attr in &rt_msg.attributes {
        match attr {
            RouteAttribute::Destination(addr) => {
                entry.destination = ip_addr(addr).ok_or("the destination is not an IP address")?;
            }
            RouteAttribute::Oif(index) => ifindex = Some(*index),
            _ => {}
        }
    }

    // IPv6 hangs the routes that drop or throw off the loopback interface.
    if !kind.has_next_hop() {
        return Ok((entry, (Ok(None), None)));
    }
    Ok((entry, next_hop(&rt_msg.attributes, ifindex, family)))
}

/// The next hop out of `ifindex` through the gateway in `attrs`, for a route
/// of `family`.
fn next_hop(attrs: &[RouteAttribute], ifindex: Option<u32>, family: AddressFamily) -> NextHop {
    let mut gateway = Ok(None);
    for attr in attrs {
        let address = match attr {
            RouteAttribute::Gateway(addr) => ip_addr(addr),
            // An IPv4 route through an IPv6 gateway (RFC 5549).
            RouteAttribute::Via(RouteVia::Inet(addr)) => Some(IpAddr::V4(*addr)),
            RouteAttribute::Via(RouteVia::Inet6(addr)) => Some(IpAddr::V6(*addr)),
            RouteAttribute::Via(_) => None,
            _ => continue,
        };
        // A `Route` holds a gateway of the family of its destination.
        gateway = address
            .filter(|address| address_family(*address) == family)
            .map(Some)
            .ok_or("the gateway is not an address of the family of the destination");
    }

    (gateway, ifindex)
}

/// The table of `rt_msg`.
fn table(rt_msg: &RouteMessage) -> u32 {
    // Tables above 255 only fit in the attribute.
    rt_msg
        .attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(rt_msg.header.table.into())
}

fn route_type(kind: RouteKind) -> RouteType {
    match kind {
        RouteKind::Unicast => RouteType::Unicast,
        RouteKind::Local => RouteType::Local,
        RouteKind::Blackhole => RouteType::BlackHole,
        RouteKind::Unreachable => RouteType::Unreachable,
        RouteKind::Prohibit => RouteType::Prohibit,
        RouteKind::Throw => RouteType::Throw,
    }
}

/// The kind of a route of type `kind`, unless a `Route` cannot hold it.
fn route_kind(kind: RouteType) -> Option<RouteKind> {
    Some(match kind {
        RouteType::Unicast => RouteKind::Unicast,
        RouteType::Local => RouteKind::Local,
        RouteType::BlackHole => RouteKind::Blackhole,
        RouteType::Unreachable => RouteKind::Unreachable,
        RouteType::Prohibit => RouteKind::Prohibit,
        RouteType::Throw => RouteKind::Throw,
        _ => return None,
    })
}

/// A live default route of the kind and table of `route` that applies to
/// any packet, with the metric the kernel ranks it by, if a live next hop of
/// it matches the selectors of `route`. It is an error when it would not
/// leave through one known next hop, which is all a `Route` can hold.
fn default_route_candidate(
    rt_msg: &RouteMessage,
    route: &Route,
) -> Option<(u32, Result<Route, &'static str>)> {
    let header = &rt_msg.header;
    // A route for some sources or some TOS only applies to some packets.
    if header.destination_prefix_length != 0
        || header.source_prefix_length != 0
        || header.tos != 0
        || header.kind != route_type(route.kind)
        || header.flags.contains(RouteFlags::Dead)
        || table(rt_msg) != route.table
    {
        return None;
    }

    let metric = rt_msg
        .attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::Priority(metric) => Some(*metric),
            _ => None,
        })
        .unwrap_or(0);
    let Ok((entry, own_next_hop)) = parse_route(rt_msg) else {
        return None;
    };
    let multipath = rt_msg.attributes.iter().find_map(|attr| match attr {
        RouteAttribute::MultiPath(hops) => Some(hops),
        _ => None,
    });
    // With `nexthop_compat_mode` off, a route only names its nexthop object,
    // so neither its next hops nor whether they match are known.
    if multipath.is_none() && own_next_hop == (Ok(None), None) && uses_nexthop_object(rt_msg) {
        return Some((metric, Err("the default route uses a nexthop object")));
    }

    let family = rt_msg.header.address_family;
    let next_hops = multipath
        .into_iter()
        .flatten()
        // The kernel takes no dead next hop.
        .filter(|hop| !hop.flags.contains(RouteNextHopFlags::Dead))
        .map(|hop| next_hop(&hop.attributes, Some(hop.interface_index), family))
        .chain(multipath.is_none().then_some(own_next_hop));
    let mut selected = next_hops.filter(|(gateway, ifindex)| {
        route
            .gateway
            .is_none_or(|selected| *gateway == Ok(Some(selected)))
            && route
                .ifindex
                .is_none_or(|selected| *ifindex == Some(selected))
    });
    let next_hop = match (selected.next(), selected.next()) {
        (None, _) => return None,
        (Some((gateway, ifindex)), None) => gateway.map(|gateway| Route {
            gateway,
            ifindex,
            ..entry
        }),
        (Some(_), Some(_)) => Err("the default route has several next hops"),
    };

    Some((metric, next_hop))
}

fn uses_nexthop_object(rt_msg: &RouteMessage) -> bool {
    // RTA_NH_ID, which netlink-packet-route leaves unparsed.
    const RTA_NH_ID: u16 = 30;

    rt_msg
        .attributes
        .iter()
        .any(|attr| matches!(attr, RouteAttribute::Other(nla) if nla.kind() == RTA_NH_ID))
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

fn ack(payload: NetlinkPayload<RouteNetlinkMessage>) -> io::Result<()> {
    match payload {
        NetlinkPayload::Error(error) if error.code.is_none() => Ok(()),
        payload => Err(unexpected_reply(payload)),
    }
}

/// The error for a reply other than the expected one: the kernel's own, if
/// it reports one.
fn unexpected_reply(payload: NetlinkPayload<RouteNetlinkMessage>) -> io::Error {
    match payload {
        NetlinkPayload::Error(ErrorMessage {
            code: Some(code), ..
        }) => netlink_error(code),
        payload => io::Error::other(format!("unexpected netlink reply: {payload:?}")),
    }
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

        // A route of a type a `Route` cannot hold, such as the broadcast and
        // multicast ones of the local table, is skipped.
        // TODO: a route through a gateway of another family is skipped, and
        // one with several next hops (RTA_MULTIPATH), or with only a nexthop
        // object under `nexthop_compat_mode` off, reports none.
        if let Ok(route) = route_from_message(&rt_msg) {
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
    use std::{
        collections::VecDeque,
        net::{Ipv4Addr, Ipv6Addr},
        os::unix::net::UnixDatagram,
        time::Duration,
    };

    use netlink_packet_core::{DefaultNla, DoneMessage, NLM_F_MULTIPART};
    use netlink_packet_route::route::{RouteNextHop, RouteVia};

    use super::*;
    use crate::{RuleAction, TABLE_LOCAL, TABLE_MAIN};

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

    fn ack_message(
        sequence: u32,
        port_number: u32,
        error: Option<i32>,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut error_message = ErrorMessage::default();
        error_message.code = error.and_then(NonZeroI32::new);
        message(sequence, port_number, NetlinkPayload::Error(error_message))
    }

    fn route_message(destination: Ipv4Addr, deleted: bool) -> NetlinkMessage<RouteNetlinkMessage> {
        let rt_msg = change_message(&Route::new(IpAddr::V4(destination), 32));
        let payload = if deleted {
            RouteNetlinkMessage::DelRoute(rt_msg)
        } else {
            RouteNetlinkMessage::NewRoute(rt_msg)
        };
        message(0, 0, NetlinkPayload::InnerMessage(payload))
    }

    fn new_route(rt_msg: RouteMessage) -> NetlinkPayload<RouteNetlinkMessage> {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(rt_msg))
    }

    fn done(code: i32) -> NetlinkPayload<RouteNetlinkMessage> {
        let mut done = DoneMessage::default();
        done.code = code;
        NetlinkPayload::Done(done)
    }

    fn multipath_default_route(metric: u32) -> RouteMessage {
        let mut rt_msg = default_route(Ipv4Addr::new(192, 168, 1, 1), 2, Some(metric));
        rt_msg
            .attributes
            .retain(|attr| !matches!(attr, RouteAttribute::Gateway(_) | RouteAttribute::Oif(_)));
        let hops = [
            (2, Ipv4Addr::new(192, 168, 1, 1)),
            (3, Ipv4Addr::new(192, 168, 2, 1)),
        ]
        .map(|(ifindex, gateway)| {
            let mut hop = RouteNextHop::default();
            hop.interface_index = ifindex;
            hop.attributes
                .push(RouteAttribute::Gateway(RouteAddress::Inet(gateway)));
            hop
        });
        rt_msg
            .attributes
            .push(RouteAttribute::MultiPath(hops.into()));
        rt_msg
    }

    /// `get(query)` from a fake kernel that answers with `replies`, each
    /// flagged multipart and with `flags`; a dump if `query` is the default
    /// route.
    fn get_from_fake_kernel(
        query: Route,
        replies: Vec<(u16, NetlinkPayload<RouteNetlinkMessage>)>,
    ) -> io::Result<Route> {
        let dump = query.destination.is_unspecified() && query.prefix == 0;
        let (client, kernel) = UnixDatagram::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let kernel = std::thread::spawn(move || {
            let mut buf = [0; RECV_BUF_LEN];
            let n = kernel.recv(&mut buf).unwrap();
            let request = parse_nlmsgs(&buf[..n]).unwrap().remove(0);
            assert_eq!(request.header.flags & NLM_F_DUMP == NLM_F_DUMP, dump);
            if !dump {
                let NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetRoute(lookup)) =
                    &request.payload
                else {
                    panic!("not a route lookup: {request:?}");
                };
                assert!(lookup.header.flags.contains(RouteFlags::LookupTable));
            }
            for (flags, payload) in replies {
                let header = request.header;
                let mut reply = message(header.sequence_number, header.port_number, payload);
                reply.header.flags = NLM_F_MULTIPART | flags;
                kernel.send(&serialize(&[reply])).unwrap();
            }
        });

        let mut handle = Handle {
            fd: client.into(),
            port_id: 42,
            sequence: 0,
        };
        let route = handle.get_route(&query);
        kernel.join().unwrap();

        let mut byte = 0u8;
        let unread = syscall!(recv(
            handle.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_DONTWAIT
        ));
        assert_eq!(
            unread.unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "the dump was left unread"
        );
        route
    }

    /// The request that `call` makes of a fake kernel that acks it with
    /// `error`, and what `call` returns.
    fn ack_from_fake_kernel(
        call: impl FnOnce(&mut Handle) -> io::Result<()>,
        error: Option<i32>,
    ) -> (NetlinkMessage<RouteNetlinkMessage>, io::Result<()>) {
        let (client, kernel) = UnixDatagram::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let kernel = std::thread::spawn(move || {
            let mut buf = [0; RECV_BUF_LEN];
            let n = kernel.recv(&mut buf).unwrap();
            let request = parse_nlmsgs(&buf[..n]).unwrap().remove(0);
            let header = request.header;
            let reply = ack_message(header.sequence_number, header.port_number, error);
            kernel.send(&serialize(&[reply])).unwrap();
            request
        });

        let mut handle = Handle {
            fd: client.into(),
            port_id: 42,
            sequence: 0,
        };
        let result = call(&mut handle);
        (kernel.join().unwrap(), result)
    }

    #[test]
    fn a_rule_is_added_exclusively_and_deleted_by_its_spec() {
        let rule = Rule::v4().priority(5200).suppress_prefixlength(0);

        let (request, added) = ack_from_fake_kernel(|handle| handle.add_rule(&rule), None);
        added.unwrap();
        assert_eq!(
            request.header.flags,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        );
        assert_eq!(
            request.payload,
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRule(rule::rule_message(&rule)))
        );

        let (request, deleted) = ack_from_fake_kernel(|handle| handle.delete_rule(&rule), None);
        deleted.unwrap();
        assert_eq!(request.header.flags, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(
            request.payload,
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRule(rule::rule_message(&rule)))
        );
    }

    #[test]
    fn deleting_a_missing_rule_or_route_is_not_found() {
        let rule = Rule::v6().priority(5210).action(RuleAction::Lookup(51888));
        let route = Route::default().kind(RouteKind::Throw).table(51888);

        let (_, rule) =
            ack_from_fake_kernel(|handle| handle.delete_rule(&rule), Some(-libc::ENOENT));
        let (_, route) =
            ack_from_fake_kernel(|handle| handle.delete_route(&route), Some(-libc::ESRCH));
        let (_, duplicate) =
            ack_from_fake_kernel(|handle| handle.add_rule(&Rule::v4()), Some(-libc::EEXIST));

        assert_eq!(rule.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(route.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(duplicate.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn an_invalid_rule_is_not_sent() {
        let mut handle = Handle {
            fd: UnixDatagram::pair().unwrap().0.into(),
            port_id: 42,
            sequence: 0,
        };

        let error = handle.add_rule(&Rule::v4().ip_proto(0)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let error = handle.delete_rule(&Rule::v4().iif("")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(handle.sequence, 0);
    }

    fn default_route(gateway: Ipv4Addr, ifindex: u32, metric: Option<u32>) -> RouteMessage {
        let route = Route::default()
            .gateway(IpAddr::V4(gateway))
            .ifindex(ifindex);
        let mut rt_msg = change_message(&route);
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
    fn ack_accepts_only_success_and_preserves_kernel_errors() {
        assert!(ack(ack_message(9, 777, None).payload).is_ok());

        let error = ack(ack_message(9, 777, Some(-libc::EPERM)).payload).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));

        let reply = route_message(Ipv4Addr::new(10, 0, 0, 1), false);
        assert!(ack(reply.payload).unwrap_err().raw_os_error().is_none());
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
    fn route_changes_of_every_table_are_reported_with_their_table_and_kind() {
        let lo = 1;
        let local = Route::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)
            .kind(RouteKind::Local)
            .table(TABLE_LOCAL)
            .ifindex(lo);
        let mut broadcast = change_message(&local);
        broadcast.header.kind = RouteType::Broadcast;
        let mut policy = change_message(&Route::default().ifindex(7));
        // RT_TABLE_COMPAT: the real table only fits in the attribute.
        policy.header.table = 252;
        policy.attributes.push(RouteAttribute::Table(51820));
        let blackhole = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 24)
            .kind(RouteKind::Blackhole)
            .table(220);
        // IPv6 hangs a route that drops off the loopback interface.
        let unreachable = Route::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            32,
        )
        .kind(RouteKind::Unreachable);
        let mut unreachable_message = change_message(&unreachable);
        unreachable_message.attributes.push(RouteAttribute::Oif(lo));
        let main = Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 32);
        let messages = [
            change_message(&local),
            broadcast,
            policy,
            change_message(&blackhole),
            unreachable_message,
            change_message(&main),
        ]
        .into_iter()
        .map(|rt_msg| message(0, 0, new_route(rt_msg)))
        .collect();

        let mut pending = VecDeque::new();
        enqueue_route_changes(messages, &mut pending).unwrap();

        let routes: Vec<_> = pending.into_iter().map(|(_, route)| route).collect();
        assert_eq!(
            routes,
            [
                local,
                Route::default().ifindex(7).table(51820),
                blackhole,
                unreachable,
                main
            ]
        );
    }

    #[test]
    fn default_route_candidates_follow_selectors_and_metric() {
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let any = Route::default();

        let (metric, Ok(route)) =
            default_route_candidate(&default_route(gateway, 2, Some(100)), &any).unwrap()
        else {
            panic!("a single-path route has a Route");
        };
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
    fn default_route_candidates_apply_to_any_packet() {
        let any = Route::default();
        let mut tos = default_route(Ipv4Addr::new(192, 168, 1, 1), 2, None);
        tos.header.tos = 0x10;
        let mut blackhole = default_route(Ipv4Addr::new(192, 168, 1, 1), 2, None);
        blackhole.header.kind = RouteType::BlackHole;
        let any_v6 = Route::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let mut source = change_message(
            &any_v6
                .gateway(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))
                .ifindex(2),
        );
        source.header.kind = RouteType::Unicast;
        source.header.source_prefix_length = 64;
        source
            .attributes
            .push(RouteAttribute::Source(RouteAddress::Inet6(Ipv6Addr::new(
                0x2001, 0xdb8, 1, 0, 0, 0, 0, 0,
            ))));

        assert!(default_route_candidate(&tos, &any).is_none());
        assert!(default_route_candidate(&blackhole, &any).is_none());
        assert!(default_route_candidate(&source, &any_v6).is_none());
    }

    #[test]
    fn default_route_candidates_are_of_the_table_and_kind_asked_for() {
        let any = Route::default();
        let tunnel = Route::default().ifindex(9).table(51888);
        let kill_switch = Route::default().kind(RouteKind::Blackhole).table(51888);
        let main = default_route(Ipv4Addr::new(192, 168, 1, 1), 2, None);

        assert!(default_route_candidate(&change_message(&tunnel), &any).is_none());
        assert!(default_route_candidate(&main, &any.table(51888)).is_none());
        assert_eq!(
            default_route_candidate(&change_message(&tunnel), &any.table(51888)),
            Some((0, Ok(tunnel)))
        );
        assert!(
            default_route_candidate(&change_message(&kill_switch), &any.table(51888)).is_none()
        );
        assert_eq!(
            default_route_candidate(&change_message(&kill_switch), &kill_switch),
            Some((0, Ok(kill_switch)))
        );
    }

    #[test]
    fn multipath_default_route_is_a_route_through_its_one_selected_live_next_hop() {
        let any = Route::default();
        let first = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let through_first = any.gateway(first).ifindex(2);

        assert!(matches!(
            default_route_candidate(&multipath_default_route(10), &any),
            Some((10, Err(_)))
        ));
        assert_eq!(
            default_route_candidate(&multipath_default_route(10), &any.gateway(first)),
            Some((10, Ok(through_first)))
        );
        assert!(default_route_candidate(&multipath_default_route(10), &any.ifindex(4)).is_none());

        let mut one_dead = multipath_default_route(10);
        for attr in &mut one_dead.attributes {
            if let RouteAttribute::MultiPath(hops) = attr {
                hops[1].flags = RouteNextHopFlags::Dead | RouteNextHopFlags::Linkdown;
            }
        }
        assert_eq!(
            default_route_candidate(&one_dead, &any),
            Some((10, Ok(through_first)))
        );
        assert!(default_route_candidate(&one_dead, &any.ifindex(3)).is_none());
    }

    fn through_ipv6_gateway(mut rt_msg: RouteMessage) -> RouteMessage {
        rt_msg
            .attributes
            .retain(|attr| !matches!(attr, RouteAttribute::Gateway(_)));
        rt_msg
            .attributes
            .push(RouteAttribute::Via(RouteVia::Inet6(Ipv6Addr::new(
                0xfe80, 0, 0, 0, 0, 0, 0, 1,
            ))));
        rt_msg
    }

    #[test]
    fn route_through_a_gateway_of_another_family_is_not_on_link() {
        let rt_msg = through_ipv6_gateway(default_route(Ipv4Addr::new(192, 168, 1, 1), 2, None));

        assert!(route_from_message(&rt_msg).is_err());
        for query in [Route::default(), Route::default().ifindex(2)] {
            assert!(matches!(
                default_route_candidate(&rt_msg, &query),
                Some((0, Err(_)))
            ));
        }
        let mut pending = VecDeque::new();
        enqueue_route_changes(vec![message(0, 0, new_route(rt_msg))], &mut pending).unwrap();
        assert!(pending.is_empty());

        let reply = through_ipv6_gateway(change_message(
            &Route::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 32).ifindex(2),
        ));
        let error = get_from_fake_kernel(
            Route::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 32),
            vec![(0, new_route(reply))],
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn multipath_next_hop_through_a_gateway_of_another_family_is_unsupported() {
        let mut rt_msg = multipath_default_route(10);
        for attr in &mut rt_msg.attributes {
            if let RouteAttribute::MultiPath(hops) = attr {
                hops[0].attributes = vec![RouteAttribute::Via(RouteVia::Inet6(Ipv6Addr::new(
                    0xfe80, 0, 0, 0, 0, 0, 0, 1,
                )))];
            }
        }

        assert!(matches!(
            default_route_candidate(&rt_msg, &Route::default().ifindex(2)),
            Some((10, Err(_)))
        ));
        assert_eq!(
            default_route_candidate(&rt_msg, &Route::default().ifindex(3)),
            Some((
                10,
                Ok(Route::default()
                    .gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)))
                    .ifindex(3))
            ))
        );
    }

    #[test]
    fn default_route_through_a_nexthop_object_is_unsupported() {
        let mut rt_msg = default_route(Ipv4Addr::new(192, 168, 1, 1), 2, Some(10));
        rt_msg
            .attributes
            .retain(|attr| !matches!(attr, RouteAttribute::Gateway(_) | RouteAttribute::Oif(_)));
        rt_msg
            .attributes
            .push(RouteAttribute::Other(DefaultNla::new(
                30,
                103u32.to_ne_bytes().to_vec(),
            )));

        for query in [Route::default(), Route::default().ifindex(2)] {
            assert!(matches!(
                default_route_candidate(&rt_msg, &query),
                Some((10, Err(_)))
            ));
        }
    }

    #[test]
    fn lookup_reports_the_table_and_kind_of_the_route_found() {
        let found = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 1, 1)), 32)
            .ifindex(9)
            .table(51888);
        let local = Route::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)
            .kind(RouteKind::Local)
            .table(TABLE_LOCAL)
            .ifindex(1);

        for route in [found, local] {
            let query = Route::new(route.destination, 32);
            let reply = vec![(0, new_route(change_message(&route)))];
            assert_eq!(get_from_fake_kernel(query, reply).unwrap(), route);
        }

        let mut broadcast = change_message(&local);
        broadcast.header.kind = RouteType::Broadcast;
        let error = get_from_fake_kernel(
            Route::new(local.destination, 32),
            vec![(0, new_route(broadcast))],
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn default_route_dump_picks_the_lowest_metric() {
        let route = get_from_fake_kernel(
            Route::default(),
            vec![
                (
                    0,
                    new_route(default_route(Ipv4Addr::new(192, 168, 1, 1), 2, Some(200))),
                ),
                (
                    0,
                    new_route(default_route(Ipv4Addr::new(192, 168, 2, 1), 3, Some(100))),
                ),
                (
                    0,
                    new_route(change_message(&Route::new(
                        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                        8,
                    ))),
                ),
                (0, done(0)),
            ],
        )
        .unwrap();

        assert_eq!(
            route.gateway,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)))
        );
        assert_eq!(route.ifindex, Some(3));
    }

    #[test]
    fn interrupted_default_route_dump_is_an_error() {
        let error = get_from_fake_kernel(
            Route::default(),
            vec![
                (
                    NLM_F_DUMP_INTR,
                    new_route(default_route(Ipv4Addr::new(192, 168, 1, 1), 2, None)),
                ),
                (
                    0,
                    new_route(default_route(Ipv4Addr::new(192, 168, 2, 1), 3, None)),
                ),
                (0, done(0)),
            ],
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn failed_default_route_dump_is_an_error() {
        let error = get_from_fake_kernel(
            Route::default(),
            vec![
                (
                    0,
                    new_route(default_route(Ipv4Addr::new(192, 168, 1, 1), 2, None)),
                ),
                (0, done(-libc::ENOMEM)),
            ],
        )
        .unwrap_err();

        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
    }

    #[test]
    fn multipath_default_route_is_unsupported_unless_selectors_skip_it() {
        let replies = || {
            vec![
                (0, new_route(multipath_default_route(10))),
                (
                    0,
                    new_route(default_route(Ipv4Addr::new(192, 168, 9, 1), 4, Some(100))),
                ),
                (0, done(0)),
            ]
        };

        let error = get_from_fake_kernel(Route::default(), replies()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);

        let route = get_from_fake_kernel(Route::default().ifindex(4), replies()).unwrap();
        assert_eq!(
            route.gateway,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 9, 1)))
        );
    }

    fn table_attribute(rt_msg: &RouteMessage) -> Option<u32> {
        rt_msg.attributes.iter().find_map(|attr| match attr {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
    }

    #[test]
    fn change_message_puts_a_table_above_255_in_the_attribute_only() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 24);

        for (table, header, attribute) in [
            (TABLE_MAIN, TABLE_MAIN as u8, None),
            (255, 255, None),
            (256, RouteHeader::RT_TABLE_UNSPEC, Some(256)),
            (51888, RouteHeader::RT_TABLE_UNSPEC, Some(51888)),
        ] {
            let message = change_message(&route.table(table));
            assert_eq!(message.header.table, header);
            assert_eq!(table_attribute(&message), attribute);
            assert_eq!(super::table(&message), table);
        }
    }

    #[test]
    fn add_message_has_the_type_and_scope_of_the_kind() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 24);
        let gateway = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));

        for (route, kind, scope) in [
            (
                route.gateway(gateway),
                RouteType::Unicast,
                RouteScope::Universe,
            ),
            (
                route.gateway(gateway).ifindex(2),
                RouteType::Unicast,
                RouteScope::Universe,
            ),
            (route.ifindex(2), RouteType::Unicast, RouteScope::Link),
            (
                route.kind(RouteKind::Local).ifindex(1),
                RouteType::Local,
                RouteScope::Host,
            ),
            (
                route.kind(RouteKind::Blackhole),
                RouteType::BlackHole,
                RouteScope::Universe,
            ),
            (
                route.kind(RouteKind::Unreachable),
                RouteType::Unreachable,
                RouteScope::Universe,
            ),
            (
                route.kind(RouteKind::Prohibit),
                RouteType::Prohibit,
                RouteScope::Universe,
            ),
            (
                route.kind(RouteKind::Throw),
                RouteType::Throw,
                RouteScope::Universe,
            ),
        ] {
            let message = add_message(&route);
            assert_eq!((message.header.kind, message.header.scope), (kind, scope));
            assert_eq!(message.header.protocol, RouteProtocol::Boot);
            assert_eq!(route_from_message(&message), Ok(route));
        }
    }

    #[test]
    fn change_message_selects_the_route_in_its_table() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24)
            .gateway(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .ifindex(7);
        let message = change_message(&route);

        assert_eq!(message.header.table, RouteHeader::RT_TABLE_MAIN);
        assert_eq!(message.header.kind, RouteType::Unicast);
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
        let mut handle = Handle::new().unwrap();

        let route = handle.get_route(&Route::default()).unwrap();

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
        let mut handle = Handle::new().unwrap();

        handle.add_route(&route).unwrap();
        let duplicate = handle.add_route(&route);
        let found = handle.get_route(&Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 255, 7)), 32));
        let cleanup = handle.delete_route(&route);

        cleanup.unwrap();
        assert_eq!(duplicate.unwrap_err().raw_os_error(), Some(libc::EEXIST));
        let found = found.unwrap();
        assert_eq!(
            found,
            Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 255, 7)), 32).ifindex(lo)
        );
        assert_eq!(
            handle.delete_route(&route).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN and temporarily installs a reserved test route"]
    fn monitor_reports_added_and_deleted_routes_of_every_table() {
        let lo = crate::if_nametoindex("lo").unwrap();
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 254, 0)), 24).ifindex(lo);
        let throw = Route::new(route.destination, 24)
            .kind(RouteKind::Throw)
            .table(LIVE_TABLE);
        let mut monitor = RouteMonitor::new().unwrap();
        let mut handle = Handle::new().unwrap();

        handle.add_route(&route).unwrap();
        handle.add_route(&throw).unwrap();
        handle.delete_route(&route).unwrap();
        handle.delete_route(&throw).unwrap();

        let mut next = || loop {
            let change = monitor.recv().unwrap();
            if change.1.destination == route.destination {
                return change;
            }
        };
        assert_eq!(next(), (RouteChange::Add, route));
        assert_eq!(next(), (RouteChange::Add, throw));
        assert_eq!(next(), (RouteChange::Delete, route));
        assert_eq!(next(), (RouteChange::Delete, throw));
    }

    /// Tables no system uses, one that fits in the header and one that does
    /// not, for the live tests.
    const LIVE_TABLE: u32 = 3_198_018;
    const LIVE_SMALL_TABLE: u32 = 218;

    #[test]
    #[ignore = "requires CAP_NET_ADMIN and temporarily installs reserved test routes"]
    fn routes_of_every_kind_round_trip_through_a_table() {
        let lo = crate::if_nametoindex("lo").unwrap();
        let host = |last| Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 253, last)), 32);
        let mut handle = Handle::new().unwrap();

        for table in [LIVE_SMALL_TABLE, LIVE_TABLE] {
            let routes = [
                Route::default().ifindex(lo),
                host(1).ifindex(lo),
                host(2).kind(RouteKind::Local).ifindex(lo),
                host(3).kind(RouteKind::Blackhole),
                host(4).kind(RouteKind::Unreachable),
                host(5).kind(RouteKind::Prohibit),
                host(6).kind(RouteKind::Throw),
            ]
            .map(|route| route.table(table));

            for route in &routes {
                let added = handle.add_route(route);
                let duplicate = handle.add_route(route);
                let default = route
                    .destination
                    .is_unspecified()
                    .then(|| handle.get_route(&Route::default().table(table)));
                let deleted = handle.delete_route(route);
                let missing = handle.delete_route(route);

                added.unwrap_or_else(|error| panic!("add {route:?}: {error}"));
                assert_eq!(
                    duplicate.unwrap_err().kind(),
                    io::ErrorKind::AlreadyExists,
                    "{route:?}"
                );
                if let Some(default) = default {
                    assert_eq!(default.unwrap(), *route);
                }
                deleted.unwrap();
                assert_eq!(missing.unwrap_err().kind(), io::ErrorKind::NotFound);
            }
        }
    }

    /// Priorities and tables no system uses, for the live rule tests. The
    /// rules of each test look up their own table, so that a rule that
    /// selects every packet never routes it by another test's routes.
    const LIVE_PRIORITY: u32 = 31_980;
    const LIVE_RULE_TABLE: u32 = 3_198_019;
    const LIVE_POLICY_TABLE: u32 = 3_198_020;

    /// What adding `rule`, adding it again, deleting it and deleting it
    /// again come to, asserted after the rule is gone.
    fn round_trip(handle: &mut Handle, rule: &Rule) {
        let added = handle.add_rule(rule);
        let duplicate = handle.add_rule(rule);
        let deleted = handle.delete_rule(rule);
        let missing = handle.delete_rule(rule);

        added.unwrap_or_else(|error| panic!("add {rule:?}: {error}"));
        assert_eq!(
            duplicate.unwrap_err().kind(),
            io::ErrorKind::AlreadyExists,
            "{rule:?}"
        );
        deleted.unwrap();
        assert_eq!(missing.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN and temporarily installs rules of an unused priority"]
    fn rules_of_both_families_round_trip_by_their_spec() {
        let mut handle = Handle::new().unwrap();
        let lookup = RuleAction::Lookup(LIVE_RULE_TABLE);
        let benchmarking = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0));
        // Apart from the destinations of the other live tests.
        let dropped = IpAddr::V4(Ipv4Addr::new(198, 19, 255, 0));

        let every_selector = Rule::v4()
            .priority(LIVE_PRIORITY)
            .from(benchmarking, 15)
            .to(IpAddr::V4(Ipv4Addr::new(198, 19, 252, 0)), 24)
            .fwmark(0x5100, 0xff00)
            .iif("lo")
            .oif("rtx-missing0")
            .uid_range(4242..=4243)
            .ip_proto(17)
            .sport(1024..=2048)
            .dport(53..=53)
            .invert()
            .action(lookup)
            .suppress_prefixlength(0);
        let ipv6 = Rule::v6()
            .priority(LIVE_PRIORITY)
            .fwmark(0x5100, u32::MAX)
            .oif("lo")
            .uid_range(4242..=4242)
            .ip_proto(6)
            .dport(443..=443)
            .action(lookup)
            .suppress_prefixlength(64);
        let rules = [
            every_selector,
            ipv6,
            Rule::v4().priority(LIVE_PRIORITY + 1).action(lookup),
            Rule::v6().priority(LIVE_PRIORITY + 1).action(lookup),
            Rule::v4()
                .priority(LIVE_PRIORITY + 2)
                .to(dropped, 24)
                .action(RuleAction::Blackhole),
            Rule::v6()
                .priority(LIVE_PRIORITY + 2)
                .fwmark(0x5100, u32::MAX)
                .action(RuleAction::Unreachable),
            Rule::v4()
                .priority(LIVE_PRIORITY + 3)
                .to(dropped, 24)
                .action(RuleAction::Prohibit),
        ];

        for rule in &rules {
            round_trip(&mut handle, rule);
        }
    }

    /// The rules of a tunnel that captures what is not marked as its own,
    /// or what is not bound to another interface, and leaves the main
    /// table's more specific routes alone.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN and temporarily installs rules of an unused priority"]
    fn tunnel_capture_rules_round_trip_by_their_spec() {
        let mut handle = Handle::new().unwrap();
        let tunnel = RuleAction::Lookup(LIVE_RULE_TABLE);

        for rule in [Rule::v4(), Rule::v6()] {
            let suppress = rule
                .clone()
                .priority(LIVE_PRIORITY + 10)
                .suppress_prefixlength(0);
            let unmarked = rule
                .clone()
                .priority(LIVE_PRIORITY + 11)
                .invert()
                .fwmark(0x5100, u32::MAX)
                .action(tunnel);
            let every = rule.priority(LIVE_PRIORITY + 12).action(tunnel);

            let added: Vec<_> = [&suppress, &unmarked, &every]
                .map(|rule| handle.add_rule(rule))
                .into();
            let deleted: Vec<_> = [&suppress, &unmarked, &every]
                .map(|rule| handle.delete_rule(rule))
                .into();
            let missing = handle.delete_rule(&unmarked);

            for result in added.into_iter().chain(deleted) {
                result.unwrap();
            }
            assert_eq!(missing.unwrap_err().kind(), io::ErrorKind::NotFound);
        }
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN and temporarily installs reserved test routes and rules"]
    fn rules_choose_the_table_a_lookup_goes_through() {
        let lo = crate::if_nametoindex("lo").unwrap();
        let prefix = IpAddr::V4(Ipv4Addr::new(198, 18, 252, 0));
        let destination = |last| Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 252, last)), 32);
        let route = Route::new(prefix, 24).ifindex(lo).table(LIVE_POLICY_TABLE);
        let throw = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 252, 128)), 25)
            .kind(RouteKind::Throw)
            .table(LIVE_POLICY_TABLE);
        let rule = Rule::v4()
            .priority(LIVE_PRIORITY + 20)
            .to(prefix, 24)
            .action(RuleAction::Lookup(LIVE_POLICY_TABLE));
        let suppress = rule.clone().suppress_prefixlength(24);
        let mut handle = Handle::new().unwrap();

        let unruled = handle.get_route(&destination(1));
        let setup = [
            handle.add_route(&route),
            handle.add_route(&throw),
            handle.add_rule(&rule),
        ];
        let ruled = handle.get_route(&destination(1));
        let thrown = handle.get_route(&destination(129));
        let swap = [handle.delete_rule(&rule), handle.add_rule(&suppress)];
        let suppressed = handle.get_route(&destination(1));
        let cleanup = [
            handle.delete_rule(&suppress),
            handle.delete_route(&throw),
            handle.delete_route(&route),
        ];

        for result in setup.into_iter().chain(swap).chain(cleanup) {
            result.unwrap();
        }
        let main = unruled.unwrap();
        assert_eq!(main.table, TABLE_MAIN);
        assert_eq!(
            ruled.unwrap(),
            destination(1).ifindex(lo).table(LIVE_POLICY_TABLE)
        );
        // A throw, and a route the rule suppresses, leave the packet to the
        // rules after: to the main table.
        assert_eq!(
            thrown.unwrap(),
            Route {
                destination: destination(129).destination,
                ..main
            }
        );
        assert_eq!(suppressed.unwrap(), main);
    }
}
