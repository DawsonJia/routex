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

use crate::{Route, RouteChange, fd, missing_route};

/// Holds any datagram: the kernel sizes a dump datagram to the larger of
/// 8 KiB and the reader's buffer.
const RECV_BUF_LEN: usize = 16384;

/// A netlink socket that changes and queries the main routing table.
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

    /// Adds `route` to the main table; fails with `EEXIST` if it is there.
    pub fn add_route(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let mut rt_msg = change_message(route);
        rt_msg.header.protocol = RouteProtocol::Boot;
        rt_msg.header.kind = RouteType::Unicast;
        // Without a gateway, the destination is on the link of the interface.
        rt_msg.header.scope = if route.gateway.is_none() && route.ifindex.is_some() {
            RouteScope::Link
        } else {
            RouteScope::Universe
        };

        let sequence = self.request(
            NLM_F_EXCL | NLM_F_CREATE | NLM_F_ACK,
            RouteNetlinkMessage::NewRoute(rt_msg),
        )?;
        self.replies(sequence, |message| Some(ack(message.payload)))
    }

    /// Deletes the main-table route to `route.destination/prefix`, through
    /// the gateway and interface of `route` where they are set; fails with
    /// `NotFound` if there is none.
    pub fn delete_route(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let mut rt_msg = change_message(route);
        rt_msg.header.scope = RouteScope::NoWhere;

        let sequence = self.request(NLM_F_ACK, RouteNetlinkMessage::DelRoute(rt_msg))?;
        self.replies(sequence, |message| Some(ack(message.payload)))
            .map_err(missing_route)
    }

    /// How the kernel routes `route.destination`, out of `route.ifindex` if
    /// it is set: the gateway and interface it picks, for the destination as
    /// a host route. The unspecified address with prefix 0 asks for the
    /// main-table default route instead, through the gateway and interface of
    /// `route` where they are set; one that leaves through several live next
    /// hops, or a nexthop object, is an error.
    pub fn get_route(&mut self, route: &Route) -> io::Result<Route> {
        route.validate()?;

        // The kernel answers a lookup of the unspecified address with the
        // loopback route, so the default route comes from a table dump.
        if route.destination.is_unspecified() && route.prefix == 0 {
            return self.default_route(route);
        }

        // Not RTM_F_FIB_MATCH: the table entry of a multipath route has every
        // next hop, while a lookup answers with the one the kernel picks.
        let rt_msg = route_message(route);
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

/// A message that adds `route` to or deletes it from the main table.
fn change_message(route: &Route) -> RouteMessage {
    let mut rt_msg = route_message(route);
    rt_msg.header.table = RouteHeader::RT_TABLE_MAIN;
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

/// The destination of `rt_msg`, as a route through no next hop, and the next
/// hop that its own attributes name, as against those in RTA_MULTIPATH.
fn parse_route(rt_msg: &RouteMessage) -> Result<(Route, NextHop), &'static str> {
    let family = rt_msg.header.address_family;
    let mut entry = Route::new(unspecified(family), rt_msg.header.destination_prefix_length);
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

/// Whether `rt_msg` is a route of the main table, the only table this crate
/// adds to and deletes from.
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

    table == u32::from(RouteHeader::RT_TABLE_MAIN)
}

/// A live main-table unicast default route that applies to any packet,
/// with the metric the kernel ranks it by, if a live next hop of it matches
/// the selectors of `route`. It is an error when it would not leave through
/// one known next hop, which is all a `Route` can hold.
fn default_route_candidate(
    rt_msg: &RouteMessage,
    route: &Route,
) -> Option<(u32, Result<Route, &'static str>)> {
    let header = &rt_msg.header;
    // A route for some sources or some TOS only applies to some packets.
    if header.destination_prefix_length != 0
        || header.source_prefix_length != 0
        || header.tos != 0
        || header.kind != RouteType::Unicast
        || header.flags.contains(RouteFlags::Dead)
        || !in_main_table(rt_msg)
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

        // TODO: a route through a gateway of another family is skipped, and
        // one with several next hops (RTA_MULTIPATH), or with only a nexthop
        // object under `nexthop_compat_mode` off, reports none.
        if in_main_table(&rt_msg)
            && let Ok(route) = route_from_message(&rt_msg)
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
    use std::{
        collections::VecDeque,
        net::{Ipv4Addr, Ipv6Addr},
        os::unix::net::UnixDatagram,
        time::Duration,
    };

    use netlink_packet_core::{DefaultNla, DoneMessage, NLM_F_MULTIPART};
    use netlink_packet_route::route::{RouteNextHop, RouteVia};

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

    fn ack_message(
        sequence: u32,
        port_number: u32,
        error: Option<i32>,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut error_message = ErrorMessage::default();
        error_message.code = error.and_then(NonZeroI32::new);
        message(sequence, port_number, NetlinkPayload::Error(error_message))
    }

    fn main_table_message(route: &Route) -> RouteMessage {
        let mut rt_msg = change_message(route);
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
    fn route_changes_are_reported_for_every_route_of_the_main_table_only() {
        let mut local = main_table_message(&Route::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32));
        local.header.table = 255;
        local.header.kind = RouteType::Local;
        let mut policy = main_table_message(&Route::default());
        // RT_TABLE_COMPAT: the real table only fits in the attribute.
        policy.header.table = 252;
        policy.attributes.push(RouteAttribute::Table(51820));
        let mut blackhole =
            main_table_message(&Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 24));
        blackhole.header.kind = RouteType::BlackHole;
        let main = main_table_message(&Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 32));
        let messages = [local, policy, blackhole, main]
            .into_iter()
            .map(|rt_msg| message(0, 0, new_route(rt_msg)))
            .collect();

        let mut pending = VecDeque::new();
        enqueue_route_changes(messages, &mut pending).unwrap();

        let destinations: Vec<_> = pending.iter().map(|(_, route)| route.destination).collect();
        assert_eq!(
            destinations,
            [
                IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
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

        let reply = through_ipv6_gateway(main_table_message(
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
                    new_route(main_table_message(&Route::new(
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

    #[test]
    fn change_message_selects_the_main_table_route() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24)
            .gateway(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .ifindex(7);
        let message = change_message(&route);

        assert_eq!(message.header.table, RouteHeader::RT_TABLE_MAIN);
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
    fn monitor_reports_an_added_and_deleted_route() {
        let lo = crate::if_nametoindex("lo").unwrap();
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 254, 0)), 24).ifindex(lo);
        let mut monitor = RouteMonitor::new().unwrap();
        let mut handle = Handle::new().unwrap();

        handle.add_route(&route).unwrap();
        handle.delete_route(&route).unwrap();

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
