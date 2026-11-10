mod rtmsg;

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    sync::atomic::{AtomicI32, Ordering},
    time::{Duration, Instant},
};

use libc::{
    AF_INET, AF_INET6, AF_LINK, AF_ROUTE, AF_UNSPEC, F_SETFD, FD_CLOEXEC, RTA_DST, RTA_GATEWAY,
    RTA_IFP, RTA_NETMASK, RTF_GATEWAY, RTF_HOST, RTF_STATIC, RTF_UP, RTM_ADD, RTM_CHANGE,
    RTM_DELETE, RTM_GET, SHUT_RD, SOCK_RAW,
};

use crate::{Route, RouteChange, fd};
use rtmsg::{MESSAGE_CAPACITY, Message, Writer, message_type};

/// `RTF_IFSCOPE` is the XNU flag that ties a route to a specific interface
/// for use by `IP_BOUND_IF` scoped lookups. Not exposed by `libc`'s macOS
/// bindings, so define it locally from the XNU value (`net/route.h`).
const RTF_IFSCOPE: i32 = 0x1000000;

/// A `get_route` reply is told apart by the pid and sequence of its request, so
/// sequences are unique across the sockets of the process.
static ROUTE_SEQUENCE: AtomicI32 = AtomicI32::new(0);

/// XNU drops a routing message, the reply to a request included, for a
/// socket whose receive buffer is full, so a request waits for its reply only
/// this long.
const REPLY_TIMEOUT: Duration = Duration::from_secs(1);

/// A routing socket that changes and queries the routing table.
/// `add_route` and `delete_route` use it, so options set through
/// [`AsRawFd`] apply to them; every `get_route` opens a socket of its own.
pub struct Handle {
    fd: OwnedFd,
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
        let fd = open()?;
        // A change fails in its own write. Like `route add`, the socket reads
        // nothing back, so the kernel queues none of the host's routing
        // traffic to it.
        syscall!(shutdown(fd.as_raw_fd(), SHUT_RD))?;

        Ok(Self { fd })
    }

    /// Adds `route`; fails with `EEXIST` if it is there.
    pub fn add_route(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        fd::send(self.fd.as_fd(), &request(route, RTM_ADD, next_sequence()))
    }

    /// Deletes the route to `route.destination/prefix`, in the scope of
    /// `route.scope_ifindex` if it is set.
    pub fn delete_route(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        fd::send(
            self.fd.as_fd(),
            &request(route, RTM_DELETE, next_sequence()),
        )
    }

    /// The table entry the kernel routes `route.destination` by, in the scope
    /// of `route.scope_ifindex` if it is set.
    pub fn get_route(&mut self, route: &Route) -> io::Result<Route> {
        route.validate()?;

        // Every routing socket receives every routing message on the host, so
        // a long-lived one fills up between two requests and the kernel drops
        // the reply. A fresh socket is empty, and loopback, on by default,
        // delivers the reply to it.
        let socket = open()?;
        let seq = next_sequence();
        fd::send(socket.as_fd(), &request(route, RTM_GET, seq))?;

        read_reply(socket.as_fd(), seq)
    }
}

/// A routing socket that reports the changes to the routing table.
pub struct RouteMonitor {
    fd: OwnedFd,
    buf: [u8; MESSAGE_CAPACITY],
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
        Ok(Self {
            fd: open()?,
            buf: [0; MESSAGE_CAPACITY],
        })
    }

    /// Blocks until the next change to the routing table.
    pub fn recv(&mut self) -> io::Result<(RouteChange, Route)> {
        loop {
            let n = fd::recv(self.fd.as_fd(), &mut self.buf)?;
            let change = match message_type(&self.buf[..n]).map(i32::from) {
                Some(RTM_ADD) => RouteChange::Add,
                Some(RTM_DELETE) => RouteChange::Delete,
                Some(RTM_CHANGE) => RouteChange::Change,
                _ => continue,
            };

            let message = Message::parse(&self.buf[..n])?;
            // XNU broadcasts a failed request too, with its errno: some
            // process's error, and no change to the table.
            if message.hdr.rtm_errno != 0 {
                continue;
            }

            return Ok((change, read_route(&message)?));
        }
    }
}

fn open() -> io::Result<OwnedFd> {
    let fd = syscall!(socket(AF_ROUTE, SOCK_RAW, AF_UNSPEC))?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // macOS has no SOCK_CLOEXEC.
    syscall!(fcntl(fd.as_raw_fd(), F_SETFD, FD_CLOEXEC))?;

    Ok(fd)
}

fn next_sequence() -> i32 {
    ROUTE_SEQUENCE
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1)
}

/// The `rtm_type` request for `route`, encoded as `route` does.
fn request(route: &Route, rtm_type: i32, seq: i32) -> Vec<u8> {
    let mut message = Writer::new();
    message.inet(RTA_DST, route.destination);
    if rtm_type == RTM_ADD {
        match (route.gateway, route.ifindex) {
            (Some(gateway), _) => message.inet(RTA_GATEWAY, gateway),
            // `route add ... -interface ifname` is encoded as a link-layer
            // gateway. The route CLI does not also send RTA_IFP for this path.
            (None, Some(ifindex)) => message.link(RTA_GATEWAY, ifindex),
            (None, None) => {}
        }
    }
    if rtm_type != RTM_GET {
        message.netmask(netmask(route));
    }
    // A lookup asks the kernel to fill in IFP, so the slot must be reserved
    // even when the caller does not yet know the ifindex. An add through a
    // gateway names its interface the same way (`route add ... -ifp`).
    match (rtm_type, route.gateway, route.ifindex) {
        (RTM_GET, _, ifindex) => message.link(RTA_IFP, ifindex.unwrap_or(0)),
        (RTM_ADD, Some(_), Some(ifindex)) => message.link(RTA_IFP, ifindex),
        _ => {}
    }

    let mut flags = RTF_STATIC | RTF_UP;
    if route.prefix == route.max_prefix() {
        flags |= RTF_HOST;
    }
    if rtm_type == RTM_GET || rtm_type == RTM_ADD && route.gateway.is_some() {
        flags |= RTF_GATEWAY;
    }
    // XNU encodes interface-scope in two coupled fields: the flag and the
    // ifindex in `rtm_index`. Without either, it silently ignores the scope.
    let mut index = 0;
    if let Some(scope) = route.scope_ifindex {
        flags |= RTF_IFSCOPE;
        index = scope as u16;
    }

    message.finish(rtm_type, flags, index, seq)
}

fn read_reply(fd: BorrowedFd<'_>, seq: i32) -> io::Result<Route> {
    let pid = std::process::id() as i32;
    let deadline = Instant::now() + REPLY_TIMEOUT;
    let mut buf = [0; MESSAGE_CAPACITY];
    loop {
        wait_readable(fd, deadline)?;
        let n = fd::recv(fd, &mut buf)?;
        // The host's other routing traffic arrives too; only replies need
        // parsing.
        if message_type(&buf[..n]) != Some(RTM_GET as u8) {
            continue;
        }

        let reply = Message::parse(&buf[..n])?;
        if reply.hdr.rtm_pid != pid || reply.hdr.rtm_seq != seq {
            continue;
        }
        if reply.hdr.rtm_errno != 0 {
            return Err(io::Error::from_raw_os_error(reply.hdr.rtm_errno));
        }

        return read_route(&reply);
    }
}

fn wait_readable(fd: BorrowedFd<'_>, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no reply on the routing socket",
            ));
        }

        let mut poll_fd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Rounded up, so a sub-millisecond remainder still waits.
        let timeout_ms = remaining.as_micros().div_ceil(1000).min(i32::MAX as u128) as i32;
        match syscall!(poll(&mut poll_fd, 1, timeout_ms)) {
            Ok(0) => {}
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn read_route(message: &Message<'_>) -> io::Result<Route> {
    let flags = message.hdr.rtm_flags;
    let mut route = Route::default();
    for sockaddr in message.sockaddrs() {
        let (bit, sockaddr) = sockaddr?;
        match bit {
            RTA_DST => route.destination = sockaddr.ip()?,
            RTA_GATEWAY if flags & RTF_GATEWAY != 0 => route.gateway = Some(sockaddr.ip()?),
            // The link-layer gateway of an interface route names its interface.
            RTA_GATEWAY if i32::from(sockaddr.family()) == AF_LINK => {
                route.ifindex = sockaddr.link_index()?;
            }
            // A netmask may be cut before its family.
            RTA_NETMASK => {
                let family = match route.destination {
                    IpAddr::V4(_) => AF_INET,
                    IpAddr::V6(_) => AF_INET6,
                };
                route.prefix = prefix_len(sockaddr.ip_of(family as u8)?);
            }
            RTA_IFP => route.ifindex = sockaddr.link_index()?.or(route.ifindex),
            _ => {}
        }
    }
    // The kernel sends a host route without its netmask.
    if flags & RTF_HOST != 0 {
        route.prefix = route.max_prefix();
    }

    // Scope lives outside the sockaddr table: the flag is in `rtm_flags`
    // and the bound ifindex is in `rt_msghdr.rtm_index`. Reading them
    // back keeps round-trips (`add_route` -> `get_route`, `RouteMonitor` events) lossless.
    if flags & RTF_IFSCOPE != 0 {
        route.scope_ifindex = Some(u32::from(message.hdr.rtm_index));
    }

    Ok(route)
}

fn netmask(route: &Route) -> IpAddr {
    let host_bits = u32::from(route.max_prefix() - route.prefix);
    match route.destination {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(u32::MAX.checked_shl(host_bits).unwrap_or(0))),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(
            u128::MAX.checked_shl(host_bits).unwrap_or(0),
        )),
    }
}

fn prefix_len(netmask: IpAddr) -> u8 {
    match netmask {
        IpAddr::V4(netmask) => u32::from(netmask).leading_ones() as u8,
        IpAddr::V6(netmask) => u128::from(netmask).leading_ones() as u8,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, mem::offset_of};

    use libc::rt_msghdr;

    use super::{rtmsg::HEADER_LEN, *};

    fn parse(bytes: &[u8]) -> Message<'_> {
        Message::parse(bytes).unwrap()
    }

    #[test]
    fn add_by_interface_uses_link_gateway_without_ifp() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 32).ifindex(4);

        let bytes = request(&route, RTM_ADD, 1);

        assert_eq!(
            parse(&bytes).hdr.rtm_addrs,
            RTA_DST | RTA_GATEWAY | RTA_NETMASK
        );
    }

    #[test]
    fn add_by_gateway_and_interface_sends_ifp() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 32)
            .gateway(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .ifindex(4);

        let bytes = request(&route, RTM_ADD, 1);

        assert_eq!(
            parse(&bytes).hdr.rtm_addrs,
            RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFP
        );
    }

    #[test]
    fn lookup_reserves_ifp_slot() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 32);

        let bytes = request(&route, RTM_GET, 1);

        assert_eq!(parse(&bytes).hdr.rtm_addrs, RTA_DST | RTA_IFP);
    }

    #[test]
    fn host_route_sets_host_flag() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 32);

        let bytes = request(&route, RTM_DELETE, 1);

        assert_ne!(parse(&bytes).hdr.rtm_flags & RTF_HOST, 0);
    }

    #[test]
    fn netmask_sockaddr_is_compacted_like_route_cli() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 24);

        let bytes = request(&route, RTM_DELETE, 1);

        assert_eq!(bytes[HEADER_LEN + 16], 7);
        assert_eq!(bytes.len(), HEADER_LEN + 16 + 8);
    }

    #[test]
    fn default_route_netmask_uses_empty_sockaddr_slot() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

        let bytes = request(&route, RTM_DELETE, 1);

        assert_eq!(bytes[HEADER_LEN + 16], 0);
        assert_eq!(bytes.len(), HEADER_LEN + 20);
    }

    #[test]
    fn scoped_request_sets_both_flag_and_index() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))
            .ifscope(7);

        let bytes = request(&route, RTM_ADD, 1);
        let hdr = parse(&bytes).hdr;

        assert_ne!(hdr.rtm_flags & RTF_IFSCOPE, 0);
        assert_eq!(hdr.rtm_index, 7);
    }

    #[test]
    fn unscoped_request_leaves_scope_unset() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));

        let bytes = request(&route, RTM_ADD, 1);
        let hdr = parse(&bytes).hdr;

        assert_eq!(hdr.rtm_flags & RTF_IFSCOPE, 0);
        assert_eq!(hdr.rtm_index, 0);
    }

    #[test]
    fn read_route_preserves_scope() {
        let bytes = Writer::new().finish(RTM_GET, RTF_IFSCOPE, 11, 0);

        let route = read_route(&parse(&bytes)).unwrap();

        assert_eq!(route.scope_ifindex, Some(11));
    }

    #[test]
    fn read_route_without_scope_returns_none() {
        let bytes = Writer::new().finish(RTM_GET, 0, 42, 0);

        let route = read_route(&parse(&bytes)).unwrap();

        assert_eq!(route.scope_ifindex, None);
    }

    #[test]
    fn host_route_without_netmask_has_a_full_prefix() {
        let mut message = Writer::new();
        message.inet(RTA_DST, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let bytes = message.finish(RTM_GET, RTF_UP | RTF_HOST, 0, 0);

        let route = read_route(&parse(&bytes)).unwrap();

        assert_eq!(route.prefix, 32);
    }

    #[test]
    fn interface_route_reports_the_index_of_its_link_gateway() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).ifindex(7);

        let bytes = request(&route, RTM_ADD, 1);

        assert_eq!(read_route(&parse(&bytes)).unwrap(), route);
    }

    #[test]
    fn route_message_parser_accepts_an_unaligned_slice() {
        let expected = Route::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 0)), 24)
            .gateway(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 1)));
        let mut unaligned = vec![0xAA];
        unaligned.extend_from_slice(&request(&expected, RTM_ADD, 1));

        let actual = read_route(&parse(&unaligned[1..])).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn route_message_parser_rejects_short_and_inconsistent_lengths() {
        let short_error = Message::parse(&[0; 4]).err().unwrap();
        assert_eq!(short_error.kind(), io::ErrorKind::UnexpectedEof);

        let mut bytes = Writer::new().finish(RTM_GET, 0, 0, 0);
        bytes[offset_of!(rt_msghdr, rtm_msglen)..][..2]
            .copy_from_slice(&(HEADER_LEN as u16 + 1).to_ne_bytes());
        let length_error = Message::parse(&bytes).err().unwrap();
        assert_eq!(length_error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn route_parser_rejects_a_declared_but_missing_attribute() {
        let mut bytes = Writer::new().finish(RTM_GET, 0, 0, 0);
        bytes[offset_of!(rt_msghdr, rtm_addrs)..][..4].copy_from_slice(&RTA_DST.to_ne_bytes());

        let error = read_route(&parse(&bytes)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn routing_sequences_are_unique_across_concurrent_callers() {
        let handles: Vec<_> = (0..32).map(|_| std::thread::spawn(next_sequence)).collect();
        let sequences: HashSet<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(sequences.len(), 32);
    }

    fn queued_bytes(fd: impl AsFd) -> i32 {
        let mut queued = 0;
        syscall!(ioctl(fd.as_fd().as_raw_fd(), libc::FIONREAD, &mut queued)).unwrap();
        queued
    }

    #[test]
    #[ignore = "black-box check against the live macOS routing socket"]
    fn get_answers_while_routing_sockets_are_full() {
        let route = Route::default();
        let full = open().unwrap();
        let mut handle = Handle::new().unwrap();
        let mut capacity = 0;
        let mut capacity_len = std::mem::size_of_val(&capacity) as libc::socklen_t;
        syscall!(getsockopt(
            full.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&mut capacity as *mut i32).cast(),
            &mut capacity_len
        ))
        .unwrap();

        // Every reply reaches every routing socket, until one no longer fits.
        let dropped = (0..10_000).any(|_| {
            let queued = queued_bytes(&full);
            handle.get_route(&route).unwrap();
            queued_bytes(&full) == queued
        });
        assert!(
            dropped && queued_bytes(&full) > capacity / 2,
            "the replies never filled the receive buffer"
        );

        handle.get_route(&route).unwrap();
        assert_eq!(queued_bytes(&handle), 0);
    }

    #[test]
    #[ignore = "requires root and temporarily installs a reserved test route"]
    fn mutation_write_reports_duplicate_and_missing_route_errors_without_echo() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 255, 254)), 32)
            .ifindex(crate::if_nametoindex("lo0").unwrap());
        let mut handle = Handle::new().unwrap();

        handle.add_route(&route).unwrap();
        let duplicate = handle.add_route(&route);
        let cleanup = handle.delete_route(&route);

        cleanup.unwrap();
        assert_eq!(duplicate.unwrap_err().raw_os_error(), Some(libc::EEXIST));
        assert_eq!(
            handle.delete_route(&route).unwrap_err().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    #[ignore = "requires root and temporarily installs a reserved test route"]
    fn monitor_reports_an_added_and_deleted_route() {
        let lo0 = crate::if_nametoindex("lo0").unwrap();
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 254, 254)), 32).ifindex(lo0);
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
