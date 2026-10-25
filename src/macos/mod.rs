mod rtmsg;

use std::{
    io::{self, Read, Write},
    os::fd::{AsRawFd, RawFd},
    sync::atomic::{AtomicI32, Ordering},
    time::{Duration, Instant},
};

use crate::{Route, RouteAction, RouteChange, macos::rtmsg::m_rtmsg};
use libc::{
    AF_INET, AF_INET6, AF_ROUTE, AF_UNSPEC, F_SETFD, FD_CLOEXEC, RTA_DST, RTA_GATEWAY, RTA_IFP,
    RTA_NETMASK, RTAX_MAX, RTF_GATEWAY, RTF_HOST, RTF_STATIC, RTF_UP, RTM_ADD, RTM_CHANGE,
    RTM_DELETE, RTM_GET, RTM_VERSION, SO_USELOOPBACK, SOCK_RAW, SOL_SOCKET, rt_msghdr,
};

/// `RTF_IFSCOPE` is the XNU flag that ties a route to a specific interface
/// for use by `IP_BOUND_IF` scoped lookups. Not exposed by `libc`'s macOS
/// bindings, so define it locally from the XNU value (`net/route.h`).
const RTF_IFSCOPE: i32 = 0x1000000;
static ROUTE_SEQUENCE: AtomicI32 = AtomicI32::new(0);

/// XNU drops a routing message, the reply to a request included, for a
/// socket whose receive buffer is full, so a request waits for its reply only
/// this long.
const REPLY_TIMEOUT: Duration = Duration::from_secs(1);

/// A routing socket. `add`, `delete` and `monitor` use it, so options set
/// through [`AsRawFd`] apply to them; every `get` opens a socket of its own.
pub struct RouteSock {
    fd: RawFd,
}

impl AsRawFd for RouteSock {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Write for RouteSock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = syscall!(write(self.as_raw_fd(), buf.as_ptr() as *const _, buf.len()))?;

        Ok(n as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for RouteSock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = syscall!(read(
            self.as_raw_fd(),
            buf.as_mut_ptr() as *mut _,
            buf.len()
        ))?;

        Ok(n as usize)
    }
}

impl RouteAction for RouteSock {
    fn add(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let mut rtmsg = write_route_addrs(route, RouteRequestKind::Add);
        let seq = next_route_sequence();
        rtmsg.hdr.rtm_type = RTM_ADD as u8;
        rtmsg.hdr.rtm_flags = route_flags(route, route.gateway.is_some());
        apply_ifscope(&mut rtmsg.hdr, route);
        rtmsg.hdr.rtm_seq = seq;
        rtmsg.hdr.rtm_pid = unsafe { libc::getpid() };
        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        self.write_all(route_msg_bytes(&rtmsg))?;
        Ok(())
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let mut rtmsg = write_route_addrs(route, RouteRequestKind::Delete);
        let seq = next_route_sequence();
        rtmsg.hdr.rtm_type = RTM_DELETE as u8;
        rtmsg.hdr.rtm_flags = route_flags(route, false);
        apply_ifscope(&mut rtmsg.hdr, route);
        rtmsg.hdr.rtm_seq = seq;
        rtmsg.hdr.rtm_pid = unsafe { libc::getpid() };
        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        self.write_all(route_msg_bytes(&rtmsg))?;
        Ok(())
    }

    fn get(&mut self, route: &Route) -> io::Result<Route> {
        route.validate()?;

        let mut rtmsg = write_route_addrs(route, RouteRequestKind::Query);
        let seq = next_route_sequence();
        rtmsg.hdr.rtm_type = RTM_GET as u8;
        rtmsg.hdr.rtm_flags = route_flags(route, true);
        apply_ifscope(&mut rtmsg.hdr, route);
        rtmsg.hdr.rtm_seq = seq;
        rtmsg.hdr.rtm_pid = unsafe { libc::getpid() };
        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        // Every routing socket receives every routing message on the host, so
        // a long-lived one fills up between two requests and the kernel drops
        // the reply. A fresh socket is empty, and loopback, on by default,
        // delivers the reply to it.
        let mut socket = Self::open()?;
        socket.write_all(route_msg_bytes(&rtmsg))?;

        let mut response = socket.read_request_response(seq, RTM_GET as u8)?;
        if response.hdr.rtm_errno != 0 {
            return Err(code2error(response.hdr.rtm_errno));
        }

        read_route(&mut response)
    }

    fn monitor(&mut self, buf: &mut [u8]) -> io::Result<(crate::RouteChange, Route)> {
        loop {
            let n = self.read(buf)?;
            let prefix = message_prefix(&buf[..n])?;
            if !matches!(
                prefix.message_type,
                kind if kind == RTM_ADD as u8
                    || kind == RTM_DELETE as u8
                    || kind == RTM_CHANGE as u8
            ) {
                continue;
            }

            let mut rtmsg = m_rtmsg::parse(&buf[..n])?;
            validate_header(&rtmsg.hdr, None)?;
            if rtmsg.hdr.rtm_errno != 0 {
                return Err(code2error(rtmsg.hdr.rtm_errno));
            }

            let change: RouteChange = rtmsg.hdr.rtm_type.into();
            return Ok((change, read_route(&mut rtmsg)?));
        }
    }
}

impl RouteSock {
    pub fn new() -> io::Result<Self> {
        let socket = Self::open()?;
        set_route_loopback(socket.fd, false)?;

        Ok(socket)
    }

    pub fn new_buf() -> [u8; std::mem::size_of::<m_rtmsg>()] {
        m_rtmsg::new_buf()
    }

    fn open() -> io::Result<Self> {
        let fd = syscall!(socket(AF_ROUTE, SOCK_RAW, AF_UNSPEC))?;
        let socket = Self { fd };
        // macOS has no SOCK_CLOEXEC.
        syscall!(fcntl(fd, F_SETFD, FD_CLOEXEC))?;

        Ok(socket)
    }

    fn read_request_response(&mut self, seq: i32, expected_type: u8) -> io::Result<m_rtmsg> {
        let pid = unsafe { libc::getpid() };
        let deadline = Instant::now() + REPLY_TIMEOUT;
        let mut buf = m_rtmsg::new_buf();
        loop {
            self.wait_readable(deadline)?;
            let n = self.read(&mut buf)?;
            // TODO: a foreign message that fails `message_prefix` or `parse`
            // fails this request; only the reply needs strict parsing.
            let prefix = message_prefix(&buf[..n])?;
            if !matches!(
                prefix.message_type,
                kind if kind == RTM_ADD as u8
                    || kind == RTM_DELETE as u8
                    || kind == RTM_CHANGE as u8
                    || kind == RTM_GET as u8
            ) {
                continue;
            }

            let rtmsg = m_rtmsg::parse(&buf[..n])?;
            if rtmsg.hdr.rtm_pid != pid || rtmsg.hdr.rtm_seq != seq {
                continue;
            }
            validate_header(&rtmsg.hdr, Some(expected_type))?;
            return Ok(rtmsg);
        }
    }

    fn wait_readable(&self, deadline: Instant) -> io::Result<()> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no reply on the routing socket",
                ));
            }

            let mut poll_fd = libc::pollfd {
                fd: self.as_raw_fd(),
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
}

fn next_route_sequence() -> i32 {
    // TODO: `fetch_update` is deprecated in favor of `try_update` on current
    // toolchains (also used in `linux/mod.rs`).
    let previous = ROUTE_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |sequence| {
            Some(if sequence == i32::MAX {
                1
            } else {
                sequence + 1
            })
        })
        .expect("sequence update closure always returns Some");

    if previous == i32::MAX {
        1
    } else {
        previous + 1
    }
}

impl Drop for RouteSock {
    fn drop(&mut self) {
        let _ = syscall!(close(self.as_raw_fd()));
    }
}

enum RouteRequestKind {
    Add,
    Delete,
    Query,
}

fn write_route_addrs(route: &Route, kind: RouteRequestKind) -> m_rtmsg {
    let mut rtmsg = m_rtmsg::default();
    rtmsg.hdr.rtm_addrs = RTA_DST;

    if matches!(kind, RouteRequestKind::Add | RouteRequestKind::Delete) {
        rtmsg.hdr.rtm_addrs |= RTA_NETMASK;
    }
    if matches!(kind, RouteRequestKind::Add) && route.gateway.is_some() {
        rtmsg.hdr.rtm_addrs |= RTA_GATEWAY;
    }
    if matches!(kind, RouteRequestKind::Add) && route.gateway.is_none() && route.ifindex.is_some() {
        // `route add ... -interface ifname` is encoded as a link-layer gateway.
        // The route CLI does not also send RTA_IFP for this path.
        rtmsg.hdr.rtm_addrs |= RTA_GATEWAY;
    }
    // Query asks the kernel to fill in IFP, so the slot must be reserved
    // even when the caller does not yet know the ifindex.
    if matches!(kind, RouteRequestKind::Query) {
        rtmsg.hdr.rtm_addrs |= RTA_IFP;
    }

    for offset in 0..RTAX_MAX {
        let bit = 1 << offset;
        if rtmsg.hdr.rtm_addrs & bit == 0 {
            continue;
        }

        match bit {
            RTA_DST => rtmsg.put_destination(&route.destination),
            RTA_GATEWAY => {
                if let Some(gateway) = route.gateway {
                    rtmsg.put_gateway(&gateway);
                } else if let Some(ifindex) = route.ifindex {
                    rtmsg.put_index(ifindex);
                }
            }
            RTA_NETMASK => rtmsg.put_netmask(&route.mask()),
            RTA_IFP => rtmsg.put_index(route.ifindex.unwrap_or(0)),
            _ => {}
        }
    }

    rtmsg
}

fn route_flags(route: &Route, gateway: bool) -> i32 {
    let mut flags = RTF_STATIC | RTF_UP;

    if is_host_route(route) {
        flags |= RTF_HOST;
    }
    if gateway {
        flags |= RTF_GATEWAY;
    }

    flags
}

/// Apply `RTF_IFSCOPE` and `rtm_index` together for a scoped route. XNU
/// encodes interface-scope in two coupled fields — the flag in
/// `rtm_flags` and the ifindex in `rtm_msghdr.rtm_index` — so every
/// request kind (ADD / DELETE / GET) needs to touch both or the kernel
/// silently ignores the scope. Keep the coupling local to this helper
/// so the two halves cannot drift again.
fn apply_ifscope(hdr: &mut rt_msghdr, route: &Route) {
    if let Some(scope) = route.scope_ifindex {
        hdr.rtm_flags |= RTF_IFSCOPE;
        hdr.rtm_index = scope as u16;
    }
}

fn is_host_route(route: &Route) -> bool {
    match route.destination {
        std::net::IpAddr::V4(_) => route.prefix == 32,
        std::net::IpAddr::V6(_) => route.prefix == 128,
    }
}

fn read_route(rtmsg: &mut m_rtmsg) -> io::Result<Route> {
    let mut ret = Route::default();
    rtmsg.attr_len = 0;
    for offset in 0..RTAX_MAX {
        let bit = 1 << offset;
        if rtmsg.hdr.rtm_addrs & bit == 0 {
            continue;
        }

        match bit {
            RTA_DST => ret.destination = rtmsg.get_destination()?,
            RTA_GATEWAY => {
                if rtmsg.hdr.rtm_flags & RTF_GATEWAY != 0 {
                    ret.gateway = Some(rtmsg.get_gateway()?);
                } else {
                    rtmsg.skip_addr()?;
                }
            }
            RTA_NETMASK => ret.cidr(rtmsg.get_netmask(if ret.destination.is_ipv4() {
                AF_INET as u8
            } else {
                AF_INET6 as u8
            })?),
            RTA_IFP => ret.ifindex = Some(rtmsg.get_index()?),
            _ => rtmsg.skip_addr()?,
        }
    }

    // Scope lives outside the sockaddr table: the flag is in `rtm_flags`
    // and the bound ifindex is in `rt_msghdr.rtm_index`. Reading them
    // back keeps round-trips (`add` -> `get`, `monitor` events) lossless.
    if rtmsg.hdr.rtm_flags & RTF_IFSCOPE != 0 {
        ret.scope_ifindex = Some(rtmsg.hdr.rtm_index as u32);
    }

    rtmsg.attr_len = 0;
    Ok(ret)
}

fn route_msg_bytes(rtmsg: &m_rtmsg) -> &[u8] {
    let ptr = rtmsg as *const m_rtmsg as *const u8;
    let len = rtmsg.hdr.rtm_msglen as usize;

    unsafe { std::slice::from_raw_parts(ptr, len) }
}

fn validate_header(hdr: &rt_msghdr, expected_type: Option<u8>) -> io::Result<()> {
    if hdr.rtm_version != RTM_VERSION as u8 {
        return Err(io::Error::other(format!(
            "unexpected routing message version {}",
            hdr.rtm_version
        )));
    }

    if let Some(expected_type) = expected_type
        && hdr.rtm_type != expected_type
    {
        return Err(io::Error::other(format!(
            "unexpected routing message type {}",
            hdr.rtm_type
        )));
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MessagePrefix {
    message_type: u8,
}

fn message_prefix(bytes: &[u8]) -> io::Result<MessagePrefix> {
    if bytes.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated routing message prefix",
        ));
    }

    let message_len = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
    if message_len < 4 || message_len > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid routing message length {message_len} for {} received bytes",
                bytes.len()
            ),
        ));
    }
    if bytes[2] != RTM_VERSION as u8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected routing message version {}", bytes[2]),
        ));
    }

    Ok(MessagePrefix {
        message_type: bytes[3],
    })
}

fn code2error(err: i32) -> io::Error {
    io::Error::from_raw_os_error(err)
}

fn set_route_loopback(fd: RawFd, enabled: bool) -> io::Result<()> {
    let enabled = i32::from(enabled);
    syscall!(setsockopt(
        fd,
        SOL_SOCKET,
        SO_USELOOPBACK,
        (&enabled as *const i32).cast(),
        std::mem::size_of_val(&enabled) as _
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr},
    };

    use super::*;

    #[test]
    fn add_by_interface_uses_link_gateway_without_ifp() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 32).ifindex(4);

        let rtmsg = write_route_addrs(&route, RouteRequestKind::Add);

        assert_eq!(rtmsg.hdr.rtm_addrs, RTA_DST | RTA_GATEWAY | RTA_NETMASK);
    }

    #[test]
    fn query_reserves_ifp_slot() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 32);

        let rtmsg = write_route_addrs(&route, RouteRequestKind::Query);

        assert_eq!(rtmsg.hdr.rtm_addrs, RTA_DST | RTA_IFP);
    }

    #[test]
    fn host_route_sets_host_flag() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 32);

        assert_ne!(route_flags(&route, false) & RTF_HOST, 0);
    }

    #[test]
    fn netmask_sockaddr_is_compacted_like_route_cli() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 24);

        let rtmsg = write_route_addrs(&route, RouteRequestKind::Add);

        assert_eq!(rtmsg.attr[16] as u8, 7);
    }

    #[test]
    fn default_route_netmask_uses_empty_sockaddr_slot() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

        let rtmsg = write_route_addrs(&route, RouteRequestKind::Add);

        assert_eq!(rtmsg.attr[16] as u8, 0);
        assert_eq!(rtmsg.attr_len, 20);
    }

    #[test]
    fn apply_ifscope_sets_both_flag_and_index() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))
            .ifscope(7);

        let mut rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_flags = route_flags(&route, true);
        apply_ifscope(&mut rtmsg.hdr, &route);

        assert_ne!(rtmsg.hdr.rtm_flags & RTF_IFSCOPE, 0);
        assert_eq!(rtmsg.hdr.rtm_index, 7);
    }

    #[test]
    fn apply_ifscope_no_scope_leaves_header_untouched() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));

        let mut rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_flags = route_flags(&route, true);
        apply_ifscope(&mut rtmsg.hdr, &route);

        assert_eq!(rtmsg.hdr.rtm_flags & RTF_IFSCOPE, 0);
        assert_eq!(rtmsg.hdr.rtm_index, 0);
    }

    #[test]
    fn read_route_preserves_scope() {
        let mut rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_flags = RTF_IFSCOPE;
        rtmsg.hdr.rtm_index = 11;
        // No sockaddr table — RTA bits are all zero, so read_route just
        // sees the scope metadata in the header.
        rtmsg.hdr.rtm_addrs = 0;
        rtmsg.hdr.rtm_msglen = std::mem::size_of::<rt_msghdr>() as u16;

        let route = read_route(&mut rtmsg).unwrap();
        assert_eq!(route.scope_ifindex, Some(11));
    }

    #[test]
    fn read_route_without_scope_returns_none() {
        let mut rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_flags = 0;
        rtmsg.hdr.rtm_index = 42;
        rtmsg.hdr.rtm_addrs = 0;
        rtmsg.hdr.rtm_msglen = std::mem::size_of::<rt_msghdr>() as u16;

        let route = read_route(&mut rtmsg).unwrap();
        assert_eq!(route.scope_ifindex, None);
    }

    #[test]
    fn route_message_parser_accepts_an_unaligned_slice() {
        let expected = Route::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 0)), 24)
            .gateway(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 1)));
        let mut wire = write_route_addrs(&expected, RouteRequestKind::Add);
        wire.hdr.rtm_flags = RTF_GATEWAY;
        wire.hdr.rtm_msglen = wire.len() as u16;

        let mut unaligned = vec![0xAA];
        unaligned.extend_from_slice(route_msg_bytes(&wire));
        let mut parsed = m_rtmsg::parse(&unaligned[1..]).unwrap();

        let actual = read_route(&mut parsed).unwrap();
        assert_eq!(actual.destination, expected.destination);
        assert_eq!(actual.prefix, expected.prefix);
        assert_eq!(actual.gateway, expected.gateway);
    }

    #[test]
    fn route_message_parser_rejects_short_and_inconsistent_lengths() {
        let short_error = m_rtmsg::parse(&[0; 4]).err().unwrap();
        assert_eq!(short_error.kind(), io::ErrorKind::UnexpectedEof);

        let mut wire = m_rtmsg::default();
        wire.hdr.rtm_msglen = (std::mem::size_of::<rt_msghdr>() + 1) as u16;
        let bytes = &route_msg_bytes(&wire)[..std::mem::size_of::<rt_msghdr>()];
        let length_error = m_rtmsg::parse(bytes).err().unwrap();
        assert_eq!(length_error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn route_parser_rejects_a_declared_but_missing_attribute() {
        let mut message = m_rtmsg::default();
        message.hdr.rtm_msglen = std::mem::size_of::<rt_msghdr>() as u16;
        message.hdr.rtm_addrs = RTA_DST;

        let error = read_route(&mut message).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn raw_route_errno_is_preserved() {
        let error = code2error(libc::ENOBUFS);

        assert_eq!(error.raw_os_error(), Some(libc::ENOBUFS));
    }

    #[test]
    fn routing_sequences_are_unique_across_concurrent_callers() {
        let handles: Vec<_> = (0..32)
            .map(|_| std::thread::spawn(next_route_sequence))
            .collect();
        let sequences: HashSet<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(sequences.len(), 32);
        assert!(sequences.iter().all(|sequence| *sequence > 0));
    }

    fn queued_bytes(socket: &RouteSock) -> i32 {
        let mut queued = 0;
        syscall!(ioctl(socket.as_raw_fd(), libc::FIONREAD, &mut queued)).unwrap();
        queued
    }

    #[test]
    #[ignore = "black-box check against the live macOS routing socket"]
    fn get_answers_on_a_full_socket() {
        let route = Route::default();
        let mut full = RouteSock::new().unwrap();
        let mut flooder = RouteSock::new().unwrap();
        let mut capacity = 0;
        let mut capacity_len = std::mem::size_of_val(&capacity) as libc::socklen_t;
        syscall!(getsockopt(
            full.as_raw_fd(),
            SOL_SOCKET,
            libc::SO_RCVBUF,
            (&mut capacity as *mut i32).cast(),
            &mut capacity_len
        ))
        .unwrap();

        // Every reply reaches every routing socket, until one no longer fits.
        let dropped = (0..10_000).any(|_| {
            let queued = queued_bytes(&full);
            flooder.get(&route).unwrap();
            queued_bytes(&full) == queued
        });
        assert!(
            dropped && queued_bytes(&full) > capacity / 2,
            "the replies never filled the receive buffer"
        );

        full.get(&route).unwrap();
    }

    #[test]
    #[ignore = "requires root and temporarily installs a reserved test route"]
    fn mutation_write_reports_duplicate_and_missing_route_errors_without_echo() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(198, 18, 255, 254)), 32)
            .ifindex(crate::if_nametoindex("lo0").unwrap());
        let mut socket = RouteSock::new().unwrap();

        socket.add(&route).unwrap();
        let duplicate = socket.add(&route);
        let cleanup = socket.delete(&route);

        cleanup.unwrap();
        assert_eq!(duplicate.unwrap_err().raw_os_error(), Some(libc::EEXIST));
        assert_eq!(
            socket.delete(&route).unwrap_err().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
}
