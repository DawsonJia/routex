//! The ioctls that configure an interface: its addresses, MTU and flags.
//! They take the interface by name, on a socket of the family they are of.

use std::{
    io,
    marker::PhantomData,
    mem::{size_of, zeroed},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
};

use libc::{
    AF_INET, AF_INET6, EADDRNOTAVAIL, EINVAL, F_SETFD, FD_CLOEXEC, IFF_POINTOPOINT, IFF_UP,
    IFNAMSIZ, SOCK_DGRAM, c_char, c_int, c_short, c_ulong, ifreq, in6_addrlifetime, in6_ifreq,
    sockaddr_in, sockaddr_in6,
};

use super::{prefix_len, v4_netmask, v6_netmask};
use crate::{Address, missing_address};

/// `struct ifaliasreq` of `net/if.h`, which `libc` leaves out. Its second
/// address is the peer of an address of a point-to-point interface, and the
/// broadcast address of one of a broadcast interface.
#[repr(C)]
struct IfAliasReq {
    name: IfName,
    addr: sockaddr_in,
    dstaddr: sockaddr_in,
    mask: sockaddr_in,
}

/// `struct in6_aliasreq` of `netinet6/in6_var.h`, which `libc` leaves out.
#[repr(C)]
struct In6AliasReq {
    name: IfName,
    addr: sockaddr_in6,
    dstaddr: sockaddr_in6,
    prefixmask: sockaddr_in6,
    flags: c_int,
    lifetime: in6_addrlifetime,
}

type IfName = [c_char; IFNAMSIZ];

/// `ND6_INFINITE_LIFETIME`: the address never expires.
const INFINITE_LIFETIME: u32 = u32::MAX;

/// An ioctl of the `'i'` group that takes a `T`, encoded as `_IOW` and
/// `_IOWR` of `sys/ioccom.h` do: the kernel copies as many bytes as the
/// request says, so a request goes with its one argument type.
struct Request<T>(c_ulong, PhantomData<T>);

impl<T> Request<T> {
    /// `_IOW('i', number, T)`: the kernel reads the `T`.
    const fn write(number: u8) -> Self {
        Self::new(0x8000_0000, number)
    }

    /// `_IOWR('i', number, T)`: the kernel reads the `T` and writes it back.
    const fn read_write(number: u8) -> Self {
        Self::new(0xc000_0000, number)
    }

    const fn new(direction: c_ulong, number: u8) -> Self {
        // IOCPARM_MASK: the length of the argument has 13 bits.
        assert!(size_of::<T>() <= 0x1fff);
        let len = (size_of::<T>() as c_ulong) << 16;
        let group = (b'i' as c_ulong) << 8;
        Self(direction | len | group | number as c_ulong, PhantomData)
    }
}

const SIOCSIFADDR: Request<ifreq> = Request::write(12);
const SIOCSIFFLAGS: Request<ifreq> = Request::write(16);
const SIOCGIFFLAGS: Request<ifreq> = Request::read_write(17);
const SIOCSIFNETMASK: Request<ifreq> = Request::write(22);
const SIOCDIFADDR: Request<ifreq> = Request::write(25);
const SIOCAIFADDR: Request<IfAliasReq> = Request::write(26);
const SIOCGIFADDR: Request<ifreq> = Request::read_write(33);
const SIOCGIFDSTADDR: Request<ifreq> = Request::read_write(34);
const SIOCGIFMTU: Request<ifreq> = Request::read_write(51);
const SIOCSIFMTU: Request<ifreq> = Request::write(52);
const SIOCDIFADDR_IN6: Request<in6_ifreq> = Request::write(25);
const SIOCAIFADDR_IN6: Request<In6AliasReq> = Request::write(26);
const SIOCGIFDSTADDR_IN6: Request<in6_ifreq> = Request::read_write(34);
const SIOCGIFNETMASK_IN6: Request<in6_ifreq> = Request::read_write(37);

fn ioctl<T>(socket: BorrowedFd<'_>, request: Request<T>, argument: &mut T) -> io::Result<()> {
    syscall!(ioctl(socket.as_raw_fd(), request.0, argument as *mut T))?;

    Ok(())
}

/// A socket to make the interface ioctls of `family` on.
fn socket(family: c_int) -> io::Result<OwnedFd> {
    let fd = syscall!(socket(family, SOCK_DGRAM, 0))?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // macOS has no SOCK_CLOEXEC.
    syscall!(fcntl(fd.as_raw_fd(), F_SETFD, FD_CLOEXEC))?;

    Ok(fd)
}

/// The name of the interface `ifindex`; fails with `ENXIO` if there is none.
fn name(ifindex: u32) -> io::Result<IfName> {
    let mut name = [0; IFNAMSIZ];
    if unsafe { libc::if_indextoname(ifindex, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }

    Ok(name)
}

/// A request about the interface `name`, the rest of it zero.
fn if_request(name: IfName) -> ifreq {
    let mut request: ifreq = unsafe { zeroed() };
    request.ifr_name = name;
    request
}

/// A request about the address `ip` of the interface `name`.
fn in6_request(name: IfName, ip: Ipv6Addr) -> in6_ifreq {
    let mut request: in6_ifreq = unsafe { zeroed() };
    request.ifr_name = name;
    request.ifr_ifru.ifru_addr = in6_sockaddr(ip);
    request
}

pub(super) fn replace_address(address: &Address) -> io::Result<()> {
    let name = name(address.ifindex)?;
    match address.ip {
        IpAddr::V4(ip) => replace_v4(name, ip, address.prefix, address.peer.and_then(v4)),
        IpAddr::V6(ip) => replace_v6(name, ip, address.prefix, address.peer.and_then(v6)),
    }
}

pub(super) fn delete_address(address: &Address) -> io::Result<()> {
    let name = name(address.ifindex)?;
    match address.ip {
        IpAddr::V4(ip) => {
            let mut request = if_request(name);
            request.ifr_ifru.ifru_addr = in_sockaddr(ip);
            ioctl(socket(AF_INET)?.as_fd(), SIOCDIFADDR, &mut request)
        }
        IpAddr::V6(ip) => ioctl(
            socket(AF_INET6)?.as_fd(),
            SIOCDIFADDR_IN6,
            &mut in6_request(name, ip),
        ),
    }
    .map_err(missing_address)
}

pub(super) fn set_mtu(ifindex: u32, mtu: u32) -> io::Result<()> {
    let mut request = if_request(name(ifindex)?);
    // The kernel reads it back as the unsigned number it is, and refuses
    // the MTUs it does not take.
    request.ifr_ifru.ifru_mtu = mtu as c_int;

    ioctl(socket(AF_INET)?.as_fd(), SIOCSIFMTU, &mut request)
}

pub(super) fn get_mtu(ifindex: u32) -> io::Result<u32> {
    let mut request = if_request(name(ifindex)?);
    ioctl(socket(AF_INET)?.as_fd(), SIOCGIFMTU, &mut request)?;

    Ok(unsafe { request.ifr_ifru.ifru_mtu } as u32)
}

pub(super) fn set_up(ifindex: u32, up: bool) -> io::Result<()> {
    let socket = socket(AF_INET)?;
    let mut request = if_request(name(ifindex)?);
    let flags = flags(socket.as_fd(), &mut request)?;
    request.ifr_ifru.ifru_flags = if up {
        flags | IFF_UP as c_short
    } else {
        flags & !(IFF_UP as c_short)
    };

    ioctl(socket.as_fd(), SIOCSIFFLAGS, &mut request)
}

/// The flags of the interface of `request`, which the kernel fills in.
fn flags(socket: BorrowedFd<'_>, request: &mut ifreq) -> io::Result<c_short> {
    ioctl(socket, SIOCGIFFLAGS, request)?;

    Ok(unsafe { request.ifr_ifru.ifru_flags })
}

fn replace_v4(name: IfName, ip: Ipv4Addr, prefix: u8, peer: Option<Ipv4Addr>) -> io::Result<()> {
    let socket = socket(AF_INET)?;
    let point_to_point =
        flags(socket.as_fd(), &mut if_request(name))? & IFF_POINTOPOINT as c_short != 0;
    match (peer, point_to_point) {
        // SIOCAIFADDR fails an address of a point-to-point interface that
        // has no peer with EDESTADDRREQ.
        (None, true) => set_peerless(socket.as_fd(), name, ip, prefix),
        // XNU takes the peer for the broadcast address of a broadcast
        // interface, and drops it on any other.
        (Some(peer), false) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("peer {peer} on an interface that is not point-to-point"),
        )),
        // Adds the address, or changes the prefix and peer of the one that
        // is there.
        (peer, _) => {
            let mut request = IfAliasReq {
                name,
                addr: in_sockaddr_in(ip),
                dstaddr: peer.map_or(unsafe { zeroed() }, in_sockaddr_in),
                mask: in_sockaddr_in(v4_netmask(prefix)),
            };
            ioctl(socket.as_fd(), SIOCAIFADDR, &mut request)
        }
    }
}

/// Sets `ip/prefix` as the address without a peer of a point-to-point
/// interface, which is the first IPv4 address of the interface or none:
/// SIOCSIFADDR and SIOCSIFNETMASK change the address they name, or else the
/// first one, whatever it is, and keep its peer.
fn set_peerless(socket: BorrowedFd<'_>, name: IfName, ip: Ipv4Addr, prefix: u8) -> io::Result<()> {
    let invalid = |message: String| Err(io::Error::new(io::ErrorKind::InvalidInput, message));

    // A request that names no address is about the first one.
    let mut first = if_request(name);
    match ioctl(socket, SIOCGIFADDR, &mut first) {
        Err(error) if error.raw_os_error() == Some(EADDRNOTAVAIL) => {}
        Err(error) => return Err(error),
        Ok(()) => {
            let first_ip = sockaddr_ip(unsafe { first.ifr_ifru.ifru_addr });
            if first_ip != Some(ip) {
                return invalid(format!(
                    "{ip} without a peer would take the place of {first_ip:?}, the first IPv4 \
                     address of a point-to-point interface"
                ));
            }
            let mut peer = if_request(name);
            ioctl(socket, SIOCGIFDSTADDR, &mut peer)?;
            if let Some(peer) = sockaddr_ip(unsafe { peer.ifr_ifru.ifru_dstaddr }) {
                return invalid(format!("{ip} would keep its peer {peer}"));
            }
        }
    }

    let mut address = if_request(name);
    address.ifr_ifru.ifru_addr = in_sockaddr(ip);
    let mut netmask = if_request(name);
    netmask.ifr_ifru.ifru_addr = in_sockaddr(v4_netmask(prefix));

    // SIOCSIFNETMASK needs the address to be there, and leaves the net and
    // subnet that XNU derived from the old mask: setting the address again
    // derives them from the new one.
    ioctl(socket, SIOCSIFADDR, &mut address)?;
    ioctl(socket, SIOCSIFNETMASK, &mut netmask)?;
    ioctl(socket, SIOCSIFADDR, &mut address)
}

fn replace_v6(name: IfName, ip: Ipv6Addr, prefix: u8, peer: Option<Ipv6Addr>) -> io::Result<()> {
    let socket = socket(AF_INET6)?;
    let add = |(prefix, peer): (u8, Option<Ipv6Addr>)| {
        let mut request = In6AliasReq {
            name,
            addr: in6_sockaddr(ip),
            // No peer is a sockaddr of no family.
            dstaddr: peer.map_or(unsafe { zeroed() }, in6_sockaddr),
            prefixmask: in6_sockaddr(v6_netmask(prefix)),
            flags: 0,
            lifetime: in6_addrlifetime {
                ia6t_expire: 0,
                ia6t_preferred: 0,
                ia6t_vltime: INFINITE_LIFETIME,
                ia6t_pltime: INFINITE_LIFETIME,
            },
        };
        ioctl(socket.as_fd(), SIOCAIFADDR_IN6, &mut request)
    };

    match v6_prefix_and_peer(socket.as_fd(), name, ip)? {
        // XNU gives an address its prefix and peer when it adds it, and
        // changes neither after: one that is there with another goes first,
        // and comes back if the kernel refuses the new one.
        Some(current) if current != (prefix, peer) => {
            ioctl(socket.as_fd(), SIOCDIFADDR_IN6, &mut in6_request(name, ip))?;
            add((prefix, peer)).inspect_err(|_| {
                let _ = add(current);
            })
        }
        _ => add((prefix, peer)),
    }
}

/// The prefix and peer of the address `ip` of the interface `name`, if the
/// interface has it.
fn v6_prefix_and_peer(
    socket: BorrowedFd<'_>,
    name: IfName,
    ip: Ipv6Addr,
) -> io::Result<Option<(u8, Option<Ipv6Addr>)>> {
    let mut netmask = in6_request(name, ip);
    match ioctl(socket, SIOCGIFNETMASK_IN6, &mut netmask) {
        Err(error) if error.raw_os_error() == Some(EADDRNOTAVAIL) => return Ok(None),
        result => result?,
    }
    let netmask = unsafe { netmask.ifr_ifru.ifru_addr }.sin6_addr.s6_addr;
    let prefix = prefix_len(IpAddr::V6(Ipv6Addr::from(netmask)));

    let mut peer = in6_request(name, ip);
    let peer = match ioctl(socket, SIOCGIFDSTADDR_IN6, &mut peer) {
        // TODO: only a point-to-point interface answers. A loopback one can
        // give an address a peer too, which only getifaddrs reports, and
        // which is taken for none here.
        Err(error) if error.raw_os_error() == Some(EINVAL) => None,
        Err(error) => return Err(error),
        // No peer is a sockaddr of no family.
        Ok(()) => {
            let peer = unsafe { peer.ifr_ifru.ifru_dstaddr };
            (c_int::from(peer.sin6_family) == AF_INET6)
                .then(|| Ipv6Addr::from(peer.sin6_addr.s6_addr))
        }
    };

    Ok(Some((prefix, peer)))
}

/// `ip` if it is an IPv4 address; `Address::validate` leaves a peer of the
/// family of its address.
fn v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn v6(ip: IpAddr) -> Option<Ipv6Addr> {
    match ip {
        IpAddr::V4(_) => None,
        IpAddr::V6(ip) => Some(ip),
    }
}

fn in_sockaddr_in(ip: Ipv4Addr) -> sockaddr_in {
    let mut sockaddr: sockaddr_in = unsafe { zeroed() };
    sockaddr.sin_len = size_of::<sockaddr_in>() as u8;
    sockaddr.sin_family = AF_INET as u8;
    sockaddr.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    sockaddr
}

/// `ip` as the `sockaddr` an `ifreq` holds, which is as long as a
/// `sockaddr_in`.
fn in_sockaddr(ip: Ipv4Addr) -> libc::sockaddr {
    unsafe { std::mem::transmute(in_sockaddr_in(ip)) }
}

/// The address of `sockaddr`, if it is an IPv4 one; a `sockaddr` the kernel
/// left zero is of no family.
fn sockaddr_ip(sockaddr: libc::sockaddr) -> Option<Ipv4Addr> {
    let sockaddr: sockaddr_in = unsafe { std::mem::transmute(sockaddr) };
    (c_int::from(sockaddr.sin_family) == AF_INET)
        .then(|| Ipv4Addr::from(sockaddr.sin_addr.s_addr.to_ne_bytes()))
}

fn in6_sockaddr(ip: Ipv6Addr) -> sockaddr_in6 {
    let mut sockaddr: sockaddr_in6 = unsafe { zeroed() };
    sockaddr.sin6_len = size_of::<sockaddr_in6>() as u8;
    sockaddr.sin6_family = AF_INET6 as u8;
    sockaddr.sin6_addr.s6_addr = ip.octets();
    sockaddr
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, ffi::CStr, ptr};

    use super::*;

    #[test]
    fn requests_are_those_of_the_system_headers() {
        // As `sys/sockio.h` and `netinet6/in6_var.h` of the macOS SDK have
        // them.
        assert_eq!(SIOCSIFADDR.0, 0x8020_690c);
        assert_eq!(SIOCSIFFLAGS.0, 0x8020_6910);
        assert_eq!(SIOCGIFFLAGS.0, 0xc020_6911);
        assert_eq!(SIOCSIFNETMASK.0, 0x8020_6916);
        assert_eq!(SIOCDIFADDR.0, 0x8020_6919);
        assert_eq!(SIOCAIFADDR.0, 0x8040_691a);
        assert_eq!(SIOCGIFADDR.0, libc::SIOCGIFADDR);
        assert_eq!(SIOCGIFDSTADDR.0, 0xc020_6922);
        assert_eq!(SIOCGIFMTU.0, 0xc020_6933);
        assert_eq!(SIOCSIFMTU.0, 0x8020_6934);
        assert_eq!(SIOCDIFADDR_IN6.0, 0x8120_6919);
        assert_eq!(SIOCAIFADDR_IN6.0, 0x8080_691a);
        assert_eq!(SIOCGIFDSTADDR_IN6.0, 0xc120_6922);
        assert_eq!(SIOCGIFNETMASK_IN6.0, 0xc120_6925);
    }

    #[test]
    fn sockaddrs_carry_their_length_and_family() {
        let v4 = in_sockaddr_in(Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!((v4.sin_len, v4.sin_family), (16, AF_INET as u8));
        assert_eq!(v4.sin_addr.s_addr.to_ne_bytes(), [198, 18, 0, 1]);
        assert_eq!(
            sockaddr_ip(in_sockaddr(Ipv4Addr::new(198, 18, 0, 1))),
            Some(Ipv4Addr::new(198, 18, 0, 1))
        );
        assert_eq!(sockaddr_ip(unsafe { zeroed() }), None);

        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let v6 = in6_sockaddr(ip);
        assert_eq!((v6.sin6_len, v6.sin6_family), (28, AF_INET6 as u8));
        assert_eq!(v6.sin6_addr.s6_addr, ip.octets());
    }

    fn lo0() -> u32 {
        crate::if_nametoindex("lo0").unwrap()
    }

    fn v4_address(ifindex: u32, last: [u8; 2], prefix: u8) -> Address {
        Address::new(
            ifindex,
            IpAddr::V4(Ipv4Addr::new(198, 18, last[0], last[1])),
            prefix,
        )
    }

    fn v6_address(ifindex: u32, last: [u16; 2], prefix: u8) -> Address {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0xfb, last[0], 0, 0, 0, last[1]);
        Address::new(ifindex, IpAddr::V6(ip), prefix)
    }

    fn assert_kind(result: io::Result<()>, kind: io::ErrorKind) {
        assert_eq!(result.unwrap_err().kind(), kind);
    }

    #[test]
    #[ignore = "black-box check against the live macOS interfaces"]
    fn the_mtu_of_an_interface_is_read_without_root() {
        assert!(get_mtu(lo0()).unwrap() >= 1280);
    }

    #[test]
    #[ignore = "black-box check against the live macOS interfaces"]
    fn an_interface_that_is_not_there_is_the_kernels_error() {
        let missing = 4242;
        let address = v4_address(missing, [251, 1], 24);

        for result in [
            replace_address(&address),
            delete_address(&address),
            set_mtu(missing, 1400),
            set_up(missing, true),
            get_mtu(missing).map(drop),
        ] {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ENXIO));
        }
    }

    #[test]
    #[ignore = "black-box check against the live macOS interfaces"]
    fn a_peer_takes_a_point_to_point_interface() {
        let address = v4_address(lo0(), [251, 1], 32);
        let peer = IpAddr::V4(Ipv4Addr::new(198, 18, 251, 2));

        // Refused before the request that takes root.
        assert_kind(
            replace_address(&address.peer(peer)),
            io::ErrorKind::InvalidInput,
        );
    }

    /// A `utun` interface, which is point-to-point and goes with its
    /// socket.
    struct Utun {
        index: u32,
        _socket: OwnedFd,
    }

    fn utun() -> Utun {
        let fd = syscall!(socket(libc::AF_SYSTEM, SOCK_DGRAM, libc::SYSPROTO_CONTROL)).unwrap();
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut info: libc::ctl_info = unsafe { zeroed() };
        for (to, from) in info.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
            *to = *from as c_char;
        }
        syscall!(ioctl(socket.as_raw_fd(), libc::CTLIOCGINFO, &mut info)).unwrap();

        // Unit 0 asks for the first utun that is free.
        let mut control: libc::sockaddr_ctl = unsafe { zeroed() };
        control.sc_len = size_of::<libc::sockaddr_ctl>() as u8;
        control.sc_family = libc::AF_SYSTEM as u8;
        control.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        control.sc_id = info.ctl_id;
        syscall!(connect(
            socket.as_raw_fd(),
            (&control as *const libc::sockaddr_ctl).cast(),
            size_of::<libc::sockaddr_ctl>() as libc::socklen_t
        ))
        .expect("no utun: its control socket takes root");

        let mut name: IfName = [0; IFNAMSIZ];
        let mut len = IFNAMSIZ as libc::socklen_t;
        syscall!(getsockopt(
            socket.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut len
        ))
        .unwrap();

        Utun {
            index: unsafe { libc::if_nametoindex(name.as_ptr()) },
            _socket: socket,
        }
    }

    /// The bytes of `sockaddr` from `offset` on, zero where it is cut: XNU
    /// cuts a netmask after its last nonzero byte.
    unsafe fn sockaddr_bytes<const N: usize>(
        sockaddr: *const libc::sockaddr,
        offset: usize,
    ) -> [u8; N] {
        let mut bytes = [0; N];
        let len = usize::from(unsafe { (*sockaddr).sa_len });
        let present = len.saturating_sub(offset).min(N);
        unsafe {
            ptr::copy_nonoverlapping(
                sockaddr.cast::<u8>().add(offset),
                bytes.as_mut_ptr(),
                present,
            );
        }
        bytes
    }

    /// The address in `sockaddr`, read as one of `family`.
    unsafe fn sockaddr_address(sockaddr: *const libc::sockaddr, family: c_int) -> IpAddr {
        match family {
            AF_INET => IpAddr::from(unsafe { sockaddr_bytes::<4>(sockaddr, 4) }),
            _ => IpAddr::from(unsafe { sockaddr_bytes::<16>(sockaddr, 8) }),
        }
    }

    /// The addresses the kernel has for the interface `ifindex`, less the
    /// link-local one it adds to an interface with IPv6 itself.
    fn addresses(ifindex: u32) -> HashSet<Address> {
        let name = name(ifindex).unwrap();
        let name = unsafe { CStr::from_ptr(name.as_ptr()) };
        let mut head = ptr::null_mut();
        syscall!(getifaddrs(&mut head)).unwrap();

        let mut addresses = HashSet::new();
        let mut next = head;
        while let Some(entry) = unsafe { next.as_ref() } {
            next = entry.ifa_next;
            if unsafe { CStr::from_ptr(entry.ifa_name) } != name || entry.ifa_addr.is_null() {
                continue;
            }
            let family = c_int::from(unsafe { (*entry.ifa_addr).sa_family });
            if family != AF_INET && family != AF_INET6 {
                continue;
            }
            let ip = unsafe { sockaddr_address(entry.ifa_addr, family) };
            if matches!(ip, IpAddr::V6(ip) if ip.segments()[0] & 0xffc0 == 0xfe80) {
                continue;
            }
            // The netmask of an IPv4 address may be of no family.
            let netmask = unsafe { sockaddr_address(entry.ifa_netmask, family) };
            // The second address of an interface that is not point-to-point
            // is no peer: the broadcast address, or the address itself.
            let peer = (entry.ifa_flags & IFF_POINTOPOINT as u32 != 0
                && !entry.ifa_dstaddr.is_null()
                && c_int::from(unsafe { (*entry.ifa_dstaddr).sa_family }) == family)
                .then(|| unsafe { sockaddr_address(entry.ifa_dstaddr, family) });

            addresses.insert(Address {
                ifindex,
                ip,
                prefix: prefix_len(netmask),
                peer,
            });
        }
        unsafe { libc::freeifaddrs(head) };

        addresses
    }

    fn is_up(ifindex: u32) -> bool {
        let socket = socket(AF_INET).unwrap();
        let mut request = if_request(name(ifindex).unwrap());
        flags(socket.as_fd(), &mut request).unwrap() & IFF_UP as c_short != 0
    }

    #[test]
    #[ignore = "requires root, and configures a utun interface of its own"]
    fn an_ipv4_address_without_a_peer_is_the_first_of_a_point_to_point_interface() {
        let utun = utun();
        let first = v4_address(utun.index, [251, 1], 24);
        let other = v4_address(utun.index, [251, 2], 24);
        let peer = IpAddr::V4(Ipv4Addr::new(198, 18, 250, 2));
        let to_peer = v4_address(utun.index, [250, 1], 32).peer(peer);

        assert_kind(delete_address(&first), io::ErrorKind::NotFound);
        replace_address(&first).unwrap();
        replace_address(&first).unwrap();
        assert_eq!(addresses(utun.index), HashSet::from([first]));

        // Its prefix changes where it is.
        let wider = v4_address(utun.index, [251, 1], 10);
        replace_address(&wider).unwrap();
        assert_eq!(addresses(utun.index), HashSet::from([wider]));

        // Another one would take its place, and one after an address with a
        // peer the place of that.
        assert_kind(replace_address(&other), io::ErrorKind::InvalidInput);
        assert_eq!(addresses(utun.index), HashSet::from([wider]));
        delete_address(&wider).unwrap();
        replace_address(&to_peer).unwrap();
        assert_kind(replace_address(&other), io::ErrorKind::InvalidInput);
        assert_eq!(addresses(utun.index), HashSet::from([to_peer]));

        // The first address keeps a peer it has.
        let peerless = v4_address(utun.index, [250, 1], 32);
        assert_kind(replace_address(&peerless), io::ErrorKind::InvalidInput);
        assert_eq!(addresses(utun.index), HashSet::from([to_peer]));

        delete_address(&to_peer).unwrap();
        assert_kind(delete_address(&to_peer), io::ErrorKind::NotFound);
        assert_eq!(addresses(utun.index), HashSet::new());
    }

    #[test]
    #[ignore = "requires root, and configures a utun interface of its own"]
    fn ipv4_addresses_with_a_peer_change_where_they_are() {
        let utun = utun();
        let first = v4_address(utun.index, [251, 1], 24);
        let alias = v4_address(utun.index, [250, 1], 32);
        let peer = |last| IpAddr::V4(Ipv4Addr::new(198, 18, 250, last));

        // After the address without a peer, as before it.
        replace_address(&first).unwrap();
        replace_address(&alias.peer(peer(2))).unwrap();
        replace_address(&alias.peer(peer(2))).unwrap();
        assert_eq!(
            addresses(utun.index),
            HashSet::from([first, alias.peer(peer(2))])
        );

        // An interface has an ip once: its prefix and peer change.
        let wider = v4_address(utun.index, [250, 1], 24).peer(peer(3));
        replace_address(&wider).unwrap();
        assert_eq!(addresses(utun.index), HashSet::from([first, wider]));
        // The first address gets a peer the same way.
        replace_address(&first.peer(peer(9))).unwrap();
        assert_eq!(
            addresses(utun.index),
            HashSet::from([first.peer(peer(9)), wider])
        );

        // An address is deleted by its ip alone.
        delete_address(&alias).unwrap();
        assert_kind(delete_address(&alias), io::ErrorKind::NotFound);
        delete_address(&first).unwrap();
        assert_eq!(addresses(utun.index), HashSet::new());
    }

    #[test]
    #[ignore = "requires root, and configures a utun interface of its own"]
    fn ipv6_addresses_change_their_prefix_and_peer() {
        let utun = utun();
        let address = v6_address(utun.index, [0, 1], 64);
        let host = v6_address(utun.index, [1, 1], 128);
        let peer = |last| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xfb, 1, 0, 0, 0, last));

        assert_kind(delete_address(&address), io::ErrorKind::NotFound);
        replace_address(&address).unwrap();
        replace_address(&address).unwrap();
        assert_eq!(addresses(utun.index), HashSet::from([address]));

        let wider = v6_address(utun.index, [0, 1], 48);
        replace_address(&wider).unwrap();
        assert_eq!(addresses(utun.index), HashSet::from([wider]));

        replace_address(&host.peer(peer(2))).unwrap();
        replace_address(&host.peer(peer(3))).unwrap();
        assert_eq!(
            addresses(utun.index),
            HashSet::from([wider, host.peer(peer(3))])
        );

        // The kernel takes a peer with a host prefix only, and the address
        // it refuses to change stays as it was.
        let refused = v6_address(utun.index, [1, 1], 64).peer(peer(3));
        assert_eq!(
            replace_address(&refused).unwrap_err().raw_os_error(),
            Some(EINVAL)
        );
        assert_eq!(
            addresses(utun.index),
            HashSet::from([wider, host.peer(peer(3))])
        );

        replace_address(&host).unwrap();
        assert_eq!(addresses(utun.index), HashSet::from([wider, host]));

        delete_address(&host).unwrap();
        delete_address(&wider).unwrap();
        assert_kind(delete_address(&wider), io::ErrorKind::NotFound);
        assert_eq!(addresses(utun.index), HashSet::new());
    }

    #[test]
    #[ignore = "requires root, and configures a utun interface of its own"]
    fn a_link_takes_an_mtu_and_goes_up_and_down() {
        let utun = utun();
        set_up(utun.index, false).unwrap();
        assert!(!is_up(utun.index));

        set_mtu(utun.index, 1400).unwrap();
        assert_eq!(get_mtu(utun.index).unwrap(), 1400);
        assert!(!is_up(utun.index));

        set_up(utun.index, true).unwrap();
        set_up(utun.index, true).unwrap();
        assert!(is_up(utun.index));
        assert_eq!(get_mtu(utun.index).unwrap(), 1400);

        set_up(utun.index, false).unwrap();
        assert!(!is_up(utun.index));

        // The kernel refuses the MTUs it does not take.
        for mtu in [0, u32::MAX] {
            assert_eq!(
                set_mtu(utun.index, mtu).unwrap_err().raw_os_error(),
                Some(EINVAL)
            );
        }
        assert_eq!(get_mtu(utun.index).unwrap(), 1400);
    }

    #[test]
    #[ignore = "requires root and temporarily adds a reserved test address to lo0"]
    fn an_address_without_a_peer_is_an_alias_of_another_interface() {
        /// Takes the address back off lo0, also when the test fails.
        struct Cleanup(Address);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = delete_address(&self.0);
            }
        }

        let lo0 = lo0();
        let address = v4_address(lo0, [251, 1], 32);
        let before = addresses(lo0);
        assert!(!before.contains(&address));

        let _cleanup = Cleanup(address);
        replace_address(&address).unwrap();
        replace_address(&address).unwrap();
        assert!(addresses(lo0).contains(&address));

        // Beside the addresses the interface has, and changed where it is.
        let wider = v4_address(lo0, [251, 1], 24);
        replace_address(&wider).unwrap();
        let mut with_wider = before.clone();
        with_wider.insert(wider);
        assert_eq!(addresses(lo0), with_wider);

        delete_address(&address).unwrap();
        assert_kind(delete_address(&address), io::ErrorKind::NotFound);
        assert_eq!(addresses(lo0), before);
    }
}
