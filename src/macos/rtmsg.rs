//! The messages of routing sockets: an `rt_msghdr`, then the sockaddrs that
//! its `rtm_addrs` bits name, in bit order, each padded to 4 bytes.

use std::{
    io,
    mem::{offset_of, size_of},
    net::IpAddr,
};

use libc::{
    AF_INET, AF_INET6, AF_LINK, RTA_NETMASK, RTAX_MAX, RTM_VERSION, rt_msghdr, sockaddr_dl,
    sockaddr_in, sockaddr_in6,
};

pub(super) const HEADER_LEN: usize = size_of::<rt_msghdr>();

/// Holds any routing message: a header and `RTAX_MAX` sockaddrs, each at
/// most 255 bytes long.
pub(super) const MESSAGE_CAPACITY: usize = HEADER_LEN + RTAX_MAX as usize * roundup(255);

/// The type of the routing message in `bytes`. Every routing message, not
/// only the `rt_msghdr` ones, starts with its length, version and type.
pub(super) fn message_type(bytes: &[u8]) -> Option<u8> {
    bytes.get(offset_of!(rt_msghdr, rtm_type)).copied()
}

/// Builds a request: the sockaddrs, in the order of their `RTA_*` bits, then
/// the header.
pub(super) struct Writer {
    message: Vec<u8>,
    addrs: i32,
}

impl Writer {
    pub(super) fn new() -> Self {
        Self {
            message: vec![0; HEADER_LEN],
            addrs: 0,
        }
    }

    pub(super) fn inet(&mut self, bit: i32, addr: IpAddr) {
        self.push(bit, &inet_sockaddr(addr));
    }

    pub(super) fn link(&mut self, bit: i32, ifindex: u32) {
        let mut sockaddr = vec![0; size_of::<sockaddr_dl>()];
        sockaddr[0] = sockaddr.len() as u8;
        sockaddr[1] = AF_LINK as u8;
        set(
            &mut sockaddr,
            offset_of!(sockaddr_dl, sdl_index),
            &(ifindex as u16).to_ne_bytes(),
        );
        self.push(bit, &sockaddr);
    }

    /// Writes `mask` as `route` does: cut after its last nonzero byte, and a
    /// zero mask as an empty sockaddr.
    pub(super) fn netmask(&mut self, mask: IpAddr) {
        let mut sockaddr = if mask.is_unspecified() {
            Vec::new()
        } else {
            inet_sockaddr(mask)
        };
        let len = sockaddr
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |last| last + 1);
        sockaddr.truncate(len);
        if let Some(sa_len) = sockaddr.first_mut() {
            *sa_len = len as u8;
        }
        self.push(RTA_NETMASK, &sockaddr);
    }

    fn push(&mut self, bit: i32, sockaddr: &[u8]) {
        debug_assert!(bit > self.addrs, "sockaddrs out of RTA_* order");
        self.addrs |= bit;
        self.message.extend_from_slice(sockaddr);
        self.message.resize(
            self.message.len() + roundup(sockaddr.len()) - sockaddr.len(),
            0,
        );
    }

    /// The request, with the header fields a request sets; the others stay
    /// zero.
    pub(super) fn finish(mut self, rtm_type: i32, flags: i32, index: u16, seq: i32) -> Vec<u8> {
        let message = &mut self.message;
        let len = message.len() as u16;
        let pid = std::process::id() as i32;
        set(
            message,
            offset_of!(rt_msghdr, rtm_msglen),
            &len.to_ne_bytes(),
        );
        set(
            message,
            offset_of!(rt_msghdr, rtm_version),
            &[RTM_VERSION as u8],
        );
        set(message, offset_of!(rt_msghdr, rtm_type), &[rtm_type as u8]);
        set(
            message,
            offset_of!(rt_msghdr, rtm_index),
            &index.to_ne_bytes(),
        );
        set(
            message,
            offset_of!(rt_msghdr, rtm_flags),
            &flags.to_ne_bytes(),
        );
        set(
            message,
            offset_of!(rt_msghdr, rtm_addrs),
            &self.addrs.to_ne_bytes(),
        );
        set(message, offset_of!(rt_msghdr, rtm_pid), &pid.to_ne_bytes());
        set(message, offset_of!(rt_msghdr, rtm_seq), &seq.to_ne_bytes());

        self.message
    }
}

/// A routing message received from the kernel.
pub(super) struct Message<'a> {
    pub hdr: rt_msghdr,
    addrs: &'a [u8],
}

impl<'a> Message<'a> {
    pub(super) fn parse(bytes: &'a [u8]) -> io::Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated routing message header",
            ));
        }

        // Routing sockets return byte buffers with no Rust alignment
        // guarantee. Copy the wire header into an owned, aligned value before
        // inspecting any fields.
        let hdr = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<rt_msghdr>()) };
        let len = hdr.rtm_msglen as usize;
        if len < HEADER_LEN || len > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid routing message length {len} for {} received bytes",
                    bytes.len()
                ),
            ));
        }
        if hdr.rtm_version != RTM_VERSION as u8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected routing message version {}", hdr.rtm_version),
            ));
        }

        Ok(Self {
            hdr,
            addrs: &bytes[HEADER_LEN..len],
        })
    }

    /// The sockaddrs of the message, each with its `RTA_*` bit.
    pub(super) fn sockaddrs(&self) -> impl Iterator<Item = io::Result<(i32, Sockaddr<'a>)>> {
        let addrs = self.hdr.rtm_addrs;
        let mut rest = self.addrs;
        (0..RTAX_MAX)
            .map(|offset| 1 << offset)
            .filter(move |bit| addrs & bit != 0)
            .map(move |bit| {
                let len = usize::from(*rest.first().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "missing routing sockaddr")
                })?);
                let slot = rest.get(..roundup(len)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "truncated routing sockaddr")
                })?;
                rest = &rest[slot.len()..];

                Ok((bit, Sockaddr(&slot[..len])))
            })
    }
}

/// A sockaddr of a routing message. A netmask may be cut after its last
/// nonzero byte, its family included.
#[derive(Clone, Copy)]
pub(super) struct Sockaddr<'a>(&'a [u8]);

impl Sockaddr<'_> {
    pub(super) fn family(&self) -> u8 {
        self.field::<1>(1)[0]
    }

    pub(super) fn ip(&self) -> io::Result<IpAddr> {
        self.ip_of(self.family())
    }

    /// The address, read as one of `family`.
    pub(super) fn ip_of(&self, family: u8) -> io::Result<IpAddr> {
        match i32::from(family) {
            AF_INET => Ok(IpAddr::from(
                self.field::<4>(offset_of!(sockaddr_in, sin_addr)),
            )),
            AF_INET6 => Ok(IpAddr::from(
                self.field::<16>(offset_of!(sockaddr_in6, sin6_addr)),
            )),
            family => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported sockaddr family {family}"),
            )),
        }
    }

    /// The interface index of a link sockaddr, if it names one.
    pub(super) fn link_index(&self) -> io::Result<Option<u32>> {
        if i32::from(self.family()) != AF_LINK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected link sockaddr, found family {}", self.family()),
            ));
        }

        let index = u16::from_ne_bytes(self.field(offset_of!(sockaddr_dl, sdl_index)));
        Ok((index != 0).then_some(u32::from(index)))
    }

    /// `N` bytes at `offset`; the ones a cut sockaddr leaves out are zero.
    fn field<const N: usize>(&self, offset: usize) -> [u8; N] {
        let present = self.0.get(offset..).unwrap_or_default();
        let len = present.len().min(N);
        let mut field = [0; N];
        field[..len].copy_from_slice(&present[..len]);
        field
    }
}

fn inet_sockaddr(addr: IpAddr) -> Vec<u8> {
    let (mut sockaddr, family) = match addr {
        IpAddr::V4(addr) => {
            let mut sockaddr = vec![0; size_of::<sockaddr_in>()];
            set(
                &mut sockaddr,
                offset_of!(sockaddr_in, sin_addr),
                &addr.octets(),
            );
            (sockaddr, AF_INET)
        }
        IpAddr::V6(addr) => {
            let mut sockaddr = vec![0; size_of::<sockaddr_in6>()];
            set(
                &mut sockaddr,
                offset_of!(sockaddr_in6, sin6_addr),
                &addr.octets(),
            );
            (sockaddr, AF_INET6)
        }
    };
    sockaddr[0] = sockaddr.len() as u8;
    sockaddr[1] = family as u8;
    sockaddr
}

fn set(bytes: &mut [u8], offset: usize, field: &[u8]) {
    bytes[offset..offset + field.len()].copy_from_slice(field);
}

/// The space a sockaddr of `len` bytes takes; an empty one takes 4 too.
const fn roundup(len: usize) -> usize {
    if len == 0 { 4 } else { len.next_multiple_of(4) }
}
