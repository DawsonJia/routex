//! The addresses of an interface.

use std::{io, net::IpAddr};

/// An address of an interface: `ip/prefix` on interface `ifindex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    pub ifindex: u32,
    pub ip: IpAddr,
    /// How much of `ip` is the prefix that is on the link of the interface.
    pub prefix: u8,
    /// The address at the other end of a point-to-point link, of the family
    /// of `ip`. The route the address brings is then to the peer, not to
    /// the prefix.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub peer: Option<IpAddr>,
}

impl Address {
    pub fn new(ifindex: u32, ip: IpAddr, prefix: u8) -> Address {
        Address {
            ifindex,
            ip,
            prefix,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            peer: None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn peer(mut self, peer: IpAddr) -> Address {
        self.peer = Some(peer);
        self
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        let invalid = |message: String| Err(io::Error::new(io::ErrorKind::InvalidInput, message));

        let max_prefix = match self.ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if self.prefix > max_prefix {
            return invalid(format!("invalid prefix {} for {}", self.prefix, self.ip));
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(peer) = self.peer
            && peer.is_ipv4() != self.ip.is_ipv4()
        {
            return invalid(format!("peer {peer} does not match address {}", self.ip));
        }

        // XNU takes a netmask of 0 for none, and gives the address the mask
        // of its class instead.
        #[cfg(target_os = "macos")]
        if self.ip.is_ipv4() && self.prefix == 0 {
            return invalid(format!("macOS has no IPv4 prefix 0 for {}", self.ip));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn assert_invalid(address: Address) {
        assert_eq!(
            address.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "{address:?}"
        );
    }

    #[test]
    fn prefixes_fit_the_family() {
        let v4 = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        assert!(Address::new(7, v4, 32).validate().is_ok());
        assert!(Address::new(7, v6, 128).validate().is_ok());
        assert_invalid(Address::new(7, v4, 33));
        assert_invalid(Address::new(7, v6, 129));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_peer_is_of_the_family_of_the_address() {
        let v4 = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        assert!(Address::new(7, v4, 32).peer(v4).validate().is_ok());
        assert!(Address::new(7, v6, 128).peer(v6).validate().is_ok());
        assert_invalid(Address::new(7, v4, 32).peer(v6));
        assert_invalid(Address::new(7, v6, 128).peer(v4));
    }

    #[test]
    fn an_ipv4_prefix_of_0_is_invalid_where_the_kernel_takes_it_for_none() {
        let address = Address::new(7, IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 0);

        assert_eq!(address.validate().is_err(), cfg!(target_os = "macos"));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(Address::new(7, v6, 0).validate().is_ok());
    }
}
