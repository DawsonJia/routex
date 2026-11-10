#![doc = include_str!("../README.md")]

use std::{ffi::CString, io, net::IpAddr};

// Keep raw syscalls inside this crate. Exporting a macro that supplies its own
// `unsafe` block lets downstream safe code pass arbitrary invalid pointers to
// libc without an unsafe call site.
#[cfg(any(target_os = "linux", target_os = "macos"))]
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* ) ) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { libc::$fn($( $arg), *) };
        if res < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod fd;

/// Linux and macOS fail to delete a route that is not there with `ESRCH`,
/// which is `NotFound` here, as on Windows, with the kernel's error as its
/// source.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn missing_route(error: io::Error) -> io::Error {
    if error.raw_os_error() == Some(libc::ESRCH) {
        io::Error::new(io::ErrorKind::NotFound, error)
    } else {
        error
    }
}
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::{Handle, RouteMonitor};
#[cfg(target_os = "macos")]
pub use macos::{Handle, RouteMonitor};
#[cfg(target_os = "windows")]
pub use windows::{Handle, if_friendly_name_to_index};

/// A route: traffic to `destination/prefix` goes through `gateway`, or
/// straight out of interface `ifindex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Route {
    pub destination: IpAddr,
    pub prefix: u8,
    /// The next hop, of the family of `destination`.
    pub gateway: Option<IpAddr>,
    /// The outgoing interface. Without a gateway, the destination is on its
    /// link.
    pub ifindex: Option<u32>,
    /// macOS interface-scoped routing (`RTF_IFSCOPE`). When set, the route
    /// is only matched by lookups whose `IP_BOUND_IF` scope equals this
    /// ifindex. Used to install a per-interface copy of the default route so
    /// that physical-NIC-bound sockets can still reach the internet after a
    /// VPN's `0/1` + `128/1` routes have taken the unscoped default.
    #[cfg(target_os = "macos")]
    pub scope_ifindex: Option<u32>,
}

/// The IPv4 default route, `0.0.0.0/0`.
impl Default for Route {
    fn default() -> Self {
        Route::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    }
}

impl Route {
    pub fn new(destination: IpAddr, prefix: u8) -> Route {
        Route {
            destination,
            prefix,
            gateway: None,
            ifindex: None,
            #[cfg(target_os = "macos")]
            scope_ifindex: None,
        }
    }

    /// The prefix length of a host route to `destination`.
    pub(crate) fn max_prefix(&self) -> u8 {
        match self.destination {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.prefix > self.max_prefix() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid prefix {} for {}", self.prefix, self.destination),
            ));
        }

        if let Some(gateway) = self.gateway
            && std::mem::discriminant(&self.destination) != std::mem::discriminant(&gateway)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "gateway {gateway} does not match destination {}",
                    self.destination
                ),
            ));
        }

        Ok(())
    }

    pub fn gateway(mut self, gateway: IpAddr) -> Route {
        self.gateway = Some(gateway);
        self
    }

    pub fn ifindex(mut self, ifindex: u32) -> Route {
        self.ifindex = Some(ifindex);
        self
    }

    /// Scope this route to a specific interface (`RTF_IFSCOPE`).
    #[cfg(target_os = "macos")]
    pub fn ifscope(mut self, ifindex: u32) -> Route {
        self.scope_ifindex = Some(ifindex);
        self
    }
}

/// A change to the routing table, as reported by [`RouteMonitor`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteChange {
    Add,
    Delete,
    /// An existing route got a new gateway, interface or metrics (macOS).
    Change,
}

/// The index of the interface named `name`.
pub fn if_nametoindex(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;

    #[cfg(not(target_os = "windows"))]
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };

    #[cfg(target_os = "windows")]
    let ifindex = unsafe {
        windows_sys::Win32::NetworkManagement::IpHelper::if_nametoindex(name.as_ptr().cast())
    };

    (ifindex != 0).then_some(ifindex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_missing_route_is_not_found_with_the_kernel_error_as_its_source() {
        let error = missing_route(io::Error::from_raw_os_error(libc::ESRCH));
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let source = error.get_ref().unwrap().downcast_ref::<io::Error>();
        assert_eq!(source.unwrap().raw_os_error(), Some(libc::ESRCH));

        let other = missing_route(io::Error::from_raw_os_error(libc::EPERM));
        assert_eq!(other.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn validate_rejects_prefix_outside_address_family() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 33);

        assert_eq!(
            route.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn validate_rejects_mismatched_gateway_family() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .gateway(IpAddr::V6(Ipv6Addr::LOCALHOST));

        assert_eq!(
            route.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
