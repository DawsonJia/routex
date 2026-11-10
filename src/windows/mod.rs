use std::{
    io,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};

use windows_sys::Win32::{
    Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS,
        ERROR_SUCCESS,
    },
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable,
        GAA_FLAG_INCLUDE_ALL_INTERFACES, GetAdaptersAddresses, GetBestRoute2, GetIpForwardTable2,
        GetIpInterfaceEntry, IP_ADAPTER_ADDRESSES_LH, InitializeIpForwardEntry,
        InitializeIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    },
    Networking::WinSock::{
        ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR,
        MIB_IPPROTO_NETMGMT, NlroManual, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
    },
};

use crate::{Address, Route};

mod interface;

/// Changes and queries the routing table, and the addresses and MTU of the
/// interfaces, through the IP Helper API.
// TODO: a `RouteMonitor` backed by NotifyRouteChange2.
pub struct Handle;

impl Handle {
    pub fn new() -> io::Result<Self> {
        Ok(Self)
    }

    /// Adds `route`. Without an interface, it goes out of the one of the best
    /// route to its gateway, or else to its destination.
    pub fn add_route(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let mut row = route_row(route);
        row.InterfaceIndex = resolve_interface_index(route)?;
        win32_result(unsafe { CreateIpForwardEntry2(&row) })
    }

    /// Deletes the one route that `route` selects by destination, and by
    /// gateway and interface where they are set.
    pub fn delete_route(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let row = find_unique_route(route)?;
        win32_result(unsafe { DeleteIpForwardEntry2(&row) })
    }

    /// The best route to `route.destination`, out of `route.ifindex` if it is
    /// set. The unspecified address with prefix 0 asks for the default route,
    /// through the gateway and interface of `route` where they are set.
    pub fn get_route(&mut self, route: &Route) -> io::Result<Route> {
        route.validate()?;

        // GetBestRoute2 treats an unspecified destination as a lookup target, not as "show default route".
        let row = if route.destination.is_unspecified() && route.prefix == 0 {
            best_matching_route(route)?
        } else {
            best_route(route.destination, route.ifindex.unwrap_or(0))?
        };

        route_from_row(&row)
    }

    /// Makes `address` an address of its interface, whether or not it is
    /// one already. An interface has an `ip` once, so this changes the
    /// prefix of the one that is there, which an adapter that is opened
    /// again may have kept.
    pub fn replace_address(&mut self, address: &Address) -> io::Result<()> {
        address.validate()?;

        interface::replace_address(address)
    }

    /// Deletes the address `address.ip` from its interface, whatever its
    /// prefix; fails with `NotFound` if there is none.
    pub fn delete_address(&mut self, address: &Address) -> io::Result<()> {
        address.validate()?;

        interface::delete_address(address)
    }

    /// Sets the MTU of the interface `ifindex`, for each of IPv4 and IPv6
    /// that the interface has.
    pub fn set_link_mtu(&mut self, ifindex: u32, mtu: u32) -> io::Result<()> {
        interface::set_mtu(ifindex, mtu)
    }

    /// The MTU of the interface `ifindex`: that of IPv4, or of IPv6 on an
    /// interface without IPv4.
    pub fn get_link_mtu(&mut self, ifindex: u32) -> io::Result<u32> {
        interface::get_mtu(ifindex)
    }
}

/// The index of the adapter whose friendly name, as shown in the network
/// settings, is `name`, ignoring case.
pub fn if_friendly_name_to_index(name: &str) -> Option<u32> {
    let table = AdapterAddressTable::new().ok()?;
    let target = name.to_lowercase();

    table.rows().find_map(|row| {
        let friendly_name = unsafe { wide_ptr_to_string(row.FriendlyName) }?;
        (friendly_name.to_lowercase() == target).then(|| {
            preferred_adapter_index(unsafe { row.Anonymous1.Anonymous.IfIndex }, row.Ipv6IfIndex)
        })?
    })
}

fn preferred_adapter_index(ipv4_index: u32, ipv6_index: u32) -> Option<u32> {
    (ipv4_index != 0)
        .then_some(ipv4_index)
        .or_else(|| (ipv6_index != 0).then_some(ipv6_index))
}

fn route_row(route: &Route) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.DestinationPrefix.Prefix = sockaddr(route.destination);
    row.DestinationPrefix.PrefixLength = route.prefix;
    row.NextHop = sockaddr(
        route
            .gateway
            .unwrap_or_else(|| unspecified(route.destination)),
    );
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Origin = NlroManual;

    row
}

fn find_unique_route(route: &Route) -> io::Result<MIB_IPFORWARD_ROW2> {
    let table = RouteTable::new(address_family(route.destination))?;
    let mut matches = table
        .rows()
        .iter()
        .copied()
        .filter(|row| row.ValidLifetime != 0 && row_matches(row, route));
    let route = matches
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "route not found"))?;

    if matches.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "route selector is ambiguous; specify gateway and interface index",
        ));
    }

    Ok(route)
}

fn best_matching_route(route: &Route) -> io::Result<MIB_IPFORWARD_ROW2> {
    let table = RouteTable::new(address_family(route.destination))?;
    let mut best = None;

    for row in table
        .rows()
        .iter()
        .copied()
        .filter(|row| row.ValidLifetime != 0 && row_matches(row, route))
    {
        let interface_metric = match interface_metric(&row) {
            Ok(Some(metric)) => metric,
            Ok(None) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let rank = route_rank(&row, interface_metric);
        if best.as_ref().is_none_or(|(best_rank, _)| rank < *best_rank) {
            best = Some((rank, row));
        }
    }

    best.map(|(_, row)| row)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no usable route found"))
}

fn row_matches(row: &MIB_IPFORWARD_ROW2, route: &Route) -> bool {
    row.DestinationPrefix.PrefixLength == route.prefix
        && sockaddr_ip(row.DestinationPrefix.Prefix) == Some(route.destination)
        && route
            .gateway
            .is_none_or(|gateway| sockaddr_ip(row.NextHop) == Some(gateway))
        && route
            .ifindex
            .is_none_or(|ifindex| row.InterfaceIndex == ifindex)
}

fn best_route(destination: IpAddr, interface_index: u32) -> io::Result<MIB_IPFORWARD_ROW2> {
    let destination = sockaddr(destination);
    let mut best_route = MIB_IPFORWARD_ROW2::default();
    let mut best_source = SOCKADDR_INET::default();

    win32_result(unsafe {
        GetBestRoute2(
            ptr::null(),
            interface_index,
            ptr::null(),
            &destination,
            0,
            &mut best_route,
            &mut best_source,
        )
    })?;

    Ok(best_route)
}

fn interface_metric(route: &MIB_IPFORWARD_ROW2) -> io::Result<Option<u32>> {
    let mut interface = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut interface) };
    interface.Family = unsafe { route.DestinationPrefix.Prefix.si_family };
    interface.InterfaceLuid = route.InterfaceLuid;
    interface.InterfaceIndex = route.InterfaceIndex;
    win32_result(unsafe { GetIpInterfaceEntry(&mut interface) })?;

    Ok(usable_interface_metric(&interface))
}

fn usable_interface_metric(interface: &MIB_IPINTERFACE_ROW) -> Option<u32> {
    (interface.Connected && !interface.DisableDefaultRoutes).then_some(interface.Metric)
}

fn route_rank(
    route: &MIB_IPFORWARD_ROW2,
    interface_metric: u32,
) -> (u64, u32, u32, Option<(u8, [u8; 16])>) {
    (
        u64::from(route.Metric) + u64::from(interface_metric),
        route.Metric,
        route.InterfaceIndex,
        sockaddr_ip(route.NextHop).map(ip_sort_key),
    )
}

fn ip_sort_key(address: IpAddr) -> (u8, [u8; 16]) {
    match address {
        IpAddr::V4(address) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&address.octets());
            (4, bytes)
        }
        IpAddr::V6(address) => (6, address.octets()),
    }
}

fn resolve_interface_index(route: &Route) -> io::Result<u32> {
    if let Some(ifindex) = route.ifindex {
        return Ok(ifindex);
    }

    let target = route.gateway.unwrap_or(route.destination);
    Ok(best_route(target, 0)?.InterfaceIndex)
}

fn route_from_row(row: &MIB_IPFORWARD_ROW2) -> io::Result<Route> {
    let destination = sockaddr_ip(row.DestinationPrefix.Prefix)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-IP route destination"))?;
    let mut route = Route::new(destination, row.DestinationPrefix.PrefixLength);
    // An on-link route has an all-zero next hop.
    route.gateway = sockaddr_ip(row.NextHop).filter(|gateway| !gateway.is_unspecified());
    route.ifindex = Some(row.InterfaceIndex);

    Ok(route)
}

fn sockaddr(addr: IpAddr) -> SOCKADDR_INET {
    match addr {
        IpAddr::V4(addr) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(addr.octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(addr) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: windows_sys::Win32::Networking::WinSock::IN6_ADDR_0 {
                        Byte: addr.octets(),
                    },
                },
                Anonymous: Default::default(),
            },
        },
    }
}

fn sockaddr_ip(addr: SOCKADDR_INET) -> Option<IpAddr> {
    // Every variant starts with the family, which tells the one to read.
    unsafe {
        match addr.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                addr.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(addr.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

fn unspecified(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn address_family(addr: IpAddr) -> ADDRESS_FAMILY {
    match addr {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}

// TODO: keep the raw code in AlreadyExists and NotFound as well, so that
// `raw_os_error` works as it does on Linux and macOS.
fn win32_result(code: u32) -> io::Result<()> {
    match code {
        ERROR_SUCCESS => Ok(()),
        ERROR_OBJECT_ALREADY_EXISTS => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("Win32 error {code}"),
        )),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Win32 error {code}"),
        )),
        _ => Err(io::Error::from_raw_os_error(code as i32)),
    }
}

struct RouteTable {
    ptr: *mut MIB_IPFORWARD_TABLE2,
}

impl RouteTable {
    fn new(family: ADDRESS_FAMILY) -> io::Result<Self> {
        let mut ptr = ptr::null_mut();
        win32_result(unsafe { GetIpForwardTable2(family, &mut ptr) })?;

        Ok(Self { ptr })
    }

    fn rows(&self) -> &[MIB_IPFORWARD_ROW2] {
        unsafe {
            let table = &*self.ptr;
            std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize)
        }
    }
}

impl Drop for RouteTable {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.ptr.cast()) };
    }
}

struct AdapterAddressTable {
    buf: Vec<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>,
}

impl AdapterAddressTable {
    fn new() -> io::Result<Self> {
        let mut len = 15_000u32;
        loop {
            let mut buf = aligned_adapter_buffer(len as usize);
            let code = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    GAA_FLAG_INCLUDE_ALL_INTERFACES,
                    ptr::null(),
                    buf.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            match code {
                ERROR_SUCCESS => return Ok(Self { buf }),
                ERROR_BUFFER_OVERFLOW => continue,
                _ => return Err(io::Error::from_raw_os_error(code as i32)),
            }
        }
    }

    fn rows(&self) -> AdapterAddressRows<'_> {
        AdapterAddressRows {
            next: self.buf.as_ptr().cast(),
            _table: self,
        }
    }
}

fn aligned_adapter_buffer(byte_len: usize) -> Vec<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>> {
    let entry_size = std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>();
    vec![MaybeUninit::uninit(); byte_len.div_ceil(entry_size)]
}

struct AdapterAddressRows<'a> {
    next: *const IP_ADAPTER_ADDRESSES_LH,
    _table: &'a AdapterAddressTable,
}

impl<'a> Iterator for AdapterAddressRows<'a> {
    type Item = &'a IP_ADAPTER_ADDRESSES_LH;

    fn next(&mut self) -> Option<Self::Item> {
        let row = unsafe { self.next.as_ref()? };
        self.next = row.Next;
        Some(row)
    }
}

unsafe fn wide_ptr_to_string(ptr: windows_sys::core::PWSTR) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    Some(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(ptr, len)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(metric: u32, interface_index: u32, gateway: Ipv4Addr) -> MIB_IPFORWARD_ROW2 {
        MIB_IPFORWARD_ROW2 {
            Metric: metric,
            InterfaceIndex: interface_index,
            NextHop: sockaddr(IpAddr::V4(gateway)),
            ..Default::default()
        }
    }

    #[test]
    fn route_rank_uses_route_plus_interface_metric() {
        let low_route_metric = row(5, 2, Ipv4Addr::new(10, 0, 0, 2));
        let low_effective_metric = row(15, 3, Ipv4Addr::new(10, 0, 0, 3));

        assert!(route_rank(&low_effective_metric, 5) < route_rank(&low_route_metric, 50));
    }

    #[test]
    fn route_rank_breaks_equal_metric_ties_deterministically() {
        let first = row(10, 2, Ipv4Addr::new(10, 0, 0, 2));
        let second = row(10, 3, Ipv4Addr::new(10, 0, 0, 1));

        assert!(route_rank(&first, 10) < route_rank(&second, 10));
    }

    #[test]
    fn adapter_address_storage_has_the_required_alignment() {
        let buffer = aligned_adapter_buffer(15_000);

        assert_eq!(
            buffer.as_ptr() as usize % std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>(),
            0
        );
    }

    #[test]
    fn adapter_index_prefers_ipv4_and_falls_back_to_ipv6() {
        assert_eq!(preferred_adapter_index(4, 6), Some(4));
        assert_eq!(preferred_adapter_index(0, 6), Some(6));
        assert_eq!(preferred_adapter_index(0, 0), None);
    }

    #[test]
    fn default_route_requires_an_enabled_connected_interface() {
        let usable = MIB_IPINTERFACE_ROW {
            Connected: true,
            DisableDefaultRoutes: false,
            Metric: 10,
            ..Default::default()
        };
        let disconnected = MIB_IPINTERFACE_ROW {
            Connected: false,
            ..usable
        };
        let default_routes_disabled = MIB_IPINTERFACE_ROW {
            DisableDefaultRoutes: true,
            ..usable
        };

        assert_eq!(usable_interface_metric(&usable), Some(10));
        assert_eq!(usable_interface_metric(&disconnected), None);
        assert_eq!(usable_interface_metric(&default_routes_disabled), None);
    }
}
