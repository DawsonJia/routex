//! The addresses and the MTU of an interface, through the IP Helper API.

use std::io;

use windows_sys::Win32::{
    NetworkManagement::IpHelper::{
        CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, GetIpInterfaceEntry,
        GetUnicastIpAddressEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
        MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
        SetUnicastIpAddressEntry,
    },
    Networking::WinSock::{
        ADDRESS_FAMILY, AF_INET, AF_INET6, IpDadStatePreferred, IpPrefixOriginManual,
        IpSuffixOriginManual,
    },
};

use super::{sockaddr, win32_result};
use crate::Address;

/// Never expires.
const INFINITE_LIFETIME: u32 = u32::MAX;

pub(super) fn replace_address(address: &Address) -> io::Result<()> {
    if set_address(address)? {
        return Ok(());
    }

    let mut row = address_row(address);
    set_manual(&mut row, address.prefix);
    // In use at once, while the system looks for a duplicate.
    // TODO: an address that turns out to be a duplicate is reported nowhere.
    row.DadState = IpDadStatePreferred;
    match win32_result(unsafe { CreateUnicastIpAddressEntry(&row) }) {
        // Another caller added the ip in between, and its row takes the
        // prefix. Windows says the same of an ip that another interface
        // has still, which wireguard-windows takes off the interfaces that
        // are not connected: there is then no row to set, and the error
        // stands.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if set_address(address)? {
                Ok(())
            } else {
                Err(error)
            }
        }
        result => result,
    }
}

/// Gives the row of `address.ip` the prefix of `address`, if its interface
/// has the ip, as an adapter that is opened again has the addresses of its
/// last use: the row keeps the rest of what the system has for it.
fn set_address(address: &Address) -> io::Result<bool> {
    let mut row = address_row(address);
    match win32_result(unsafe { GetUnicastIpAddressEntry(&mut row) }) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    set_manual(&mut row, address.prefix);
    win32_result(unsafe { SetUnicastIpAddressEntry(&row) })?;

    Ok(true)
}

pub(super) fn delete_address(address: &Address) -> io::Result<()> {
    win32_result(unsafe { DeleteUnicastIpAddressEntry(&address_row(address)) })
}

pub(super) fn set_mtu(ifindex: u32, mtu: u32) -> io::Result<()> {
    // IPv6 takes no MTU under 1280, and IPv4 every one that IPv6 takes: the
    // row of IPv6 goes first, so that an MTU it refuses changes neither.
    let rows = [
        interface_row(ifindex, AF_INET6)?,
        interface_row(ifindex, AF_INET)?,
    ];
    if rows.iter().all(Option::is_none) {
        return Err(no_interface(ifindex));
    }
    for mut row in rows.into_iter().flatten() {
        row.NlMtu = mtu;
        win32_result(unsafe { SetIpInterfaceEntry(&mut row) })?;
    }

    Ok(())
}

pub(super) fn get_mtu(ifindex: u32) -> io::Result<u32> {
    for family in [AF_INET, AF_INET6] {
        if let Some(row) = interface_row(ifindex, family)? {
            return Ok(row.NlMtu);
        }
    }

    Err(no_interface(ifindex))
}

/// The row that selects `address.ip` on its interface.
fn address_row(address: &Address) -> MIB_UNICASTIPADDRESS_ROW {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    // With no LUID, the index selects the interface.
    row.InterfaceIndex = address.ifindex;
    row.Address = sockaddr(address.ip);

    row
}

/// Makes `row` an address that was set by hand, with `prefix`, for good.
fn set_manual(row: &mut MIB_UNICASTIPADDRESS_ROW, prefix: u8) {
    row.OnLinkPrefixLength = prefix;
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    row.ValidLifetime = INFINITE_LIFETIME;
    row.PreferredLifetime = INFINITE_LIFETIME;
    row.SkipAsSource = false;
}

/// The row of the interface `ifindex` for `family`, as SetIpInterfaceEntry
/// takes it back, or none if the interface has no such family.
fn interface_row(ifindex: u32, family: ADDRESS_FAMILY) -> io::Result<Option<MIB_IPINTERFACE_ROW>> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family;
    row.InterfaceIndex = ifindex;
    match win32_result(unsafe { GetIpInterfaceEntry(&mut row) }) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    row.SitePrefixLength = site_prefix_length(family, row.SitePrefixLength);

    Ok(Some(row))
}

/// The SitePrefixLength to set a row of `family` with, given the one that
/// GetIpInterfaceEntry `reported`, which SetIpInterfaceEntry may refuse: it
/// takes 0 alone for IPv4, and for IPv6 no more than the bits of an address.
/// The length of an IPv6 interface is otherwise its own, and stays.
fn site_prefix_length(family: ADDRESS_FAMILY, reported: u32) -> u32 {
    if family == AF_INET {
        0
    } else {
        reported.min(128)
    }
}

fn no_interface(ifindex: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no interface {ifindex} with IPv4 or IPv6"),
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::Networking::WinSock::IpDadStateTentative;

    use super::{super::sockaddr_ip, *};

    #[test]
    fn an_address_row_selects_the_ip_on_the_interface_by_index() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let row = address_row(&Address::new(7, ip, 64));

        assert_eq!(row.InterfaceIndex, 7);
        assert_eq!(unsafe { row.InterfaceLuid.Value }, 0);
        assert_eq!(sockaddr_ip(row.Address), Some(ip));
    }

    #[test]
    fn a_row_that_is_there_takes_the_prefix_and_keeps_its_state() {
        let mut row = MIB_UNICASTIPADDRESS_ROW {
            DadState: IpDadStateTentative,
            SkipAsSource: true,
            ValidLifetime: 60,
            PreferredLifetime: 30,
            ..Default::default()
        };

        set_manual(&mut row, 24);

        assert_eq!(row.OnLinkPrefixLength, 24);
        assert_eq!(row.PrefixOrigin, IpPrefixOriginManual);
        assert_eq!(row.SuffixOrigin, IpSuffixOriginManual);
        assert_eq!(row.ValidLifetime, INFINITE_LIFETIME);
        assert_eq!(row.PreferredLifetime, INFINITE_LIFETIME);
        assert!(!row.SkipAsSource);
        assert_eq!(row.DadState, IpDadStateTentative);
    }

    #[test]
    fn a_row_is_set_with_a_site_prefix_length_its_family_takes() {
        assert_eq!(site_prefix_length(AF_INET, 255), 0);
        assert_eq!(site_prefix_length(AF_INET, 24), 0);
        assert_eq!(site_prefix_length(AF_INET6, 64), 64);
        assert_eq!(site_prefix_length(AF_INET6, 255), 128);
    }

    #[test]
    #[ignore = "black-box check against the live Windows interfaces"]
    fn an_interface_that_is_not_there_is_not_found() {
        let missing = 424_242;
        let address = Address::new(missing, IpAddr::V4(Ipv4Addr::new(198, 18, 251, 1)), 24);

        for result in [
            delete_address(&address),
            set_mtu(missing, 1400),
            get_mtu(missing).map(drop),
        ] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        }
    }
}
