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
        AF_INET, AF_INET6, IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual,
    },
};

use super::{sockaddr, win32_result};
use crate::Address;

/// Never expires.
const INFINITE_LIFETIME: u32 = u32::MAX;

pub(super) fn replace_address(address: &Address) -> io::Result<()> {
    let mut row = address_row(address);
    match win32_result(unsafe { GetUnicastIpAddressEntry(&mut row) }) {
        // The interface has the ip, as an adapter that is opened again has
        // the addresses of its last use: the row takes the new prefix, and
        // keeps the rest of what the system has for it.
        Ok(()) => {
            set_manual(&mut row, address.prefix);
            win32_result(unsafe { SetUnicastIpAddressEntry(&row) })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut row = address_row(address);
            set_manual(&mut row, address.prefix);
            // In use at once, while the system looks for a duplicate.
            // TODO: an address that turns out to be a duplicate is reported
            // nowhere.
            row.DadState = IpDadStatePreferred;
            win32_result(unsafe { CreateUnicastIpAddressEntry(&row) })
        }
        Err(error) => Err(error),
    }
}

pub(super) fn delete_address(address: &Address) -> io::Result<()> {
    win32_result(unsafe { DeleteUnicastIpAddressEntry(&address_row(address)) })
}

pub(super) fn set_mtu(ifindex: u32, mtu: u32) -> io::Result<()> {
    for mut row in interface_rows(ifindex)? {
        row.NlMtu = mtu;
        // GetIpInterfaceEntry may fill in a SitePrefixLength that
        // SetIpInterfaceEntry refuses.
        row.SitePrefixLength = 0;
        win32_result(unsafe { SetIpInterfaceEntry(&mut row) })?;
    }

    Ok(())
}

pub(super) fn get_mtu(ifindex: u32) -> io::Result<u32> {
    Ok(interface_rows(ifindex)?[0].NlMtu)
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

/// The rows of the interface `ifindex`, one for each of IPv4 and IPv6 that
/// it has, IPv4 first; fails with `NotFound` if it has neither.
fn interface_rows(ifindex: u32) -> io::Result<Vec<MIB_IPINTERFACE_ROW>> {
    let mut rows = Vec::new();
    for family in [AF_INET, AF_INET6] {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = family;
        row.InterfaceIndex = ifindex;
        match win32_result(unsafe { GetIpInterfaceEntry(&mut row) }) {
            Ok(()) => rows.push(row),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    if rows.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no interface {ifindex} with IPv4 or IPv6"),
        ));
    }
    Ok(rows)
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
