//! A small `ip addr` look-alike:
//!
//! ```text
//! sudo cargo run --example address -- replace 198.18.0.1/24 dev tun0
//! sudo cargo run --example address -- replace 198.18.0.1 peer 198.18.0.2 dev utun5
//! sudo cargo run --example address -- delete 198.18.0.1/24 dev tun0
//! ```
//!
//! `peer` is for Linux and macOS.

use std::{env, error::Error, net::IpAddr};

use routex::{Address, Handle, if_nametoindex};

const USAGE: &str = "usage: address <replace|delete> <ip>[/<prefix>] [peer <peer>] dev <interface>";

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or(USAGE)?;
    let (ip, prefix) = parse_ip(&args.next().ok_or(USAGE)?)?;

    let mut ifindex = None;
    let mut peer: Option<IpAddr> = None;
    while let Some(key) = args.next() {
        let value = args.next().ok_or(USAGE)?;
        match key.as_str() {
            "dev" => {
                let index = if_nametoindex(&value);
                ifindex = Some(index.ok_or_else(|| format!("unknown interface {value}"))?);
            }
            "peer" => peer = Some(value.parse()?),
            _ => return Err(USAGE.into()),
        }
    }

    let address = Address::new(ifindex.ok_or(USAGE)?, ip, prefix);
    #[cfg(not(target_os = "windows"))]
    let address = match peer {
        Some(peer) => address.peer(peer),
        None => address,
    };
    #[cfg(target_os = "windows")]
    if peer.is_some() {
        return Err("an address has no peer on Windows".into());
    }

    let mut handle = Handle::new()?;
    match command.as_str() {
        "replace" => handle.replace_address(&address)?,
        "delete" => handle.delete_address(&address)?,
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

/// `ip[/prefix]`; without a prefix, a host address.
fn parse_ip(address: &str) -> Result<(IpAddr, u8), Box<dyn Error>> {
    let (ip, prefix) = match address.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (address, None),
    };
    let ip: IpAddr = ip.parse()?;
    let prefix = match prefix {
        Some(prefix) => prefix.parse()?,
        None if ip.is_ipv4() => 32,
        None => 128,
    };

    Ok((ip, prefix))
}
