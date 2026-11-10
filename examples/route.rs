//! A small `route`/`ip route` look-alike:
//!
//! ```text
//! cargo run --example route -- get 1.1.1.1
//! sudo cargo run --example route -- add 198.18.0.0/15 via 192.168.1.1 dev en0
//! ```

use std::{env, error::Error, net::IpAddr};

use routex::{Handle, Route, if_nametoindex};

const USAGE: &str =
    "usage: route <add|delete|get> <destination>[/<prefix>] [via <gateway>] [dev <interface>]";

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let (Some(command), Some(destination)) = (args.next(), args.next()) else {
        return Err(USAGE.into());
    };

    let mut route = parse_destination(&destination)?;
    while let Some(key) = args.next() {
        let value = args.next().ok_or(USAGE)?;
        route = match key.as_str() {
            "via" => route.gateway(value.parse()?),
            "dev" => route.ifindex(interface(&value)?),
            #[cfg(target_os = "macos")]
            "scope" => route.ifscope(interface(&value)?),
            _ => return Err(USAGE.into()),
        };
    }

    let mut handle = Handle::new()?;
    match command.as_str() {
        "add" => handle.add_route(&route)?,
        "delete" => handle.delete_route(&route)?,
        "get" => println!("{:?}", handle.get_route(&route)?),
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

/// `address[/prefix]`; without a prefix, a host route.
fn parse_destination(destination: &str) -> Result<Route, Box<dyn Error>> {
    let (address, prefix) = match destination.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (destination, None),
    };
    let address: IpAddr = address.parse()?;
    let prefix = match prefix {
        Some(prefix) => prefix.parse()?,
        None if address.is_ipv4() => 32,
        None => 128,
    };

    Ok(Route::new(address, prefix))
}

fn interface(name: &str) -> Result<u32, Box<dyn Error>> {
    Ok(if_nametoindex(name).ok_or_else(|| format!("unknown interface {name}"))?)
}
