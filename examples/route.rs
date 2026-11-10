//! A small `route`/`ip route` look-alike:
//!
//! ```text
//! cargo run --example route -- get 1.1.1.1
//! sudo cargo run --example route -- add 198.18.0.0/15 via 192.168.1.1 dev en0
//! sudo cargo run --example route -- add throw 198.18.0.0/15 table 51888
//! ```
//!
//! A route type before the destination, and `table`, are for Linux.

use std::{env, error::Error, net::IpAddr};

use routex::{Handle, Route, if_nametoindex};

const USAGE: &str = "usage: route <add|delete|get> [unicast|local|blackhole|unreachable|prohibit|throw] \
    <destination>[/<prefix>] [via <gateway>] [dev <interface>] [table <table>]";

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1).peekable();
    let command = args.next().ok_or(USAGE)?;

    #[cfg(target_os = "linux")]
    let kind = args
        .next_if(|arg| route_kind(arg).is_some())
        .as_deref()
        .and_then(route_kind);
    let mut route = parse_destination(&args.next().ok_or(USAGE)?)?;
    #[cfg(target_os = "linux")]
    if let Some(kind) = kind {
        route = route.kind(kind);
    }

    while let Some(key) = args.next() {
        let value = args.next().ok_or(USAGE)?;
        route = match key.as_str() {
            "via" => route.gateway(value.parse()?),
            "dev" => route.ifindex(interface(&value)?),
            #[cfg(target_os = "linux")]
            "table" => route.table(match value.as_str() {
                "main" => routex::TABLE_MAIN,
                "local" => routex::TABLE_LOCAL,
                "default" => routex::TABLE_DEFAULT,
                table => table.parse()?,
            }),
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

#[cfg(target_os = "linux")]
fn route_kind(name: &str) -> Option<routex::RouteKind> {
    use routex::RouteKind;

    Some(match name {
        "unicast" => RouteKind::Unicast,
        "local" => RouteKind::Local,
        "blackhole" => RouteKind::Blackhole,
        "unreachable" => RouteKind::Unreachable,
        "prohibit" => RouteKind::Prohibit,
        "throw" => RouteKind::Throw,
        _ => return None,
    })
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
