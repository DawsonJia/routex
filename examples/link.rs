//! A small `ip link` look-alike:
//!
//! ```text
//! cargo run --example link -- show tun0
//! sudo cargo run --example link -- set tun0 mtu 1400 up
//! ```
//!
//! `up` and `down` are for Linux and macOS.

use std::{env, error::Error};

use routex::{Handle, if_nametoindex};

const USAGE: &str = "usage: link show <interface> | link set <interface> [mtu <mtu>] [up|down]";

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or(USAGE)?;
    let name = args.next().ok_or(USAGE)?;
    let ifindex = if_nametoindex(&name).ok_or_else(|| format!("unknown interface {name}"))?;

    let mut handle = Handle::new()?;
    match command.as_str() {
        "show" => println!("{name}: mtu {}", handle.get_link_mtu(ifindex)?),
        "set" => {
            while let Some(key) = args.next() {
                match key.as_str() {
                    "mtu" => handle.set_link_mtu(ifindex, args.next().ok_or(USAGE)?.parse()?)?,
                    #[cfg(not(target_os = "windows"))]
                    "up" => handle.set_link_up(ifindex, true)?,
                    #[cfg(not(target_os = "windows"))]
                    "down" => handle.set_link_up(ifindex, false)?,
                    _ => return Err(USAGE.into()),
                }
            }
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}
