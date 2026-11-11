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
            // The whole command is read before any of it changes the link,
            // and the MTU is set first wherever it is in the command, as the
            // kernel sets it for `ip link set`.
            let mut mtu = None;
            let mut up = None;
            while let Some(key) = args.next() {
                match key.as_str() {
                    "mtu" => mtu = Some(args.next().ok_or(USAGE)?.parse()?),
                    "up" => up = Some(true),
                    "down" => up = Some(false),
                    _ => return Err(USAGE.into()),
                }
            }
            #[cfg(target_os = "windows")]
            if up.is_some() {
                return Err("a link goes neither up nor down on Windows".into());
            }

            if let Some(mtu) = mtu {
                handle.set_link_mtu(ifindex, mtu)?;
            }
            #[cfg(not(target_os = "windows"))]
            if let Some(up) = up {
                handle.set_link_up(ifindex, up)?;
            }
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}
