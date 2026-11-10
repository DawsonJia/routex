//! A small `ip rule` look-alike, for Linux:
//!
//! ```text
//! sudo cargo run --example rule -- add priority 5200 lookup main suppress_prefixlength 0
//! sudo cargo run --example rule -- add priority 5210 not fwmark 0x5100 lookup 51888
//! sudo cargo run --example rule -- -6 delete priority 5210 not fwmark 0x5100 lookup 51888
//! ```

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{env, ops::RangeInclusive};

    use routex::{Handle, Rule, RuleAction, TABLE_DEFAULT, TABLE_LOCAL, TABLE_MAIN};

    const USAGE: &str = "usage: rule [-6] <add|delete> [priority N] [not] [from P] [to P] \
        [fwmark MARK[/MASK]] [iif NAME] [oif NAME] [uidrange A-B] [ipproto N] [sport A[-B]] \
        [dport A[-B]] [lookup TABLE | blackhole | unreachable | prohibit] \
        [suppress_prefixlength N]";

    fn number(value: &str) -> Result<u32, std::num::ParseIntError> {
        match value.strip_prefix("0x") {
            Some(hex) => u32::from_str_radix(hex, 16),
            None => value.parse(),
        }
    }

    fn range<T: std::str::FromStr>(value: &str) -> Result<RangeInclusive<T>, T::Err> {
        let (start, end) = value.split_once('-').unwrap_or((value, value));
        Ok(start.parse()?..=end.parse()?)
    }

    let mut args = env::args().skip(1).peekable();
    let mut rule = match args.next_if_eq("-6") {
        Some(_) => Rule::v6(),
        None => Rule::v4(),
    };
    let command = args.next().ok_or(USAGE)?;

    while let Some(key) = args.next() {
        rule = match key.as_str() {
            "not" => rule.invert(),
            "blackhole" => rule.action(RuleAction::Blackhole),
            "unreachable" => rule.action(RuleAction::Unreachable),
            "prohibit" => rule.action(RuleAction::Prohibit),
            key => {
                let value = args.next().ok_or(USAGE)?;
                match key {
                    "priority" => rule.priority(value.parse()?),
                    "from" | "to" => {
                        let (address, prefix) = value.split_once('/').ok_or(USAGE)?;
                        let (address, prefix) = (address.parse()?, prefix.parse()?);
                        if key == "from" {
                            rule.from(address, prefix)
                        } else {
                            rule.to(address, prefix)
                        }
                    }
                    "fwmark" => match value.split_once('/') {
                        Some((mark, mask)) => rule.fwmark(number(mark)?, number(mask)?),
                        None => rule.fwmark(number(&value)?, u32::MAX),
                    },
                    "iif" => rule.iif(value),
                    "oif" => rule.oif(value),
                    "uidrange" => rule.uid_range(range(&value)?),
                    "ipproto" => rule.ip_proto(value.parse()?),
                    "sport" => rule.sport(range(&value)?),
                    "dport" => rule.dport(range(&value)?),
                    "lookup" => rule.action(RuleAction::Lookup(match value.as_str() {
                        "main" => TABLE_MAIN,
                        "local" => TABLE_LOCAL,
                        "default" => TABLE_DEFAULT,
                        table => table.parse()?,
                    })),
                    "suppress_prefixlength" => rule.suppress_prefixlength(value.parse()?),
                    _ => return Err(USAGE.into()),
                }
            }
        };
    }

    let mut handle = Handle::new()?;
    match command.as_str() {
        "add" => handle.add_rule(&rule)?,
        "delete" => handle.delete_rule(&rule)?,
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("routing rules are a Linux feature");
}
