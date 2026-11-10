# routex

Add, delete, look up and monitor IP routes on Linux, macOS and Windows, and
add and delete the rules of policy routing on Linux.

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Backend | rtnetlink | routing socket, `route(4)` | IP Helper |
| `Handle::add_route`, `delete_route`, `get_route` | yes | yes | yes |
| `RouteMonitor` | yes | yes | no |
| Routing tables, `Route::table` | yes | no | no |
| Route types, `Route::kind` | unicast, local, blackhole, unreachable, prohibit, throw | no | no |
| Rules, `Handle::add_rule`, `delete_rule` | yes | no | no |
| Interface-scoped routes, `Route::ifscope` | no | yes | no |

What a platform lacks, routex does not offer there: the fields, methods and
types of a feature only exist on the platforms in its row.

```rust,no_run
use routex::{Handle, Route};

fn main() -> std::io::Result<()> {
    let mut handle = Handle::new()?;

    // The unspecified address with prefix 0 asks for the default route.
    let default = handle.get_route(&Route::default())?;
    // Through the gateway of the default route, and out of its interface; a
    // default route on a point-to-point link may have no gateway.
    let route = Route {
        destination: "198.18.0.0".parse().unwrap(),
        prefix: 15,
        ..default
    };

    handle.add_route(&route)?;
    handle.delete_route(&route)
}
```

Changing routes and rules takes root: `CAP_NET_ADMIN` on Linux, an elevated
process on Windows. A route gives its interface by index; `if_nametoindex`
maps a name to one, and on Windows `if_friendly_name_to_index` maps the name
shown in the network settings. A rule names its interfaces, as the kernel
keeps them.

On Linux, policy routing sends what a tunnel captures by a table of its own.
This is `ip route add default dev tun0 table 51888`, `ip route add throw
10.0.0.0/8 table 51888`, `ip rule add priority 5200 lookup main
suppress_prefixlength 0` and `ip rule add priority 5210 not fwmark 0x5100
lookup 51888`; the table, priorities and mark are the caller's to choose:

```rust,no_run
#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::{io::ErrorKind, net::Ipv4Addr};

    use routex::{Handle, Route, RouteKind, Rule, RuleAction, TABLE_MAIN, if_nametoindex};

    const TABLE: u32 = 51888;
    let tun0 = if_nametoindex("tun0").ok_or(ErrorKind::NotFound)?;
    let mut handle = Handle::new()?;

    // The main table keeps the routes more specific than its default one,
    // and the tunnel's table throws the private ranges back to it.
    let routes = [
        Route::default().ifindex(tun0).table(TABLE),
        Route::new(Ipv4Addr::new(10, 0, 0, 0).into(), 8)
            .kind(RouteKind::Throw)
            .table(TABLE),
    ];
    let rules = [
        Rule::v4()
            .priority(5200)
            .action(RuleAction::Lookup(TABLE_MAIN))
            .suppress_prefixlength(0),
        // What the tunnel sends itself is marked, and goes by the main
        // table. A tunnel that binds its sockets to the physical interface
        // instead looks up its table for every packet: no `fwmark`.
        Rule::v4()
            .priority(5210)
            .invert()
            .fwmark(0x5100, u32::MAX)
            .action(RuleAction::Lookup(TABLE)),
    ];

    // A route through no interface, and a rule, outlive the process that
    // added them: delete what a previous run left before adding.
    for route in &routes {
        match handle.delete_route(route) {
            Err(error) if error.kind() != ErrorKind::NotFound => return Err(error),
            _ => handle.add_route(route)?,
        }
    }
    for rule in &rules {
        match handle.delete_rule(rule) {
            Err(error) if error.kind() != ErrorKind::NotFound => return Err(error),
            _ => handle.add_rule(rule)?,
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
```

## Semantics

- `get_route` tells how the kernel routes the destination: the gateway and
  interface it picks. The destination and prefix it reports are the
  platform's own: the matching table entry on Windows, that entry or a host
  route cloned from it on macOS, and the destination as a host route on Linux.
  It honours `ifindex` on Linux and Windows, and `scope_ifindex` on macOS.
- `get_route` of the unspecified address with prefix 0 returns the default
  route. On Linux that is the one of `kind` in `table` with the lowest metric,
  through its live next hop that `gateway` and `ifindex` select; one with
  several such next hops, or with a nexthop object the kernel does not expand,
  is an error, as a `Route` holds a single next hop.
- On Linux, a `Route` is in a `table`, `TABLE_MAIN` unless set, and of a
  `kind`: unicast, local, blackhole, unreachable, prohibit or throw. A route
  that drops or throws has no gateway or interface. `add_route` and
  `delete_route` work on the table of the route; `delete_route` only deletes
  a route of its kind, though for IPv6 the kernel ignores the kind.
- On Linux, a lookup goes through the rules as a packet does, so `get_route`
  of a destination ignores `table` and `kind` and reports those of the route
  it found. A destination routed by a route of another type, such as
  broadcast or multicast, is an error.
- A `Route` holds a gateway of the family of its destination, so on Linux a
  route through a gateway of another family, an IPv4 route through an IPv6
  one, is an error for `get_route` and skipped by `RouteMonitor`.
- On Linux, `RouteMonitor` reports the routes of every table, with their
  table and kind; a multipath route without its gateways and interfaces. It
  skips the routes of the types a `Route` cannot hold, such as the broadcast
  and multicast ones of the local table.
- `add_route` of a route that is there fails with
  `io::ErrorKind::AlreadyExists`, and `delete_route` of one that is not with
  `io::ErrorKind::NotFound`.
- A rule is of the family of its `from` and `to`, which `Rule::v4` and
  `Rule::v6` start as prefixes of length 0: every address. A selector that is
  not set, a prefix of 0 included, selects every packet.
- A rule, and a route that leaves through no interface (blackhole,
  unreachable, prohibit, throw), stay in the kernel after the process that
  added them exits; a route through an interface goes with the interface. A
  caller deletes its leftovers by the spec it adds them with.
- `add_rule` of a rule that is there fails with `io::ErrorKind::AlreadyExists`.
  `delete_rule` deletes the first rule, by priority, with the action of the
  spec, every selector the spec sets, and its priority if set, and fails with
  `io::ErrorKind::NotFound` if there is none. Neither compares `invert`, as
  the kernel does not: a rule and its inversion cannot share a priority. A
  rule with a priority of its own is the one its spec deletes.
- A rule names its `iif` and `oif`: one may name an interface that does not
  exist yet, and outlives it. `iif lo` selects the packets the host sends;
  `oif` those of sockets bound to the interface.
- Of the selectors and actions of `ip rule`, routex leaves out `tos` and
  `dsfield`, `dscp`, `flowlabel`, `l3mdev`, `tun_id`, `realms`, `protocol`,
  `suppress_ifgroup`, and the `goto`, `nop` and `nat` actions.
- On macOS, `Route::ifscope` installs an interface-scoped route
  (`RTF_IFSCOPE`), which only lookups bound to that interface match: the way to
  keep a per-interface default route next to a VPN's.
- `RouteMonitor::recv` blocks until the next change. On macOS it also reports
  `RouteChange::Change`.

## Examples

```sh
cargo run --example route -- get 1.1.1.1
sudo cargo run --example route -- add 198.18.0.0/15 via 192.168.1.1
sudo cargo run --example route -- add throw 198.18.0.0/15 table 51888
sudo cargo run --example rule -- add priority 5210 not fwmark 0x5100 lookup 51888
cargo run --example monitor
```

## Tests

`cargo test` runs the unit tests. `cargo test -- --ignored` also runs the
checks against the live routing table; those that change routes and rules
need root, use addresses from the reserved `198.18.0.0/15` benchmarking
range, and tables and rule priorities no system uses.
