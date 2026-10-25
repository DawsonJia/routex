# routex

Add, delete, look up and monitor IP routes on Linux, macOS and Windows.

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Backend | rtnetlink | routing socket, `route(4)` | IP Helper |
| `RouteSock::add`, `delete`, `get` | yes | yes | yes |
| `RouteMonitor` | yes | yes | no |

```rust,no_run
use routex::{Route, RouteSock};

fn main() -> std::io::Result<()> {
    let mut sock = RouteSock::new()?;

    // The unspecified address with prefix 0 asks for the default route.
    let default = sock.get(&Route::default())?;
    // Through the gateway of the default route, and out of its interface; a
    // default route on a point-to-point link may have no gateway.
    let route = Route {
        destination: "198.18.0.0".parse().unwrap(),
        prefix: 15,
        ..default
    };

    sock.add(&route)?;
    sock.delete(&route)
}
```

Changing routes takes root: `CAP_NET_ADMIN` on Linux, an elevated process on
Windows. Interfaces are given by index; `if_nametoindex` maps a name to one,
and on Windows `if_friendly_name_to_index` maps the name shown in the network
settings.

## Semantics

- `get` tells how the kernel routes the destination: the gateway and interface
  it picks. The destination and prefix it reports are the platform's own: the
  matching table entry on Windows, that entry or a host route cloned from it on
  macOS, and the destination as a host route on Linux. It honours `ifindex` on
  Linux and Windows, and `scope_ifindex` on macOS.
- `get` of the unspecified address with prefix 0 returns the default route. On
  Linux that is the main-table one with the lowest metric, through its live
  next hop that `gateway` and `ifindex` select; one with several such next
  hops, or with a nexthop object the kernel does not expand, is an error, as a
  `Route` holds a single next hop.
- A `Route` holds a gateway of the family of its destination, so on Linux a
  route through a gateway of another family, an IPv4 route through an IPv6
  one, is an error for `get` and skipped by `RouteMonitor`.
- On Linux, `add`, `delete` and `RouteMonitor` work on the main table only. The
  monitor reports every route of it, blackholes included; a multipath route
  without its gateways and interfaces.
- On macOS, `Route::ifscope` installs an interface-scoped route
  (`RTF_IFSCOPE`), which only lookups bound to that interface match: the way to
  keep a per-interface default route next to a VPN's.
- `RouteMonitor::recv` blocks until the next change. On macOS it also reports
  `RouteChange::Change`.

## Examples

```sh
cargo run --example route -- get 1.1.1.1
sudo cargo run --example route -- add 198.18.0.0/15 via 192.168.1.1
cargo run --example monitor
```

## Tests

`cargo test` runs the unit tests. `cargo test -- --ignored` also runs the
checks against the live routing table; those that change routes need root and
use addresses from the reserved `198.18.0.0/15` benchmarking range.
