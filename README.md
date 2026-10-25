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
    let route = Route::new("198.18.0.0".parse().unwrap(), 15).gateway(default.gateway.unwrap());

    sock.add(&route)?;
    sock.delete(&route)
}
```

Changing routes takes root: `CAP_NET_ADMIN` on Linux, an elevated process on
Windows. Interfaces are given by index; `if_nametoindex` maps a name to one,
and on Windows `if_friendly_name_to_index` maps the name shown in the network
settings.

## Semantics

- `get` returns the routing table entry the kernel routes the destination by,
  not the destination as a host route. It honours `ifindex` on Linux and
  Windows, and `scope_ifindex` on macOS.
- On Linux, `add`, `delete` and `RouteMonitor` work on the main table only.
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
