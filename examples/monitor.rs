#[cfg(not(target_os = "windows"))]
fn main() -> std::io::Result<()> {
    let mut monitor = routex::RouteMonitor::new()?;

    loop {
        let (change, route) = monitor.recv()?;
        println!("{change:?} {route:?}");
    }
}

#[cfg(target_os = "windows")]
fn main() {
    eprintln!("route monitoring is not implemented on Windows");
}
