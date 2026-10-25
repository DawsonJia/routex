use routex::{Route, RouteSock, if_nametoindex};

fn main() {
    let mut handle = RouteSock::new().unwrap();
    let ifindex = if_nametoindex("enp0s5").unwrap();

    let route = Route::new("1.9.4.5".parse().unwrap(), "32".parse().unwrap()).ifindex(ifindex);
    handle.add(&route).unwrap();
    println!("1.9.4.5/32 add to en0");

    std::thread::sleep(std::time::Duration::from_secs(10));

    handle.delete(&route).unwrap();
    println!("1.9.4.5/32 delete from en0");
}
