use routex::{Route, RouteSock};

fn main() {
    let mut handle = RouteSock::new().unwrap();

    // let route = Route::new("0.0.0.0".parse().unwrap(), "0".parse().unwrap());
    let route = Route::new("192.168.0.4".parse().unwrap(), "32".parse().unwrap());
    let ret = handle.get(&route).unwrap();
    println!("{:?}", ret);
}
