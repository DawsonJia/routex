#![allow(dead_code)]

use routex::{Route, RouteSock, if_nametoindex};

use std::fs::read_to_string;

const NON_CN_LIST: &str =
    "/Users/bytedance/project/my_project/Rust/quicocks/examples/non_cn_ip_cidr.txt";

fn main() {
    // add_list();
    // add_by_gateway();
    add_by_iface();
}

fn add_by_gateway() {
    let mut handle = RouteSock::new().unwrap();
    // let route = handle.get(&route).unwrap();
    // println!("{:?}", route);
    // let gateway = route.gateway.unwrap();

    let route = Route::new("1.9.4.5".parse().unwrap(), "32".parse().unwrap())
        .gateway("10.211.55.1".parse().unwrap());
    handle.add(&route).unwrap();
    println!("1.9.4.5/32 add to utun4");
}

fn add_by_iface() {
    let mut handle = RouteSock::new().unwrap();
    let ifindex = if_nametoindex("enp0s5").unwrap();

    let route = Route::new("1.9.4.5".parse().unwrap(), "32".parse().unwrap()).ifindex(ifindex);
    handle.add(&route).unwrap();
    println!("1.9.4.5/32 add to en0");
}

fn add_list() {
    let mut handle = RouteSock::new().unwrap();
    let ifindex = if_nametoindex("utun4").unwrap();

    for line in read_to_string(NON_CN_LIST).unwrap().lines() {
        if let Some((ip, cidr)) = line.split_once('/') {
            let route = Route::new(ip.parse().unwrap(), cidr.parse().unwrap()).ifindex(ifindex);

            handle.add(&route).unwrap();
        } else {
            println!("{} can not be splited by `/`", line);
        }
    }
}
