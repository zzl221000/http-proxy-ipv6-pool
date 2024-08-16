mod proxy;

use cidr::{Ipv4Cidr, Ipv6Cidr};
use getopts::Options;
use proxy::start_proxy;
use std::{env, process::exit, net::IpAddr};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("b", "bind", "http proxy bind address", "BIND");
    opts.optopt(
        "i",
        "ipv6-subnet",
        "IPv6 Subnet: 2001:19f0:6001:48e4::/64",
        "IPv6_SUBNET",
    );
    opts.optopt(
        "v",
        "ipv4-subnet",
        "IPv4 Subnet: 192.168.0.0/24",
        "IPv4_SUBNET",
    );
    opts.optopt(
        "a",
        "allowed-ips",
        "Comma-separated list of allowed IP addresses",
        "ALLOWED_IPS",
    );
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("s", "system_route", "Whether to use system routing instead of ndpdd. (Provide network card interface, such as eth0)", "Network Interface");
    opts.optopt("g", "gateway", "Some service providers need to track the route before it takes effect.", "Gateway");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f.to_string())
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let system_route = matches.opt_str("s").unwrap_or("".to_string());
    println!("System route option received: {}", system_route);

    let gateway = matches.opt_str("g").unwrap_or("".to_string());
    println!("Gateway: {}", gateway);

    let bind_addr = matches.opt_str("b").unwrap_or("0.0.0.0:51080".to_string());
    let ipv6_subnet = matches
        .opt_str("i")
        .unwrap_or("2001:19f0:6001:48e4::/64".to_string());
    let ipv4_subnet = matches
        .opt_str("v")
        .unwrap_or("192.168.0.0/24".to_string());

    let allowed_ips_str = matches.opt_str("a").unwrap_or_default();
    let allowed_ips = parse_allowed_ips(&allowed_ips_str);

    run(bind_addr, system_route, gateway, ipv6_subnet, ipv4_subnet, allowed_ips);
}

fn parse_allowed_ips(allowed_ips_str: &str) -> Vec<IpAddr> {
    allowed_ips_str
        .split(',')
        .filter_map(|ip_str| ip_str.parse::<IpAddr>().ok())
        .collect()
}

#[tokio::main]
async fn run(
    bind_addr: String,
    system_route: String,
    gateway: String,
    ipv6_subnet: String,
    ipv4_subnet: String,
    allowed_ips: Vec<IpAddr>,
) {
    let ipv6 = match ipv6_subnet.parse::<Ipv6Cidr>() {
        Ok(cidr) => {
            let a = cidr.first_address();
            let b = cidr.network_length();
            (a, b)
        }
        Err(_) => {
            println!("invalid IPv6 subnet");
            exit(1);
        }
    };

    let ipv4 = match ipv4_subnet.parse::<Ipv4Cidr>() {
        Ok(cidr) => {
            let a = cidr.first_address();
            let b = cidr.network_length();
            (a, b)
        }
        Err(_) => {
            println!("invalid IPv4 subnet");
            exit(1);
        }
    };

    let bind_addr = match bind_addr.parse() {
        Ok(b) => b,
        Err(e) => {
            println!("bind address not valid: {}", e);
            return;
        }
    };

    if !system_route.is_empty() {
        if let Err(e) = start_proxy(bind_addr, true, gateway.clone(), system_route.clone(), ipv6, ipv4, allowed_ips).await {
            println!("{}", e);
        }
    } else {
        if let Err(e) = start_proxy(bind_addr, false, gateway.clone(), system_route.clone(), ipv6, ipv4, allowed_ips).await {
            println!("{}", e);
        }
    }
}
