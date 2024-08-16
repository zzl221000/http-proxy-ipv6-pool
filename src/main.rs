mod proxy;
mod socks5;

use cidr::{Ipv4Cidr, Ipv6Cidr};
use getopts::Options;
use proxy::start_proxy;
use socks5::start_socks5_proxy;
use std::{env, process::exit, net::IpAddr, net::SocketAddr};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("b", "bind", "HTTP proxy bind address", "BIND");
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
    opts.optopt(
        "S",  // 使用单字符作为短选项
        "socks5",
        "SOCKS5 proxy bind address (e.g., 127.0.0.1:51081)",
        "SOCKS5_ADDR",
    );
    opts.optflag("h", "help", "Print this help menu");
    opts.optopt("r", "system_route", "Whether to use system routing instead of ndpdd. (Provide network card interface, such as eth0)", "Network Interface");
    opts.optopt("g", "gateway", "Some service providers need to track the route before it takes effect.", "Gateway");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("Error parsing options: {}", f);
            print_usage(&program, opts);
            exit(1);
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let system_route = matches.opt_str("r").unwrap_or_else(|| "".to_string());
    println!("System route option received: {}", system_route);

    let gateway = matches.opt_str("g").unwrap_or_else(|| "".to_string());
    println!("Gateway: {}", gateway);

    let bind_addr = matches.opt_str("b").unwrap_or_else(|| "0.0.0.0:51080".to_string());
    let socks5_bind_addr = matches.opt_str("S").unwrap_or_else(|| "127.0.0.1:51081".to_string());

    let ipv6_subnet = matches
        .opt_str("i")
        .unwrap_or_else(|| "::/128".to_string());
    let ipv4_subnet = matches
        .opt_str("v")
        .unwrap_or_else(|| "0.0.0.0/32".to_string());

    let allowed_ips = matches.opt_str("a")
        .map(|s| parse_allowed_ips(&s));

    let ipv6 = match ipv6_subnet.parse::<Ipv6Cidr>() {
        Ok(cidr) => (cidr.first_address(), cidr.network_length()),
        Err(_) => {
            println!("Invalid IPv6 subnet");
            exit(1);
        }
    };

    let ipv4 = match ipv4_subnet.parse::<Ipv4Cidr>() {
        Ok(cidr) => (cidr.first_address(), cidr.network_length()),
        Err(_) => {
            println!("Invalid IPv4 subnet");
            exit(1);
        }
    };

    let bind_addr = match bind_addr.parse() {
        Ok(b) => b,
        Err(e) => {
            println!("Bind address not valid: {}", e);
            return;
        }
    };

    let socks5_bind_addr = match socks5_bind_addr.parse::<SocketAddr>() {
        Ok(b) => b,
        Err(e) => {
            println!("SOCKS5 bind address not valid: {}", e);
            return;
        }
    };

    // 启动HTTP代理和SOCKS5代理，并处理结果
    let (http_result, socks5_result) = tokio::join!(
        start_proxy(
            bind_addr,
            !system_route.is_empty(),
            gateway.clone(),
            system_route.clone(),
            ipv6,
            ipv4,
            allowed_ips.clone()
        ),
        start_socks5_proxy(socks5_bind_addr, ipv6, ipv4,allowed_ips.clone())
    );

    if let Err(e) = http_result {
        eprintln!("HTTP Proxy encountered an error: {}", e);
    }

    if let Err(e) = socks5_result {
        eprintln!("SOCKS5 Proxy encountered an error: {}", e);
    }
}

fn parse_allowed_ips(allowed_ips_str: &str) -> Vec<IpAddr> {
    allowed_ips_str
        .split(',')
        .filter_map(|ip_str| ip_str.parse::<IpAddr>().ok())
        .collect()
}
