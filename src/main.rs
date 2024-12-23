mod proxy;
mod socks5;

use cidr::{Ipv4Cidr, Ipv6Cidr};
use getopts::Options;
use proxy::start_proxy;
use serde::{Deserialize, Serialize};
use socks5::start_socks5_proxy;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::{env, net::IpAddr, net::SocketAddr, process::exit};
fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}
#[derive(Debug, Serialize, Deserialize)]
struct Config {
    route_ttl: u64,
    address_ttl: u64,
    proxies: Vec<Proxy>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Proxy {
    interface: String,
    router: bool,
    timeout: u64,
    ttl: u64,
    rules: Vec<Rule>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Rule {
    prefix: String,
    static_route: bool,
}

fn parse_ndppd_conf<P: AsRef<Path>>(path: P) -> io::Result<Config> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut config = Config {
        route_ttl: 0,
        address_ttl: 0,
        proxies: Vec::new(),
    };
    let mut current_proxy: Option<Proxy> = None;
    let mut current_rule: Option<Rule> = None;

    for line in reader.lines() {
        let line = line?;
        let trimmed_line = line.trim();

        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue; // Skip empty lines and comments
        }

        if let Some(proxy_start) = trimmed_line.strip_prefix("proxy ") {
            if let Some(_end_brace) = proxy_start.find('}') {
                // Handle end of a proxy block
                if let Some(mut proxy) = current_proxy.take() {
                    if let Some(rule) = current_rule.take() {
                        proxy.rules.push(rule);
                    }
                    config.proxies.push(proxy);
                }
                continue;
            }

            if let Some(open_brace) = proxy_start.find('{') {
                let interface = &proxy_start[..open_brace].trim().to_string();
                current_proxy = Some(Proxy {
                    interface: interface.clone(),
                    router: false,
                    timeout: 0,
                    ttl: 0,
                    rules: Vec::new(),
                });
                continue;
            }
        }

        if let Some(key_value) = trimmed_line.split_once(' ') {
            let (key, value) = key_value;
            match key.trim() {
                "route-ttl" => config.route_ttl = value.trim().parse().unwrap_or(0),
                "address-ttl" => config.address_ttl = value.trim().parse().unwrap_or(0),
                "router" => {
                    if let Some(ref mut proxy) = current_proxy {
                        proxy.router = value.trim() == "yes";
                    }
                }
                "timeout" => {
                    if let Some(ref mut proxy) = current_proxy {
                        proxy.timeout = value.trim().parse().unwrap_or(0);
                    }
                }
                "ttl" => {
                    if let Some(ref mut proxy) = current_proxy {
                        proxy.ttl = value.trim().parse().unwrap_or(0);
                    }
                }
                "rule" => {
                    if let Some(open_brace) = value.find('{') {
                        let prefix = value[..open_brace].trim().to_string();
                        current_rule = Some(Rule {
                            prefix: prefix.clone(),
                            static_route: false,
                        });
                    }
                }
                "static" => {
                    if let Some(ref mut rule) = current_rule {
                        rule.static_route = true;
                    }
                }
                _ => {}
            }
        } else if let Some(_close_brace) = trimmed_line.find('}') {
            if let Some(mut proxy) = current_proxy.take() {
                if let Some(rule) = current_rule.take() {
                    proxy.rules.push(rule);
                }
                config.proxies.push(proxy);
            }
        }
    }

    Ok(config)
}
#[test]
fn test_parse() -> io::Result<()> {
    let config = parse_ndppd_conf("demo.conf")?;
    println!("{:#?}", config);
    Ok(())
}
#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("b", "bind", "HTTP proxy bind address", "BIND");
    opts.optopt(
        "i",
        "ipv6-subnets",
        "Comma-separated list of IPv6 subnets (e.g., 2001:19f0:6001:48e4::/64,2001:19f0:6001:48e5::/64)",
        "IPv6_SUBNETS",
    );
    opts.optopt(
        "v",
        "ipv4-subnets",
        "Comma-separated list of IPv4 subnets (e.g., 192.168.0.0/24,192.168.1.0/24)",
        "IPv4_SUBNETS",
    );
    opts.optopt(
        "a",
        "allowed-ips",
        "Comma-separated list of allowed IP addresses",
        "ALLOWED_IPS",
    );
    opts.optopt(
        "S",
        "socks5",
        "SOCKS5 proxy bind address (e.g., 127.0.0.1:51081)",
        "SOCKS5_ADDR",
    );
    opts.optopt(
        "u",
        "username",
        "Username for SOCKS5 authentication",
        "USERNAME",
    );
    opts.optopt(
        "p",
        "password",
        "Password for SOCKS5 authentication",
        "PASSWORD",
    );
    opts.optopt("f", "follow", "Follow ndppd conf", "FOLLOW");
    opts.optopt("t", "timeout", "Timeout duration in seconds", "TIMEOUT"); // 新增-t参数
    opts.optflag("h", "help", "Print this help menu");
    opts.optopt("r", "system_route", "Whether to use system routing instead of ndpdd. (Provide network card interface, such as eth0)", "Network Interface");
    opts.optopt(
        "g",
        "gateway",
        "Some service providers need to track the route before it takes effect.",
        "Gateway",
    );

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

    let bind_addr = matches
        .opt_str("b")
        .unwrap_or_else(|| "0.0.0.0:51080".to_string());
    let socks5_bind_addr = matches
        .opt_str("S")
        .unwrap_or_else(|| "127.0.0.1:51081".to_string());

    let mut ipv6_subnets = matches
        .opt_str("i")
        .map(|s| parse_subnets::<Ipv6Cidr>(&s))
        .unwrap_or_else(Vec::new);
    let follow = matches
        .opt_str("f")
        .unwrap_or_else(|| "/etc/ndppd.conf".to_string());
    match parse_ndppd_conf(follow) {
        Ok(config) => {
            config
                .proxies
                .iter()
                .flat_map(|r| {
                    r.rules
                        .iter()
                        .flat_map(|r| parse_subnets::<Ipv6Cidr>(&r.prefix))
                })
                .for_each(|ipv6_subnet| ipv6_subnets.push(ipv6_subnet));
        }
        Err(_) => {}
    };
    let ipv4_subnets = matches
        .opt_str("v")
        .map(|s| parse_subnets::<Ipv4Cidr>(&s))
        .unwrap_or_else(Vec::new);

    let allowed_ips = matches.opt_str("a").map(|s| parse_allowed_ips(&s));

    let username = matches.opt_str("u").unwrap_or_else(|| "".to_string());
    let password = matches.opt_str("p").unwrap_or_else(|| "".to_string());

    // Parse the timeout duration from the command line arguments
    let timeout_duration = matches
        .opt_str("t")
        .and_then(|t| t.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(5)); // Default to 5 seconds if not specified

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

    let ipv6_subnets = Arc::new(ipv6_subnets);
    let ipv4_subnets = Arc::new(ipv4_subnets);

    // 启动HTTP代理和SOCKS5代理，并处理结果
    let (http_result, socks5_result) = tokio::join!(
        start_proxy(
            bind_addr,
            !system_route.is_empty(),
            gateway.clone(),
            system_route.clone(),
            ipv6_subnets.clone(),
            ipv4_subnets.clone(),
            allowed_ips.clone(),
            username.clone(),
            password.clone(),
            timeout_duration // 传递timeout_duration
        ),
        start_socks5_proxy(
            socks5_bind_addr,
            ipv6_subnets,
            ipv4_subnets,
            allowed_ips,
            username,
            password,
            timeout_duration
        )
    );

    if let Err(e) = http_result {
        eprintln!("HTTP Proxy encountered an error: {}", e);
    }

    if let Err(e) = socks5_result {
        eprintln!("SOCKS5 Proxy encountered an error: {}", e);
    }
}

fn parse_subnets<C: std::str::FromStr>(subnets_str: &str) -> Vec<C> {
    subnets_str
        .split(',')
        .filter_map(|subnet_str| subnet_str.parse::<C>().ok())
        .collect()
}

fn parse_allowed_ips(allowed_ips_str: &str) -> Vec<IpAddr> {
    allowed_ips_str
        .split(',')
        .filter_map(|ip_str| ip_str.parse::<IpAddr>().ok())
        .collect()
}
