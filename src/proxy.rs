use hyper::{
    client::HttpConnector,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Client, Method, Request, Response, Server, StatusCode,
};
use rand::{random, Rng};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use tokio::{ net::TcpSocket, task};
use std::sync::{Arc};
use tokio::process::Command;
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::time::Duration;
use tokio::sync::Mutex;
use lazy_static::lazy_static;
use tokio::time::timeout;

use hyper::upgrade::OnUpgrade;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use rand::seq::SliceRandom;

const MAX_ADDRESSES: usize = 1000;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
lazy_static! {
    static ref IP_MAP: Mutex<HashMap<String, IpAddr>> = Mutex::new(HashMap::new());
    static ref GLOBAL_ADDRESS_QUEUE: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
}

pub async fn start_proxy(
    listen_addr: SocketAddr,
    is_system_route: bool,
    gateway: String,
    interface: String,
    ipv6_subnets: Arc<Vec<Ipv6Cidr>>,
    ipv4_subnets: Arc<Vec<Ipv4Cidr>>,
    allowed_ips: Option<Vec<IpAddr>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let interface_arc = Arc::new(interface);
    let gateway_arc = Arc::new(gateway);
    let allowed_ips_arc = allowed_ips.map(Arc::new);

    let make_service = make_service_fn(move |conn: &AddrStream| {
        let remote_addr = conn.remote_addr();
        let interface_clone = Arc::clone(&interface_arc);
        let gateway_clone = Arc::clone(&gateway_arc);
        let ipv6_subnets_clone = Arc::clone(&ipv6_subnets);  // 使用 Arc 克隆引用
        let ipv4_subnets_clone = Arc::clone(&ipv4_subnets);
        let allowed_ips_clone = allowed_ips_arc.clone();

        async move {
            let service = service_fn(move |mut req: Request<Body>| {
                req.extensions_mut().insert(remote_addr);

                Proxy {
                    ipv6_subnets: Arc::clone(&ipv6_subnets_clone),  // 直接使用 Arc::clone
                    ipv4_subnets: Arc::clone(&ipv4_subnets_clone),  // 直接使用 Arc::clone
                    address_queue: GLOBAL_ADDRESS_QUEUE.clone(),
                    allowed_ips: allowed_ips_clone.clone(),
                }
                    .proxy(req, is_system_route, (*interface_clone).clone(), (*gateway_clone).clone())
            });

            Ok::<_, hyper::Error>(service)
        }
    });

    Server::bind(&listen_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service)
        .await
        .map_err(|err| err.into())
}

#[derive(Clone)]
pub(crate) struct Proxy {
    pub ipv6_subnets: Arc<Vec<Ipv6Cidr>>,
    pub ipv4_subnets: Arc<Vec<Ipv4Cidr>>,
    address_queue: Arc<Mutex<VecDeque<String>>>,
    allowed_ips: Option<Arc<Vec<IpAddr>>>,
}
impl Proxy {
    pub(crate) async fn proxy(
        self,
        req: Request<Body>,
        is_system_route: bool,
        interface: String,
        gateway: String,
    ) -> Result<Response<Body>, hyper::Error> {
        let client_ip: Option<IpAddr> = if let Some(remote_addr) = req.extensions().get::<SocketAddr>() {
            Some(remote_addr.ip())
        } else if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
            forwarded_for.to_str().ok().and_then(|ip_str| ip_str.parse().ok())
        } else if let Some(real_ip) = req.headers().get("x-real-ip") {
            real_ip.to_str().ok().and_then(|ip_str| ip_str.parse().ok())
        } else {
            None
        };

        if let Some(client_ip) = client_ip {
            println!("Client IP: {}", client_ip);

            // 如果设置了 allowed_ips 列表，则检查客户端 IP 是否在列表中
            if let Some(allowed_ips) = &self.allowed_ips {
                let ip_allowed = allowed_ips.iter().any(|allowed_ip| match (allowed_ip, client_ip) {
                    (IpAddr::V4(allowed_ip), IpAddr::V4(client_ip)) => {
                        // 使用包含关系判断 IPv4 子网
                        Ipv4Cidr::new(*allowed_ip, 32).unwrap().contains(&client_ip)
                    }
                    (IpAddr::V6(allowed_ip), IpAddr::V6(client_ip)) => {
                        // 使用包含关系判断 IPv6 子网
                        Ipv6Cidr::new(*allowed_ip, 128).unwrap().contains(&client_ip)
                    }
                    _ => false,
                });

                if !ip_allowed {
                    println!("Access denied for IP: {}", client_ip);
                    return Ok(Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from("Access denied"))
                        .unwrap());
                }
            }
        } else {
            println!("Failed to get client IP address");
        }

        // Define a timeout duration
        let timeout_duration = Duration::from_secs(10); // 30 seconds timeout

        match timeout(timeout_duration, async {
            if req.method() == Method::CONNECT {
                self.process_connect(req, is_system_route, interface.clone(), gateway.clone()).await
            } else {
                self.process_request(req, is_system_route, interface.clone(), gateway.clone()).await
            }
        })
            .await
        {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // Timeout occurred
                println!("Request timed out");
                Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap())
            }
        }
    }

    async fn process_connect(
        self,
        mut req: Request<Body>,
        is_system_route: bool,
        interface: String,
        gateway: String,
    ) -> Result<Response<Body>, hyper::Error> {
        let remote_addr = match req.uri().authority().map(|auth| auth.to_string()) {
            Some(addr) => addr,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Missing remote address"))
                    .unwrap());
            }
        };

        let client_upgrade = match req.extensions_mut().remove::<OnUpgrade>() {
            Some(upgrade) => upgrade,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Connection not upgradeable"))
                    .unwrap());
            }
        };

        let timeout_duration = DEFAULT_TIMEOUT;

        let addrs = match remote_addr.to_socket_addrs() {
            Ok(addrs) => addrs.collect::<Vec<_>>(),
            Err(e) => {
                println!("Invalid address: {}: {:?}", remote_addr, e);
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap());
            }
        };

        if addrs.is_empty() {
            println!("No valid addresses resolved");
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("Service Unavailable"))
                .unwrap());
        }

        let addr = addrs[0];
        let socket = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4().unwrap(),
            SocketAddr::V6(_) => TcpSocket::new_v6().unwrap(),
        };

        let bind_addr = match addr {
            SocketAddr::V4(_) => get_rand_ipv4_socket_addr(&self.ipv4_subnets),
            SocketAddr::V6(_) => get_rand_ipv6_socket_addr(&self.ipv6_subnets),
        };

        if is_system_route {
            let cmd_str = format!(
                "ip addr add {}/{} dev {}",
                bind_addr.ip(),
                if bind_addr.is_ipv6() {
                    128
                } else {
                    32
                },
                interface
            );
            self.execute_command(cmd_str).await;

            if !gateway.is_empty() {
                let cmd_traceroute_str = format!("traceroute -m 10 -s {} {}", bind_addr.ip(), gateway);
                self.execute_command(cmd_traceroute_str).await;
            }

            {
                let mut queue = self.address_queue.lock().await;
                queue.push_back(bind_addr.ip().to_string());
            }

            self.manage_address_count(&interface).await;
        }

        if socket.bind(bind_addr).is_err() {
            println!("Failed to bind to address");
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("Service Unavailable"))
                .unwrap());
        }

        let connect_result = timeout(timeout_duration, socket.connect(addr)).await;
        let mut server = match connect_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                println!("Failed to connect to server: {:?}", e);
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap());
            }
            Err(_) => {
                println!("Connection to {} timed out", remote_addr);
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap());
            }
        };
        tokio::spawn(async move {
            match timeout(timeout_duration, tokio::io::copy_bidirectional(&mut client_upgrade.await.unwrap(), &mut server)).await {
                Ok(Ok((client_bytes, server_bytes))) => {
                    println!("Client wrote {} bytes, server wrote {} bytes", client_bytes, server_bytes);

                }
                Ok(Err(err)) => {
                    println!("Tunnel error: {:?}", err);

                }
                Err(_) => {
                    println!("Tunnel timed out");
                }
            }
        });
        Ok(Response::new(Body::empty()))

    }


    async fn process_request(
        self,
        req: Request<Body>,
        is_system_route: bool,
        interface: String,
        gateway: String,
    ) -> Result<Response<Body>, hyper::Error> {
        let timeout_duration = Duration::from_secs(10); // 30 seconds timeout

        let bind_addr = if req.uri().scheme_str() == Some("https") {
            // 随机选择一个 IPv6 子网
            let ipv6_cidr = self.ipv6_subnets.choose(&mut rand::thread_rng()).unwrap();
            get_rand_ipv6(ipv6_cidr)
        } else {
            // 随机选择一个 IPv4 子网
            let ipv4_cidr = self.ipv4_subnets.choose(&mut rand::thread_rng()).unwrap();
            get_rand_ipv4(ipv4_cidr)
        };

        let mut http = HttpConnector::new();
        http.set_local_address(Some(bind_addr));
        println!("{} via {bind_addr}", req.uri().host().unwrap_or_default());

        if is_system_route {
            let cmd_str = format!(
                "ip addr add {}/{} dev {}",
                bind_addr,
                if bind_addr.is_ipv6() { 128 } else { 32 },
                interface
            );
            self.execute_command(cmd_str).await;

            if !gateway.is_empty() {
                let cmd_traceroute_str = format!("traceroute -m 10 -s {} {}", bind_addr, gateway);
                self.execute_command(cmd_traceroute_str).await;
            }

            {
                let mut queue = self.address_queue.lock().await;
                queue.push_back(bind_addr.to_string());
            }

            self.manage_address_count(&interface).await;
        }

        // Apply timeout to the HTTP request process
        match timeout(timeout_duration, async {
            let client = Client::builder()
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(http);

            client.request(req).await
        })
            .await
        {
            Ok(Ok(res)) => Ok(res),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // Timeout occurred
                println!("Request processing timed out");
                Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap())
            }
        }
    }

    async fn manage_address_count(&self, interface: &str) {
        let lock_timeout = Duration::from_secs(5);

        match timeout(lock_timeout, self.address_queue.lock()).await {
            Ok(mut queue) => {
                eprintln!("Acquired lock {}", queue.len());
                if queue.len() > MAX_ADDRESSES {
                    let addresses_to_remove = queue.len() - MAX_ADDRESSES;

                    for _ in 0..addresses_to_remove {
                        if let Some(addr) = queue.pop_front() {
                            let cmd_str = format!("ip addr del {}/{} dev {}", addr, if addr.contains(":") { 128 } else { 32 }, interface);
                            if let Err(e) = self.execute_command_del(cmd_str.clone()).await {
                                eprintln!("Failed to execute command {}: {:?}", cmd_str, e);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                eprintln!("Failed to acquire lock within timeout period");
            }
        }
    }

    async fn execute_command_del(&self, cmd_str: String) -> Result<(), Box<dyn Error>> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd_str)
            .output()
            .await?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!("Command failed with status: {:?}", output.status).into())
        }
    }

    async fn execute_command(&self, cmd_str: String) {
        println!("{cmd_str} ");
        task::spawn(async move {
            let _result = Command::new("sh")
                .arg("-c")
                .arg(&cmd_str)
                .status()
                .await
                .map_err(|e| eprintln!("Failed to execute command: {}. Error: {}", cmd_str, e))
                .ok();
        });
    }
}
fn get_rand_ipv4_socket_addr(ipv4_subnets: &[Ipv4Cidr]) -> SocketAddr {
    let mut rng = rand::thread_rng();
    let ipv4_cidr = ipv4_subnets.choose(&mut rng).unwrap(); // 从列表中随机选择一个子网
    SocketAddr::new(get_rand_ipv4(ipv4_cidr), rng.gen::<u16>())
}

fn get_rand_ipv6_socket_addr(ipv6_subnets: &[Ipv6Cidr]) -> SocketAddr {
    let mut rng = rand::thread_rng();
    let ipv6_cidr = ipv6_subnets.choose(&mut rng).unwrap(); // 从列表中随机选择一个子网
    SocketAddr::new(get_rand_ipv6(ipv6_cidr), rng.gen::<u16>())
}

fn get_rand_ipv4(ipv4_cidr: &Ipv4Cidr) -> IpAddr {
    // let mut rng = rand::thread_rng();
    let mut ipv4 = u32::from(ipv4_cidr.first_address());  // 使用 first_address() 获取网络地址
    if ipv4_cidr.network_length() != 32 {
        let rand: u32 = random();
        let net_part = (ipv4 >> (32 - ipv4_cidr.network_length())) << (32 - ipv4_cidr.network_length());
        let host_part = (rand << ipv4_cidr.network_length()) >> ipv4_cidr.network_length();
        ipv4 = net_part | host_part;
    }
    IpAddr::V4(ipv4.into())
}

fn get_rand_ipv6(ipv6_cidr: &Ipv6Cidr) -> IpAddr {
    // let mut rng = rand::thread_rng();
    let mut ipv6 = u128::from(ipv6_cidr.first_address());  // 使用 first_address() 获取网络地址
    if ipv6_cidr.network_length() != 128 {
        let rand: u128 = random();
        let net_part = (ipv6 >> (128 - ipv6_cidr.network_length())) << (128 - ipv6_cidr.network_length());
        let host_part = (rand << ipv6_cidr.network_length()) >> ipv6_cidr.network_length();
        ipv6 = net_part | host_part;
    }
    IpAddr::V6(ipv6.into())
}

