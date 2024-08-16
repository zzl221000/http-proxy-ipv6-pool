use hyper::{
    client::HttpConnector,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Client, Method, Request, Response, Server, StatusCode,
};
use rand::{random, Rng};
use std::net::{IpAddr, Ipv6Addr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use tokio::{io::{AsyncRead, AsyncWrite}, net::TcpSocket, task};
use std::sync::{Arc};
use tokio::process::Command;
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::time::Duration;
use tokio::sync::Mutex;
use lazy_static::lazy_static;
use tokio::time::timeout;
use std::io;

const MAX_ADDRESSES: usize = 1000;

lazy_static! {
    static ref IP_MAP: Mutex<HashMap<String, IpAddr>> = Mutex::new(HashMap::new());
    static ref GLOBAL_ADDRESS_QUEUE: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
}

pub async fn start_proxy(
    listen_addr: SocketAddr,
    is_system_route: bool,
    gateway: String,
    interface: String,
    (ipv6, ipv6_prefix_len): (Ipv6Addr, u8),
    (ipv4, ipv4_prefix_len): (Ipv4Addr, u8),
    allowed_ips: Option<Vec<IpAddr>>,  // 修改为 Option<Vec<IpAddr>>
) -> Result<(), Box<dyn std::error::Error>> {
    let interface_arc = Arc::new(interface);
    let gateway_arc = Arc::new(gateway);
    let allowed_ips_arc = allowed_ips.map(Arc::new);  // 将 allowed_ips 包装为 Option<Arc<Vec<IpAddr>>>

    let make_service = make_service_fn(move |conn: &AddrStream| {
        let remote_addr = conn.remote_addr();
        let interface_clone = Arc::clone(&interface_arc);
        let gateway_clone = Arc::clone(&gateway_arc);

        // 直接使用 allowed_ips_arc，而不是调用 Arc::clone
        let allowed_ips_clone = allowed_ips_arc.clone();

        async move {
            let service = service_fn(move |mut req: Request<Body>| {
                // 将客户端的 SocketAddr 添加到请求的扩展中
                req.extensions_mut().insert(remote_addr);

                let interface_per_request = interface_clone.clone();
                let gateway_per_request = gateway_clone.clone();

                Proxy {
                    ipv6: ipv6.into(),
                    ipv6_prefix_len,
                    ipv4: ipv4.into(),
                    ipv4_prefix_len,
                    address_queue: GLOBAL_ADDRESS_QUEUE.clone(),
                    allowed_ips: allowed_ips_clone.clone(),  // 直接传递 Option<Arc<Vec<IpAddr>>>
                }
                    .proxy(req, is_system_route, (*interface_per_request).clone(), (*gateway_per_request).clone())
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
    pub ipv6: u128,
    pub ipv6_prefix_len: u8,
    pub ipv4: u32,
    pub ipv4_prefix_len: u8,
    address_queue: Arc<Mutex<VecDeque<String>>>,
    allowed_ips: Option<Arc<Vec<IpAddr>>>,  // 修改为 Option<Arc<Vec<IpAddr>>>
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
                if !allowed_ips.contains(&client_ip) {
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
        let timeout_duration = Duration::from_secs(10); // 10 seconds timeout

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
            Ok(Err(e)) => {
                println!("Error processing request: {:?}", e);
                Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap())
            }
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
        req: Request<Body>,
        is_system_route: bool,
        interface: String,
        gateway: String,
    ) -> Result<Response<Body>, hyper::Error> {
        let remote_addr = req.uri().authority().map(|auth| auth.to_string()).unwrap();
        let mut upgraded = match hyper::upgrade::on(req).await {
            Ok(upgraded) => upgraded,
            Err(e) => {
                println!("Failed to upgrade connection: {:?}", e);
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap());
            }
        };

        // Attempt to process the tunnel connection
        match self
            .tunnel(&mut upgraded, remote_addr, is_system_route, interface.clone(), gateway)
            .await
        {
            Ok(_) => Ok(Response::new(Body::empty())),
            Err(e) => {
                println!("Error in tunnel: {:?}", e);
                Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap())
            }
        }
    }

    async fn process_request(
        self,
        req: Request<Body>,
        is_system_route: bool,
        interface: String,
        gateway: String,
    ) -> Result<Response<Body>, hyper::Error> {
        let timeout_duration = Duration::from_secs(10); // 10 seconds timeout

        let bind_addr = if req.uri().scheme_str() == Some("https") {
            get_rand_ipv6(self.ipv6, self.ipv6_prefix_len)
        } else {
            get_rand_ipv4(self.ipv4, self.ipv4_prefix_len)
        };

        let mut http = HttpConnector::new();
        http.set_local_address(Some(bind_addr));
        println!("{} via {bind_addr}", req.uri().host().unwrap_or_default());

        if is_system_route {
            let cmd_str = format!(
                "ip addr add {}/{} dev {}",
                bind_addr,
                if bind_addr.is_ipv6() { self.ipv6_prefix_len } else { self.ipv4_prefix_len },
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
            Ok(Err(e)) => {
                println!("Error processing HTTP request: {:?}", e);
                Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service Unavailable"))
                    .unwrap())
            }
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
                            let cmd_str = format!("ip addr del {}/{} dev {}", addr, if addr.contains(":") { self.ipv6_prefix_len } else { self.ipv4_prefix_len }, interface);
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

    async fn tunnel<A>(
        &self,
        upgraded: &mut A,
        addr_str: String,
        is_system_route: bool,
        interface: String,
        gateway: String,
    ) -> io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let timeout_duration = Duration::from_secs(10); // 10 seconds timeout

        if let Ok(addrs) = addr_str.to_socket_addrs() {
            for addr in addrs {
                // 根据 addr 的类型选择使用 IPv4 还是 IPv6
                let socket = match addr {
                    SocketAddr::V4(_) => TcpSocket::new_v4()?,
                    SocketAddr::V6(_) => TcpSocket::new_v6()?,
                };

                // 根据地址类型生成随机 IP 地址
                let bind_addr = match addr {
                    SocketAddr::V4(_) => get_rand_ipv4_socket_addr(self.ipv4, self.ipv4_prefix_len),
                    SocketAddr::V6(_) => get_rand_ipv6_socket_addr(self.ipv6, self.ipv6_prefix_len),
                };

                if is_system_route {
                    let cmd_str = format!(
                        "ip addr add {}/{} dev {}",
                        bind_addr.ip(),
                        if bind_addr.is_ipv6() { self.ipv6_prefix_len } else { self.ipv4_prefix_len },
                        interface
                    );

                    self.execute_command(cmd_str).await;
                    if !gateway.is_empty() {
                        let cmd_traceroute_str = format!(
                            "traceroute -m 10 -s {} {}",
                            bind_addr.ip(),
                            gateway
                        );
                        self.execute_command(cmd_traceroute_str).await;
                    }

                    {
                        let mut queue = self.address_queue.lock().await;
                        queue.push_back(bind_addr.ip().to_string());
                    }

                    self.manage_address_count(&interface).await;
                }

                // Apply timeout to the binding, connection, and data transfer process
                if let Ok(result) = timeout(timeout_duration, async {
                    if socket.bind(bind_addr).is_ok() {
                        println!("{addr_str} via {bind_addr}");
                        if let Ok(mut server) = socket.connect(addr).await {
                            tokio::io::copy_bidirectional(upgraded, &mut server).await?;
                            return Ok(());
                        }
                    }
                    Err(io::Error::new(io::ErrorKind::Other, "Failed to bind or connect"))
                })
                    .await
                {
                    return result;
                } else {
                    println!("Timeout occurred while handling {}", addr_str);
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "Operation timed out"));
                }
            }
        } else {
            println!("error: {addr_str}");
        }

        Ok(())
    }
}

fn get_rand_ipv4_socket_addr(ipv4: u32, prefix_len: u8) -> SocketAddr {
    let mut rng = rand::thread_rng();
    SocketAddr::new(get_rand_ipv4(ipv4, prefix_len), rng.gen::<u16>())
}
fn get_rand_ipv6_socket_addr(ipv6: u128, prefix_len: u8) -> SocketAddr {
    let mut rng = rand::thread_rng();
    SocketAddr::new(get_rand_ipv6(ipv6, prefix_len), rng.gen::<u16>())
}

fn get_rand_ipv6(mut ipv6: u128, prefix_len: u8) -> IpAddr {
    if prefix_len == 128 {
        return IpAddr::V6(ipv6.into());
    }
    let rand: u128 = random();
    let net_part = (ipv6 >> (128 - prefix_len)) << (128 - prefix_len);
    let host_part = (rand << prefix_len) >> prefix_len;
    ipv6 = net_part | host_part;
    IpAddr::V6(ipv6.into())
}

fn get_rand_ipv4(mut ipv4: u32, prefix_len: u8) -> IpAddr {
    if prefix_len == 32 {
        return IpAddr::V4(ipv4.into());
    }
    let rand: u32 = random();
    let net_part = (ipv4 >> (32 - prefix_len)) << (32 - prefix_len);
    let host_part = (rand << prefix_len) >> prefix_len;
    ipv4 = net_part | host_part;
    IpAddr::V4(ipv4.into())
}
