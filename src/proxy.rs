use hyper::{
    client::HttpConnector,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Client, Method, Request, Response, Server,
};
use rand::{random, Rng};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use tokio::{io::{AsyncRead, AsyncWrite}, net::TcpSocket, task};
use std::sync::{Arc};
use tokio::process::Command;
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
const MAX_ADDRESSES: usize = 1000;


lazy_static! {
    // 使用全局的 Mutex 包装的 HashMap 来存储网址与 IP 的映射
    static ref IP_MAP: Mutex<HashMap<String, IpAddr>> = Mutex::new(HashMap::new());
}

pub async fn start_proxy(
    listen_addr: SocketAddr,
    is_system_route: bool,
    gateway: String,
    interface: String,
    (ipv6, prefix_len): (Ipv6Addr, u8),
) -> Result<(), Box<dyn std::error::Error>> {
    let interface_arc = Arc::new(interface);
    let gateway_arc = Arc::new(gateway);
    let make_service = make_service_fn(move |_: &AddrStream| {
        let interface_clone = Arc::clone(&interface_arc);
        let gateway_clone = Arc::clone(&gateway_arc);
        async move {
            let interface_per_request = interface_clone.clone();
            let gateway_per_request = gateway_clone.clone();
            Ok::<_, hyper::Error>(service_fn(move |req| {
                Proxy {
                    ipv6: ipv6.into(),
                    prefix_len,
                }
                    .proxy(req,is_system_route,(*interface_per_request).clone(),(*gateway_per_request).clone())
            }))
        }
    });

    Server::bind(&listen_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service)
        .await
        .map_err(|err| err.into())
}

#[derive(Clone, Copy)]
pub(crate) struct Proxy {
    pub ipv6: u128,
    pub prefix_len: u8,
}

impl Proxy {
    pub(crate) async fn proxy(self, req: Request<Body>,is_system_route: bool,interface: String, gateway: String) -> Result<Response<Body>, hyper::Error> {
        match if req.method() == Method::CONNECT {
            self.process_connect(req,is_system_route,interface.clone(),gateway.clone()).await
        } else {
            self.process_request(req,is_system_route,interface.clone(),gateway.clone()).await
        } {
            Ok(resp) => Ok(resp),
            Err(e) => Err(e),
        }
    }

    async fn process_connect(self, req: Request<Body>,is_system_route: bool,interface: String, gateway: String) -> Result<Response<Body>, hyper::Error> {
        tokio::task::spawn(async move {
            let remote_addr = req.uri().authority().map(|auth| auth.to_string()).unwrap();
            let mut upgraded = hyper::upgrade::on(req).await.unwrap();
            self.tunnel(&mut upgraded, remote_addr,is_system_route,interface.clone(),gateway).await
        });
        Ok(Response::new(Body::empty()))
    }

    async fn process_request(self, req: Request<Body>,is_system_route: bool,interface: String, gateway: String) -> Result<Response<Body>, hyper::Error> {
        let bind_addr = get_rand_ipv6(self.ipv6, self.prefix_len);
        let mut http = HttpConnector::new();
        http.set_local_address(Some(bind_addr));
        println!("{} via {bind_addr}", req.uri().host().unwrap_or_default());
        if is_system_route {

            let cmd_str = format!("ip addr add {}/{} dev {}", bind_addr,self.prefix_len,interface);
            self.execute_command(cmd_str).await;

            if gateway != "" {
                let cmd_traceroute_str = format!("traceroute -m 10 -s {} {}", bind_addr,gateway);
                self.execute_command(cmd_traceroute_str).await;
            }
            self.manage_address_count(&*interface).await;
        }
        let client = Client::builder()
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(http);
        let res = client.request(req).await?;
        Ok(res)
    }
    async fn manage_address_count(self, interface: &str) {
        let current_addresses = self.get_current_addresses(interface).await;
        if current_addresses.len() > MAX_ADDRESSES {
            let addresses_to_remove = current_addresses.len() - MAX_ADDRESSES;

            // Remove only the excess addresses, following FIFO order
            for addr in &current_addresses[..addresses_to_remove] {
                let cmd_str = format!("ip addr del {} dev {}", addr, interface);
                self.execute_command_del(&cmd_str).await;
            }
        }
    }
    async fn execute_command_del(&self, cmd: &str) {
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .await
            .expect("Failed to execute command");
    }
    async fn get_current_addresses(self,interface: &str) -> Vec<String> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("ip addr show dev {} | grep 'inet ' | awk '{{print $2}}'", interface))
            .output()
            .await
            .expect("Failed to execute command");

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.lines().map(|line| line.to_string()).collect()
    }
    async fn execute_command(&self, cmd_str: String)  {
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
    async fn tunnel<A>(self, upgraded: &mut A, addr_str: String,is_system_route: bool,interface: String,gateway: String) -> std::io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        if let Ok(addrs) = addr_str.to_socket_addrs() {
            for addr in addrs {
                let socket = TcpSocket::new_v6()?;
                let bind_addr = get_rand_ipv6_socket_addr(self.ipv6, self.prefix_len);
                if is_system_route {

                    let cmd_str = format!("ip addr add {}/{} dev {}", bind_addr.ip(),self.prefix_len,interface);

                    self.execute_command(cmd_str).await;
                    if gateway != "" {
                        let cmd_traceroute_str = format!("traceroute -m 10 -s {} {}", bind_addr.ip(),gateway);
                        self.execute_command(cmd_traceroute_str).await;
                    }
                    self.manage_address_count(&*interface).await;

                }
                if socket.bind(bind_addr).is_ok() {
                    println!("{addr_str} via {bind_addr}");
                    if let Ok(mut server) = socket.connect(addr).await {
                        tokio::io::copy_bidirectional(upgraded, &mut server).await?;
                        return Ok(());
                    }
                }
            }
        } else {
            println!("error: {addr_str}");
        }

        Ok(())
    }
}

fn get_rand_ipv6_socket_addr(ipv6: u128, prefix_len: u8) -> SocketAddr {
    let mut rng = rand::thread_rng();
    SocketAddr::new(get_rand_ipv6(ipv6, prefix_len), rng.gen::<u16>())
}

fn get_rand_ipv6(mut ipv6: u128, prefix_len: u8) -> IpAddr {
    if prefix_len == 128 {
        // 如果 prefix_len 为 128，直接返回原始地址
        return IpAddr::V6(ipv6.into());
    }
    let rand: u128 = random();
    let net_part = (ipv6 >> (128 - prefix_len)) << (128 - prefix_len);
    let host_part = (rand << prefix_len) >> prefix_len;
    ipv6 = net_part | host_part;
    IpAddr::V6(ipv6.into())
}
// fn get_rand_ipv6(mut ipv6: u128, prefix_len: u8, hostname: &str) -> IpAddr {
//     let mut ip_map = IP_MAP.lock().unwrap();
//
//     // 检查此 hostname 是否已有存储的 IP 地址
//     if let Some(ip) = ip_map.get(hostname) {
//         return *ip;
//     }
//
//     // 生成新的 IP 地址
//     let rand: u128 = rand::thread_rng().gen();
//     let net_part = (ipv6 >> (128 - prefix_len)) << (128 - prefix_len);
//     let host_part = (rand << prefix_len) >> prefix_len;
//     ipv6 = net_part | host_part;
//     let new_ip = IpAddr::V6(ipv6.into());
//
//     // 存储 hostname 与新生成的 IP 地址
//     ip_map.insert(hostname.to_string(), new_ip);
//
//     new_ip
// }