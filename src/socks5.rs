use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::error::Error;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

use rand::random;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use lazy_static::lazy_static;

use std::io;
lazy_static! {
    static ref SOCKS5_ADDRESS_QUEUE: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
}


const SOCKS_VERSION: u8 = 0x05;
const RESERVED: u8 = 0x00;

pub async fn start_socks5_proxy(
    listen_addr: SocketAddr,
    (ipv6, ipv6_prefix_len): (Ipv6Addr, u8),
    (ipv4, ipv4_prefix_len): (Ipv4Addr, u8),
    allowed_ips: Option<Vec<IpAddr>>,  // 允许的 IP 地址列表
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(listen_addr).await?;
    println!("SOCKS5 proxy listening on {}", listen_addr);


    loop {
        let (mut socket, addr) = listener.accept().await?;

        // 检查客户端 IP 地址是否在允许的 IP 列表中
        if let Some(ref allowed_ips) = allowed_ips {
            if !allowed_ips.contains(&addr.ip()) {
                eprintln!("Access denied for IP: {}", addr.ip());
                continue;  // 如果不在列表中，直接拒绝连接
            }
        }

        let bind_addr = match (ipv4, ipv6) {
            (Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED) => {
                // Both IPv4 and IPv6 are unspecified, use both.
                match socket.local_addr()? {
                    SocketAddr::V4(_) => get_rand_ipv4_socket_addr(ipv4, ipv4_prefix_len),
                    SocketAddr::V6(_) => get_rand_ipv6_socket_addr(ipv6, ipv6_prefix_len),
                }
            }
            (Ipv4Addr::UNSPECIFIED, _) => {
                // Only IPv4 is unspecified, use IPv6.
                get_rand_ipv6_socket_addr(ipv6, ipv6_prefix_len)
            }
            (_, Ipv6Addr::UNSPECIFIED) => {
                // Only IPv6 is unspecified, use IPv4.
                get_rand_ipv4_socket_addr(ipv4, ipv4_prefix_len)
            }
            _ => {
                // If neither is unspecified, use the address type of the socket.
                match socket.local_addr()? {
                    SocketAddr::V4(_) => get_rand_ipv4_socket_addr(ipv4, ipv4_prefix_len),
                    SocketAddr::V6(_) => get_rand_ipv6_socket_addr(ipv6, ipv6_prefix_len),
                }
            }
        };



        tokio::spawn(async move {
            if let Err(e) = handle_socks5_connection(&mut socket, bind_addr).await {
                eprintln!("Failed to handle SOCKS5 connection: {}", e);
            }
        });
    }
}

async fn handle_socks5_connection(
    socket: &mut TcpStream,
    bind_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0; 2];
    socket.read_exact(&mut buf).await?;

    if buf[0] != SOCKS_VERSION {
        return Err("Unsupported SOCKS version".into());
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0; nmethods];
    socket.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        socket.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        return Err("No acceptable authentication method".into());
    }

    socket.write_all(&[SOCKS_VERSION, 0x00]).await?;

    let mut buf = [0; 4];
    socket.read_exact(&mut buf).await?;

    let addr = match buf[3] {
        0x01 => {
            // IPv4 address
            let mut ipv4 = [0; 4];
            socket.read_exact(&mut ipv4).await?;
            let port = read_port(socket).await?;
            SocketAddr::new(IpAddr::V4(ipv4.into()), port)
        }
        0x03 => {
            // Domain name
            let mut domain_len = [0; 1];
            socket.read_exact(&mut domain_len).await?;
            let mut domain = vec![0; domain_len[0] as usize];
            socket.read_exact(&mut domain).await?;
            let port = read_port(socket).await?;
            let domain = String::from_utf8(domain)?;
            let addr_str = format!("{}:{}", domain, port);
            tokio::net::lookup_host(addr_str).await?.next().ok_or("Invalid domain name")?
        }
        0x04 => {
            // IPv6 address
            let mut ipv6 = [0; 16];
            socket.read_exact(&mut ipv6).await?;
            let port = read_port(socket).await?;
            SocketAddr::new(IpAddr::V6(ipv6.into()), port)
        }
        _ => return Err("Unsupported address type".into()),
    };

    // Create a TcpSocket and bind it to bind_addr
    let socket_type = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };

    socket_type.bind(bind_addr)?;

    // Connect to the remote address using the bound local address
    let mut remote = socket_type.connect(addr).await?;

    let reply = SocksReply::new(ResponseCode::Success);
    reply.send(socket).await?;

    tokio::io::copy_bidirectional(socket, &mut remote).await?;
    Ok(())
}

async fn read_port(socket: &mut TcpStream) -> Result<u16, Box<dyn Error>> {
    let mut buf = [0; 2];
    socket.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

fn get_rand_ipv4_socket_addr(ipv4: Ipv4Addr, prefix_len: u8) -> SocketAddr {
    let ip_addr = get_rand_ipv4(ipv4.into(), prefix_len);
    SocketAddr::new(ip_addr, random::<u16>())
}

fn get_rand_ipv6_socket_addr(ipv6: Ipv6Addr, prefix_len: u8) -> SocketAddr {
    let ip_addr = get_rand_ipv6(ipv6.into(), prefix_len);
    SocketAddr::new(ip_addr, random::<u16>())
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

struct SocksReply {
    buf: [u8; 10],
}

impl SocksReply {
    pub fn new(status: ResponseCode) -> Self {
        let buf = [
            SOCKS_VERSION,        // VER
            status as u8,         // REP
            RESERVED,             // RSV
            0x01,                 // ATYP (IPv4)
            0, 0, 0, 0,           // BND.ADDR
            0, 0,                 // BND.PORT
        ];
        Self { buf }
    }

    pub async fn send<T>(&self, stream: &mut T) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        stream.write_all(&self.buf).await?;
        Ok(())
    }
}

#[derive(Debug)]
enum ResponseCode {
    Success = 0x00,
    // Failure = 0x01,
    // RuleFailure = 0x02,
    // NetworkUnreachable = 0x03,
    // HostUnreachable = 0x04,
    // ConnectionRefused = 0x05,
    // TtlExpired = 0x06,
    // CommandNotSupported = 0x07,
    // AddrTypeNotSupported = 0x08,
}
