use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::{collections::HashMap, io, net::Ipv4Addr};

mod tcp;

const IPV4_PROTO: u16 = 0x0800;

#[derive(Debug, Hash, Clone, Copy, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::State> = Default::default();
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buffer = [0u8; 1504];
    loop {
        let read_length = nic.recv(&mut buffer)?;
        let _ethernet_flags = u16::from_be_bytes([buffer[0], buffer[1]]);
        let ethernet_protocol = u16::from_be_bytes([buffer[2], buffer[3]]);
        if ethernet_protocol != IPV4_PROTO {
            continue;
        }

        let buffer = &buffer[4..read_length];
        let ip_header = match Ipv4HeaderSlice::from_slice(buffer) {
            Ok(packet) => packet,
            Err(e) => {
                eprintln!("Ignoring weird IP packet: {}", e);
                continue;
            }
        };

        if ip_header.protocol() != IpNumber::Tcp as u8 {
            continue;
        }

        let buffer = &buffer[ip_header.slice().len()..];
        let tcp_header = match TcpHeaderSlice::from_slice(&buffer) {
            Ok(packet) => packet,
            Err(e) => {
                eprintln!("Ignoring weird TCP packet: {}", e);
                continue;
            }
        };

        let buffer = &buffer[tcp_header.slice().len()..];
        connections
            .entry(Quad {
                src: (ip_header.source_addr(), tcp_header.source_port()),
                dst: (ip_header.destination_addr(), tcp_header.destination_port()),
            })
            .or_default()
            .on_packet(ip_header, tcp_header, buffer);
    }
}
