use std::io;

use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};

const IPV4_PROTO: u16 = 0x0800;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buffer = [0u8; 1504];
    loop {
        let read_length = nic.recv(&mut buffer)?;
        let ethernet_flags = u16::from_be_bytes([buffer[0], buffer[1]]);
        let ethernet_protocol = u16::from_be_bytes([buffer[2], buffer[3]]);
        if ethernet_protocol != IPV4_PROTO {
            continue;
        }

        let data = &buffer[4..read_length];
        let data_length = read_length - 4;
        let ip_packet = match Ipv4HeaderSlice::from_slice(data) {
            Ok(packet) => packet,
            Err(e) => {
                eprintln!("Ignoring weird IP packet: {}", e);
                continue;
            }
        };

        if ip_packet.protocol() != IpNumber::Tcp as u8 {
            continue;
        }

        let tcp_packet = match TcpHeaderSlice::from_slice(&data[ip_packet.slice().len()..]) {
            Ok(packet) => packet,
            Err(e) => {
                eprintln!("Ignoring weird TCP packet: {}", e);
                continue;
            }
        };

        println!(
            "{} -> {}, {} bytes of TCP to port {}",
            ip_packet.source_addr(),
            ip_packet.destination_addr(),
            ip_packet.payload_len(),
            tcp_packet.destination_port(),
        );
    }
}
