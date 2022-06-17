use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::Ipv4Addr,
};
use tcp::{Connection, StateError};
use thiserror::Error;
use tun_tap::Iface;

mod tcp;

#[derive(Debug, Error)]
enum MainError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    State(#[from] StateError),
}

#[derive(Debug, Hash, Clone, Copy, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> Result<(), MainError> {
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    let mut nic = Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
    let mut buffer = [0u8; 1500];
    loop {
        let read_length = nic.recv(&mut buffer)?;
        let buffer = &buffer[..read_length];
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
        match connections.entry(Quad {
            src: (ip_header.source_addr(), tcp_header.source_port()),
            dst: (ip_header.destination_addr(), tcp_header.destination_port()),
        }) {
            Entry::Occupied(mut entry) => {
                match entry
                    .get_mut()
                    .on_packet(&mut nic, ip_header, tcp_header, buffer)
                {
                    Ok(_) => {}
                    Err(e) => eprintln!("{}", e),
                }
            }
            Entry::Vacant(entry) => {
                match Connection::accept(&mut nic, ip_header, tcp_header, buffer) {
                    Ok(connection) => {
                        entry.insert(connection);
                    }
                    Err(e) => eprintln!("{}", e),
                }
            }
        }
    }
}
