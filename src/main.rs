use std::io;

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
        let packet = match etherparse::Ipv4HeaderSlice::from_slice(data) {
            Ok(packet) => packet,
            Err(e) => {
                eprintln!("Ignoring weird packet: {}", e);
                continue;
            }
        };

        println!(
            "{} -> {}, {} bytes of {}",
            packet.source_addr(),
            packet.destination_addr(),
            packet.payload_len(),
            packet.protocol(),
        );
    }
}
