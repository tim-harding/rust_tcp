use std::io;

const IPV4_PROTO: u16 = 0x0800;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buffer = [0u8; 1504];
    loop {
        let read_len = nic.recv(&mut buffer)?;
        let flags = u16::from_be_bytes([buffer[0], buffer[1]]);
        let proto = u16::from_be_bytes([buffer[2], buffer[3]]);
        if proto != IPV4_PROTO {
            continue;
        }

        let data = &buffer[4..read_len];
        let data_len = read_len - 4;
        let packet = match etherparse::Ipv4HeaderSlice::from_slice(data) {
            Ok(packet) => packet,
            Err(_) => continue,
        };

        println!(
            "read {} bytes (flags: {:x}, proto: {:x}): {:?}",
            data_len, flags, proto, packet
        );
    }
}
