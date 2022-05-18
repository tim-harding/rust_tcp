use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buffer = [0u8; 1504];
    loop {
        let read_len = nic.recv(&mut buffer)?;
        let flags = u16::from_be_bytes([buffer[0], buffer[1]]);
        let proto = u16::from_be_bytes([buffer[2], buffer[3]]);
        let data = &buffer[4..read_len];
        let data_len = read_len - 4;
        println!(
            "read {} bytes (flags: {:x}, proto: {:x}): {:x?}",
            data_len, flags, proto, data
        );
    }
}
