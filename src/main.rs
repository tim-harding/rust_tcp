use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buffer = [0u8; 1504];
    let read_len = nic.recv(&mut buffer)?;
    println!("read {} bytes: {:x?}", read_len, &buffer[..read_len]);
    Ok(())
}
