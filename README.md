# TCP

## Running

`cargo run`

These commands need to be run first to give the program the right permissions:
```
sudo setcap CAP_NET_ADMIN=eip target/release/tcp
sudo setcap CAP_NET_ADMIN=eip target/release/tcp
```
And this assigns an IP address to the interface so we can connect to it:
```
sudo ip addr add 192.168.0.1/24 dev tun0
```
First check that `tun0` is available by running `ip addr`. To test that it can get a packet, use `sudo ip link set up dev tun0` and check that there is some output from the program.