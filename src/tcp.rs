use etherparse::{
    IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice, ValueError, WriteError,
};
use std::io;
use thiserror::Error;
use tun_tap::Iface;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Etherparse(#[from] WriteError),
    #[error("Expected a SYN packet")]
    ExpectedSynPacket,
    #[error("{0}")]
    Header(#[from] ValueError),
    #[error("UNA < ACK <= NXT did not hold")]
    AcknowledgmentCheck,
    #[error("Unspecified error")]
    Other,
}

pub enum State {
    SynReceived,
    Established,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    receive: ReceiveSequenceSpace,
    ip_header: Ipv4Header,
}

#[derive(Default)]
struct SendSequenceSpace {
    unacknowledged: u32,
    next: u32,
    window: u16,
    urgent: bool,
    last_window_update_sequence: u32,
    last_window_update_acknowledgement: u32,
    initial_sequence: u32,
}

#[derive(Default)]
struct ReceiveSequenceSpace {
    next: u32,
    window: u16,
    urgent: bool,
    initial_sequence: u32,
}

impl Connection {
    pub fn accept(
        nic: &mut Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        data: &[u8],
    ) -> Result<Self, StateError> {
        println!(
            "{}:{} -> {}:{}, {} bytes of TCP",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            data.len(),
        );

        if !tcp_header.syn() {
            Err(StateError::ExpectedSynPacket)?
        }

        let initial_sequence = 0;
        let window = 10;

        let receive = ReceiveSequenceSpace {
            initial_sequence: tcp_header.sequence_number(),
            next: tcp_header.sequence_number() + 1,
            window: tcp_header.window_size(),
            urgent: false,
        };

        // Started establishing a connection
        let mut syn_ack = TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            initial_sequence, // Should be random eventually
            window,           // Some window size
        );
        // The next thing we expect is the next byte of the sequence
        syn_ack.acknowledgment_number = receive.next;
        // Acknowledging their sync request
        syn_ack.ack = true;
        // We're including a sync request as well
        syn_ack.syn = true;

        let mut ip = Ipv4Header::new(
            0,
            30,
            IpNumber::Tcp,
            ip_header.destination(),
            ip_header.source(),
        );

        // This needs to be done for each packet,
        // so we set this outside the constructor to avoid confusion.
        ip.set_payload_len(syn_ack.header_len() as usize)?;

        ip.header_checksum = ip.calc_header_checksum()?;
        syn_ack.checksum = syn_ack.calc_checksum_ipv4(&ip, &[])?;

        let connection = Connection {
            state: State::SynReceived,
            send: SendSequenceSpace {
                initial_sequence: initial_sequence,
                unacknowledged: initial_sequence,
                next: initial_sequence + 1,
                window: 10,
                urgent: false,
                last_window_update_sequence: 0, // Not yet sure what these should be
                last_window_update_acknowledgement: 0,
            },
            receive,
            ip_header: ip,
        };

        let mut buffer = [0u8; 1500];
        let written = {
            let buffer_len = buffer.len();
            let mut unwritten = &mut buffer[..];
            connection.ip_header.write(&mut unwritten)?;
            syn_ack.write(&mut unwritten)?;
            buffer_len - unwritten.len()
        };

        let buffer = &buffer[..written];
        nic.send(buffer)?;
        Ok(connection)
    }

    pub fn on_packet(
        &mut self,
        nic: &mut Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        data: &[u8],
    ) -> Result<(), StateError> {
        // Check that the ACK is acceptable:
        // SND.UNA < SEG.ACK <= SND.NXT
        // using arithmetic mod 2^32
        let ack = tcp_header.acknowledgment_number();
        let una = self.send.unacknowledged;
        let nxt = self.send.next;
        if una < ack {
            if ack <= nxt {
                // No wrapping
                // una < ack <= nxt
            } else {
                // una < ack, ack > nxt
                // nxt may have wrapped.
                // (una ack nxt) -> (nxt una ack) is fine
                // (una ack nxt) -> (una nxt ack) is wrong

                // (nxt = una) does not work because (una < ack <= nxt => una != nxt)
                if nxt >= una {
                    Err(StateError::AcknowledgmentCheck)?
                }
            }
        } else if ack < una {
            // (una ack nxt) -> (ack nxt una) is fine
            // (una ack nxt) -> (ack una nxt) is wrong
            // (una ack nxt) -> (nxt ack una) is wrong

            // (nxt = una) does not work because (una < ack <= nxt => una != nxt)
            // However, (nxt = ack) does work
            if !(nxt < una && nxt >= ack) {
                Err(StateError::AcknowledgmentCheck)?
            }
        } else {
            // una = ack
            Err(StateError::AcknowledgmentCheck)?
        }

        match self.state {
            State::SynReceived => {
                // Expect to get an ACK for our SYN

                Ok(())
            }
            State::Established => todo!(),
        }
    }
}
