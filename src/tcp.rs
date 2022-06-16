use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice, WriteError};
use std::io;
use thiserror::Error;
use tun_tap::Iface;

use crate::tcp;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Etherparse(#[from] WriteError),
    #[error("Expected a SYN packet")]
    ExpectedSynPacket,
    #[error("Unspecified error")]
    Other,
}

pub enum State {
    Closed,
    Listen,
    SynReceived,
    Established,
}

impl Default for State {
    fn default() -> Self {
        State::Listen
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    receive: ReceiveSequenceSpace,
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
            receive: ReceiveSequenceSpace {
                initial_sequence: tcp_header.sequence_number(),
                next: tcp_header.sequence_number() + 1,
                window: tcp_header.window_size(),
                urgent: false,
            },
        };

        // Started establishing a connection
        let syn_ack = {
            let mut syn_ack = TcpHeader::new(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                connection.send.initial_sequence, // Should be random eventually
                connection.send.window,           // Some window size
            );
            // The next thing we expect is the next byte of the sequence
            syn_ack.acknowledgment_number = connection.receive.next;
            // Acknowledging their sync request
            syn_ack.ack = true;
            // We're including a sync request as well
            syn_ack.syn = true;
            syn_ack
        };

        let ip = Ipv4Header::new(
            syn_ack.header_len(),
            30,
            IpNumber::Tcp,
            ip_header.destination(),
            ip_header.source(),
        );

        // How much space is remaining in the buffer after writing both of our headers?
        let mut buffer = [0u8; 1500];
        let unwritten = {
            let mut unwritten = &mut buffer[..];
            ip.write(&mut unwritten)?;
            syn_ack.write(&mut unwritten)?;
            unwritten.len()
        };
        nic.send(&buffer[..unwritten])?;
        Ok(connection)
    }

    pub fn on_packet(
        &mut self,
        _nic: &mut Iface,
        _ip_header: Ipv4HeaderSlice,
        _tcp_header: TcpHeaderSlice,
        _data: &[u8],
    ) -> Result<(), StateError> {
        match self.state {
            State::Closed => Ok(()),
            State::Listen => Ok(()),
            State::SynReceived => Ok(()),
            State::Established => Ok(()),
        }
    }
}
