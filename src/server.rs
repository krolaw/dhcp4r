use std::net::{UdpSocket, SocketAddr, Ipv4Addr, IpAddr};
use std;
use std::cell::Cell;

use options::{DhcpOption, MessageType};
use packet::*;
use options;

///! This is a convenience module that simplifies the writing of a DHCP server service.

pub struct Server {
    out_buf: Cell<[u8; 1500]>,
    socket: UdpSocket,
    src: SocketAddr,
    server_ip: [u8; 4],
}

pub trait Handler {
    fn handle_request(&mut self, &Server, Packet);
}

/// Orders and filters options based on PARAMETER_REQUEST_LIST received from client.
/// DHCP_MESSAGE_TYPE and SERVER_IDENTIFIER are always first and always retained.
/// This function is called by Reply.
pub fn filter_options_by_req(opts: &mut Vec<DhcpOption>, req_params: &[u8]) {
    let mut pos = 0;
    let h = &[options::DHCP_MESSAGE_TYPE as u8, options::SERVER_IDENTIFIER as u8, options::IP_ADDRESS_LEASE_TIME as u8] as &[u8];
    for z in [h, req_params].iter() {
        for r in z.iter() {
            let mut found = false;
            let mut at = 0;
            for (i, o) in opts[pos..].iter().enumerate() {
                if o.code == *r {
                    found = true;
                    at = i + pos;
                    break;
                }
            }
            if found {
                opts.swap(pos, at);
                pos = pos + 1;
            }
        }
    }
    opts.truncate(pos);
}

impl Server {
    pub fn serve<H: Handler>(udp_soc: UdpSocket,
                             server_ip: [u8; 4],
                             mut handler: H)
                             -> std::io::Error {
        let mut in_buf: [u8; 1500] = [0; 1500];
        let mut s = Server {
            out_buf: Cell::new([0; 1500]),
            socket: udp_soc,
            server_ip: server_ip,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        };
        loop {
            match s.socket.recv_from(&mut in_buf) {
                Err(e) => return e,
                Ok((l, src)) => {
                    if let Ok(p) = decode(&in_buf[..l]) {
                        s.src = src;
                        handler.handle_request(&s, p);
                    }
                }
            }
        }
    }

    /// Constructs and sends a reply packet back to the client.
    /// additional_options should not include DHCP_MESSAGE_TYPE nor SERVER_IDENTIFIER as these
    /// are added automatically.
    pub fn reply(&self,
                 msg_type: MessageType,
                 additional_options: Vec<DhcpOption>,
                 offer_ip: [u8; 4],
                 req_packet: Packet)
                 -> std::io::Result<usize> {

        let ciaddr = match msg_type {
            MessageType::Nak => [0, 0, 0, 0],
            _ => req_packet.ciaddr,
        };

        let mt = &[msg_type as u8];

        let mut opts: Vec<DhcpOption> = Vec::with_capacity(additional_options.len() + 2);
        opts.push(DhcpOption {
            code: options::DHCP_MESSAGE_TYPE,
            data: mt,
        });
        opts.push(DhcpOption {
            code: options::SERVER_IDENTIFIER,
            data: &self.server_ip,
        });
        opts.extend(additional_options);

        if let Some(prl) = req_packet.option(options::PARAMETER_REQUEST_LIST) {
            filter_options_by_req(&mut opts, &prl);
        }

        self.send(Packet {
            reply: true,
            hops: 0,
            xid: req_packet.xid,
            secs: 0,
            broadcast: req_packet.broadcast,
            ciaddr: ciaddr,
            yiaddr: offer_ip,
            siaddr: [0, 0, 0, 0],
            giaddr: req_packet.giaddr,
            chaddr: req_packet.chaddr,
            options: opts,
        })
    }

    /// Checks the packet see if it was intended for this DHCP server (as opposed to some other also on the network).
    pub fn for_this_server(&self, packet: &Packet) -> bool {
        match packet.option(options::SERVER_IDENTIFIER) {
            None => false,
            Some(x) => (x == &self.server_ip),
        }
    }

    /// Encodes and sends a DHCP packet back to the client.
    pub fn send(&self, p: Packet) -> std::io::Result<usize> {
        let mut addr = self.src;
        if p.broadcast || addr.ip() == IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) {
            addr.set_ip(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)));
        }
        self.socket.send_to(p.encode(&mut self.out_buf.get()), addr)
    }
}
