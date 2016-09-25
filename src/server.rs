use std::net::{UdpSocket, SocketAddr, Ipv4Addr, IpAddr};
use std;
use std::cell::Cell;

use packet::*;
use options;
use NAK;

pub struct Server {
    out_buf: Cell<[u8; 1500]>,
    socket: UdpSocket,
    src: SocketAddr,
    server_ip: [u8; 4],
}

pub trait Handler {
    fn handle_request(&mut self, &Server, u8, Packet);
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
                        if let Some(msg_type) = p.option(options::DHCP_MESSAGE_TYPE) {
                            if msg_type.len() != 1 || !s.for_this_server(&p) {
                                continue;
                            }
                            s.src = src;
                            handler.handle_request(&s, msg_type[0], p);
                        }
                    }
                }
            }
        }
    }

    pub fn reply(&self,
                 msg_type: u8,
                 additional_options: Vec<options::Option>,
                 offer_ip: [u8; 4],
                 req_packet: Packet)
                 -> std::io::Result<usize> {
        let mt = &[msg_type];
        let mut opts: Vec<options::Option> = Vec::with_capacity(additional_options.len() + 2);
        opts.push(options::Option {
            code: options::DHCP_MESSAGE_TYPE,
            data: mt,
        });
        opts.push(options::Option {
            code: options::SERVER_IDENTIFIER,
            data: &self.server_ip,
        });
        opts.extend(additional_options);
        self.send(Packet {
            reply: true,
            hops: 0,
            xid: req_packet.xid,
            secs: 0,
            broadcast: req_packet.broadcast,
            ciaddr: if msg_type == NAK {
                [0, 0, 0, 0]
            } else {
                req_packet.ciaddr
            },
            yiaddr: offer_ip,
            siaddr: [0, 0, 0, 0],
            giaddr: req_packet.giaddr,
            chaddr: req_packet.chaddr,
            options: opts,
        })
    }

    fn for_this_server(&self, packet: &Packet) -> bool {
        match packet.option(options::SERVER_IDENTIFIER) {
            None => false,
            Some(x) => (x == &self.server_ip),
        }
    }

    fn send(&self, p: Packet) -> std::io::Result<usize> {
        let mut addr = self.src;
        if p.broadcast || addr.ip() == IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) {
            addr.set_ip(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)));
        }
        self.socket.send_to(p.encode(&mut self.out_buf.get()), addr)
    }
}
