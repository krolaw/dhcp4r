#[macro_use(u32_bytes, bytes_u32)]
extern crate dhcp4r;

use std::net::{UdpSocket, SocketAddr, Ipv4Addr, IpAddr};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::ops::Add;

// Server configuration
const SERVER_IP: [u8; 4] = [192, 168, 0, 76];
const IP_START: [u8; 4] = [192, 168, 0, 180];
const SUBNET_MASK: [u8; 4] = [255, 255, 255, 0];
const DNS_IPS: [u8; 4] = [192, 168, 0, 254]; //[8, 8, 8, 8,8, 8, 4, 4]; // google dns servers
const ROUTER_IP: [u8; 4] = [192, 168, 0, 254];
const LEASE_DURATION_SECS: u32 = 7200;
const LEASE_NUM: u32 = 100;

// Derrived constants
const LEASE_DURATION_BYTES: [u8; 4] = u32_bytes!(LEASE_DURATION_SECS);
const IP_START_NUM: u32 = bytes_u32!(IP_START);


fn main() {
    // let broadcast: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 67);

    let lease_duration: Duration = Duration::new(LEASE_DURATION_SECS as u64, 0);

    let mut lastpos: u32 = 0;
    let mut leases: HashMap<u32, ([u8; 6], Instant)> = HashMap::new();
    let socket = UdpSocket::bind("0.0.0.0:67").unwrap();
    socket.set_broadcast(true).unwrap();
    let mut in_buf = [0; 1500];
    let mut out_buf = [0; 1500];

    loop {
        let (n, src) = socket.recv_from(&mut in_buf).unwrap();
        println!("Packet received: {:?}", &in_buf[..n]);
        let packet = dhcp4r::decode(&in_buf[..n]).unwrap();

        if let Some(x) = packet.option(dhcp4r::OPTION_DHCP_MESSAGE_TYPE) {
            if x.len() != 1 {
                continue; // Invalid message - IGNORE
            }
            let send = Sender {
                soc: &socket,
                addr: src,
                buf: &mut out_buf, // broadcast: &broadcast,
            };
            match x[0] {
                dhcp4r::DISCOVER => {
                    // if let Some(x) = packet.option(dhcp4r::OPTION_REQUESTED_IP_ADDRESS) {}
                    for _ in 0..LEASE_NUM {
                        // TODO prefer REQUESTED_IP_ADDRESS
                        lastpos = (lastpos + 1) % LEASE_NUM;
                        if available(&mut leases,
                                     &packet.chaddr,
                                     &Instant::now(),
                                     IP_START_NUM + lastpos) {
                            reply(send,
                                  dhcp4r::OFFER,
                                  &packet,
                                  u32_bytes!(IP_START_NUM + lastpos));
                            break;
                        }

                    }
                }

                dhcp4r::REQUEST => {
                    if !for_this_server(&packet) {
                        continue;
                    }

                    let req_ip = match packet.option(dhcp4r::OPTION_REQUESTED_IP_ADDRESS) {
                        None => packet.ciaddr,
                        Some(x) => {
                            if x.len() != 4 {
                                continue;
                            } else {
                                [x[0], x[1], x[2], x[3]]
                            }
                        }
                    };

                    let req_ip_num = bytes_u32!(req_ip);
                    if !available(&leases, &packet.chaddr, &Instant::now(), req_ip_num) {
                        nak(send, &packet, b"Requested IP not available");
                        continue;
                    }
                    leases.insert(req_ip_num,
                                  (packet.chaddr, Instant::now().add(lease_duration)));
                    reply(send, dhcp4r::ACK, &packet, req_ip);
                }
                // Not technically necessary
                dhcp4r::RELEASE => {
                    if !for_this_server(&packet) {
                        continue;
                    }
                    let ip_num = bytes_u32!(packet.ciaddr);
                    if available(&leases, &packet.chaddr, &Instant::now(), ip_num) {
                        leases.remove(&ip_num);
                    }
                }
                // dhcp4r::INFORM => {}
                _ => {}
            }
        }

        // for option in packet.options {
        // print!("{}:{:?}\n", option.title(), option.data)
        // }
    }
}

struct Sender<'a> {
    buf: &'a mut [u8; 1500],
    soc: &'a UdpSocket,
    // broadcast: &'a SocketAddrV4,
    addr: SocketAddr,
}

impl<'a> Sender<'a> {
    fn send(self, p: dhcp4r::Packet) {
        let len = p.encode(self.buf);
        let mut addr = self.addr;
        if p.broadcast || addr.ip() == IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) {
            addr.set_ip(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)));
        }

        if let Err(x) = self.soc.send_to(&self.buf[..len], addr) {
            println!("Error: {}", x);
        } else {
            println!("Packet sent: {:?}", &self.buf[..len]);
        }
    }
}

fn for_this_server(packet: &dhcp4r::Packet) -> bool {
    match packet.option(dhcp4r::OPTION_SERVER_IDENTIFIER) {
        None => false,
        Some(x) => x == SERVER_IP,
    }
}

fn available(leases: &HashMap<u32, ([u8; 6], Instant)>,
             chaddr: &[u8; 6],
             instant: &Instant,
             pos: u32)
             -> bool {
    return pos >= IP_START_NUM && pos < IP_START_NUM + LEASE_NUM &&
           match leases.get(&pos) {
        Some(x) => x.0 == *chaddr && instant.gt(&x.1),
        None => true,
    };
}

fn nak(s: Sender, req_packet: &dhcp4r::Packet, message: &[u8]) {
    s.send(dhcp4r::Packet {
        reply: true,
        hops: 0,
        xid: req_packet.xid,
        secs: 0,
        broadcast: req_packet.broadcast,
        ciaddr: [0, 0, 0, 0],
        yiaddr: [0, 0, 0, 0],
        siaddr: [0, 0, 0, 0],
        giaddr: req_packet.giaddr,
        chaddr: req_packet.chaddr,
        options: vec![dhcp4r::Option {
                          code: dhcp4r::OPTION_DHCP_MESSAGE_TYPE,
                          data: &[dhcp4r::NAK],
                      },
                      dhcp4r::Option {
                          code: dhcp4r::OPTION_SERVER_IDENTIFIER,
                          data: &SERVER_IP,
                      },
                      dhcp4r::Option {
                          code: dhcp4r::OPTION_MESSAGE,
                          data: message,
                      }],
    });
}

fn reply(s: Sender, msg_type: u8, req_packet: &dhcp4r::Packet, offer_ip: [u8; 4]) {
    s.send(dhcp4r::Packet {
        reply: true,
        hops: 0,
        xid: req_packet.xid,
        secs: 0,
        broadcast: req_packet.broadcast,
        ciaddr: req_packet.ciaddr,
        yiaddr: offer_ip,
        siaddr: [0, 0, 0, 0], // SERVER_IP,
        giaddr: req_packet.giaddr,
        chaddr: req_packet.chaddr,
        options: vec![dhcp4r::Option {
                          code: dhcp4r::OPTION_DHCP_MESSAGE_TYPE,
                          data: &[msg_type],
                      },
                      dhcp4r::Option {
                          code: dhcp4r::OPTION_SERVER_IDENTIFIER,
                          data: &SERVER_IP,
                      },
                      dhcp4r::Option {
                          code: dhcp4r::OPTION_IP_ADDRESS_LEASE_TIME,
                          data: &LEASE_DURATION_BYTES,
                      },
                      dhcp4r::Option {
                          code: dhcp4r::OPTION_SUBNET_MASK,
                          data: &SUBNET_MASK,
                      },
                      dhcp4r::Option {
                          code: dhcp4r::OPTION_ROUTER,
                          data: &ROUTER_IP,
                      },
                      dhcp4r::Option {
                          code: dhcp4r::OPTION_DOMAIN_NAME_SERVER,
                          data: &DNS_IPS,
                      }],
    });
}
