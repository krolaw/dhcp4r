#[macro_use(u32_bytes, bytes_u32)]
extern crate dhcp4r;

use std::net::UdpSocket;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::ops::Add;
use std::cmp::PartialEq;

// Server configuration
const SERVER_IP: [u8; 4] = [192, 168, 1, 76];
const IP_START: [u8; 4] = [192, 168, 1, 100];
const SUBNET_MASK: [u8; 4] = [255, 255, 255, 0];
const DNS_IPS: [u8; 8] = [8, 8, 8, 8, 8, 8, 4, 4]; // google dns servers
const ROUTER_IP: [u8; 4] = [192, 168, 1, 254];
const LEASE_DURATION_SECS: u32 = 600;
const LEASE_NUM: u32 = 100;

// Derrived constants
const LEASE_DURATION_BYTES: [u8; 4] = u32_bytes!(LEASE_DURATION_SECS);
const IP_START_NUM: u32 = bytes_u32!(IP_START);

fn main() {
    let lease_duration: Duration = Duration::new(LEASE_DURATION_SECS as u64, 0);

    let mut lastpos: u32 = 0;
    let mut leases: HashMap<u32, ([u8; 6], Instant)> = HashMap::new();
    let socket = UdpSocket::bind("255.255.255.255:67").unwrap();
    // socket.set_broadcast(true).unwrap();
    let mut buf = [0; 1500];

    loop {
        let (n, _) = socket.recv_from(&mut buf).unwrap();
        println!("Packet received: {:?}", &buf[..n]);
        let packet = dhcp4r::decode(&buf[..n]).unwrap();

        if let Some(x) = packet.option(dhcp4r::OPTION_DHCP_MESSAGE_TYPE) {
            if x.len() != 1 {
                continue; // Invalid message - IGNORE
            }
            let resp_packet: dhcp4r::Packet;
            match x[0] {
                dhcp4r::DISCOVER => {
                    let instant = Instant::now();
                    for i in 1..LEASE_NUM {
                        if available(&mut leases, &packet.chaddr, &instant, lastpos) {
                            resp_packet = reply(dhcp4r::OFFER,
                                                &packet,
                                                u32_bytes!(IP_START_NUM + lastpos));
                            break;
                        }
                        lastpos = (lastpos + 1) % LEASE_NUM;
                    }
                    // TODO favour REQUESTED_IP_ADDRESS
                    // No available leases, ignore
                    continue;
                }

                dhcp4r::REQUEST => {
                    if notForThisServer(&packet) {
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
                    if req_ip_num < IP_START_NUM || req_ip_num >= IP_START_NUM + LEASE_NUM ||
                       !available(&leases,
                                  &packet.chaddr,
                                  &Instant::now(),
                                  req_ip_num - IP_START_NUM) {
                        // TODO reply NAK
                        continue;
                    }

                    if let Some(l) = leases.get(&req_ip_num) {
                        // TODO check lease time
                        if l.0 != packet.chaddr {
                            // TODO reply NAK
                            continue;
                        }
                    }
                    leases.insert(req_ip_num - IP_START_NUM,
                                  (packet.chaddr, Instant::now().add(lease_duration)));
                    resp_packet = reply(dhcp4r::ACK, &packet, req_ip);
                }
                // Not technically necessary
                dhcp4r::RELEASE => {
                    if notForThisServer(&packet) {
                        continue;
                    }
                    let ip_num = bytes_u32!(packet.ciaddr);
                    if available(&leases, &packet.chaddr, &Instant::now(), ip_num) {
                        leases.remove(&ip_num);
                    }
                    continue;
                }
                // dhcp4r::INFORM => {}
                _ => {
                    continue;
                }
            }
            if let Err(x) = socket.send(&buf[..resp_packet.encode(&mut buf)]) {
                println!("Error: {}", x);
            }

        }

        // for option in packet.options {
        // print!("{}:{:?}\n", option.title(), option.data)
        // }
    }
}

fn notForThisServer(packet: &dhcp4r::Packet) -> bool {
    match packet.option(dhcp4r::OPTION_SERVER_IDENTIFIER) {
        None => true,
        Some(x) => x != SERVER_IP,
    }
}

fn available(leases: &HashMap<u32, ([u8; 6], Instant)>,
             chaddr: &[u8; 6],
             instant: &Instant,
             pos: u32)
             -> bool {
    if let Some(x) = leases.get(&pos) {
        return x.0 == *chaddr || instant.gt(&x.1);
    }
    true
}

// fn write(s: UdpSocket, p: dhcp4r::Packet) {
//
// }

fn nak<'a>(req_packet: dhcp4r::Packet, message: &'a [u8]) -> dhcp4r::Packet<'a> {
    dhcp4r::Packet {
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
    }
}

fn reply<'a>(msg_type: u8, req_packet: &dhcp4r::Packet, offer_ip: [u8; 4]) -> dhcp4r::Packet<'a> {
    dhcp4r::Packet {
        reply: true,
        hops: 0,
        xid: req_packet.xid,
        secs: 0,
        broadcast: req_packet.broadcast,
        ciaddr: req_packet.ciaddr,
        yiaddr: req_packet.yiaddr,
        siaddr: SERVER_IP,
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
                          code: dhcp4r::OPTION_ROUTER,
                          data: &ROUTER_IP,
                      },
                      dhcp4r::Option {
                          code: dhcp4r::OPTION_SUBNET_MASK,
                          data: &SUBNET_MASK,
                      },
                      dhcp4r::Option {
                          code: dhcp4r::OPTION_DOMAIN_NAME_SERVER,
                          data: &DNS_IPS,
                      }],
    }
}
