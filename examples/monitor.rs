#[macro_use(u32_bytes, bytes_u32)]
extern crate dhcp4r;
extern crate time;

use std::net::{UdpSocket,Ipv4Addr};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::ops::Add;

use dhcp4r::{packet, options, server};

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:67").unwrap();
    socket.set_broadcast(true).unwrap();

    let ms = MyServer {
        //leases: HashMap::new(),
        //last_lease: 0,
        //lease_duration: Duration::new(LEASE_DURATION_SECS as u64, 0),
    };

    server::Server::serve(socket, [0,0,0,0], ms);
}

struct MyServer {
    //leases: HashMap<u32, ([u8; 6], Instant)>,
    //last_lease: u32,
    //lease_duration: Duration,
}

impl server::Handler for MyServer {
    // fn handle_request(&Server, u8, Packet);
    fn handle_request(&mut self,
                      server: &server::Server,
                      msg_type: u8,
                      in_packet: packet::Packet) {
        match msg_type {
            dhcp4r::REQUEST => {
                let req_ip = match in_packet.option(options::REQUESTED_IP_ADDRESS) {
                    None => in_packet.ciaddr,
                    Some(x) => {
                        if x.len() != 4 {
                            return;
                        } else {
                            [x[0], x[1], x[2], x[3]]
                        }
                    }
                };

                println!("{}\t{}\t{}\tOnline", time::now().strftime("%Y-%m-%dT%H:%M:%S").unwrap(),
                 chaddr(&in_packet.chaddr), Ipv4Addr::from(req_ip));
            }
            _ => {}
        }
    }
}

fn chaddr(a: &[u8]) -> String {
    let mut z = a.iter().fold(String::new(), |acc, &b| format!("{}{:02x}:", acc, &b));
    z.truncate(17);
    z
}
