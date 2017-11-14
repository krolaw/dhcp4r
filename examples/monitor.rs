extern crate dhcp4r;
extern crate time;

use std::net::{UdpSocket,Ipv4Addr};
use dhcp4r::{packet, options, server};

fn main() {
    server::Server::serve(UdpSocket::bind("0.0.0.0:67").unwrap(), [0,0,0,0], MyServer{});
}

struct MyServer {}

impl server::Handler for MyServer {
    fn handle_request(&mut self, _: &server::Server, in_packet: packet::Packet) {
        match in_packet.message_type() {
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

/// Formats byte array machine address into hex pairs separated by colons.
/// Array must be at least one byte long.
fn chaddr(a: &[u8]) -> String {
    a[1..].iter().fold(format!("{:02x}",a[0]), |acc, &b| format!("{}:{:02x}", acc, &b))
}
