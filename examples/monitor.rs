extern crate dhcp4r;

use std::net::UdpSocket;

fn main() {
    let socket = try!(UdpSocket::bind("255.255.255.255:67"));
    // socket.set_broadcast(true).unwrap();
    println!("Open");
    let mut buf = [0; 1500];
    // let mut packet = dhcp4r::Packet::new();
    loop {
        let (n, _) = try!(socket.recv_from(&mut buf));
        println!("Packet received: {:?}", &buf[..n]);
        let packet = try!(dhcp4r::decode(&buf[..n]));

        let msgType = match packet.option(dhcp4r::OPTION_DHCP_MESSAGE_TYPE) {
            None => continue,
            Some(x) => x.

        }



        // if packet.decode(&buf[..n]) {
        for option in packet.options {
            print!("{}:{:?}\n", option.title(), option.data)
        }
        // }
        // packet.options.clear()
    }



}
