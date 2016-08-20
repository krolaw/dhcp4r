// use std::net;

#[macro_export]
macro_rules! u32_bytes {
    ( $x:expr ) => {
        [($x >> 24) as u8, ($x >> 16) as u8, ($x >> 8) as u8, $x as u8]
    };
}

#[macro_export]
macro_rules! bytes_u32 {
    ( $x:expr ) => {
        ($x[0] as u32) * (1 << 24) + ($x[1] as u32) * (1 << 16) + ($x[2] as u32) * (1 << 8) + ($x[3] as u32)
    };
}

pub struct Packet<'a> {
    pub reply: bool, // false = request, true = reply
    pub hops: u8,
    pub xid: [u8; 4], // Random identifier
    pub secs: u16,
    pub broadcast: bool,
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub giaddr: [u8; 4],
    pub chaddr: [u8; 6],
    pub options: Vec<Option<'a>>,
}

pub struct Option<'a> {
    pub code: u8,
    pub data: &'a [u8],
}

impl<'a> Option<'a> {
    pub fn title(&'a self) -> String {
        match option_title(self.code) {
            Some(t) => t.to_string(),
            None => "Unknown (".to_string() + &self.code.to_string() + ")",
        }
    }
}

pub fn decode(p: &[u8]) -> Result<Packet, &'static str> {
    if p[236..240] != COOKIE {
        return Err("Invalid Cookie");
    }

    let reply = match p[0] {
        BOOT_REPLY => true,
        BOOT_REQUEST => false,
        _ => return Err("Invalid OpCode"),
    };
    // TODO hlen check
    let mut options = Vec::new();
    let mut i: usize = 240;
    loop {
        let l = p.len();
        if i < l {
            let code = p[i];
            if code == END {
                break;
            }
            if i + 2 < l {
                let opt_end = (p[i + 1]) as usize + i + 2;
                if opt_end < l {
                    options.push(Option {
                        code: code,
                        data: &p[i + 2..opt_end],
                    });
                    i = opt_end;
                    continue;
                }
            }
        }
        return Err("Options Problem");
    }
    Ok(Packet {
        reply: reply,
        hops: p[3],
        secs: ((p[8] as u16) << 8) + p[9] as u16,
        broadcast: p[10] & 128 == 128,
        ciaddr: [p[12], p[13], p[14], p[15]],
        yiaddr: [p[16], p[17], p[18], p[19]],
        siaddr: [p[20], p[21], p[22], p[23]],
        giaddr: [p[24], p[25], p[26], p[27]],
        options: options,
        chaddr: [p[28], p[29], p[30], p[31], p[32], p[33]],
        xid: [p[4], p[5], p[6], p[7]],
    })
}

impl<'a, 'b> Packet<'a> {
    pub fn option(&self, code: u8) -> std::option::Option<&[u8]> {
        for option in &self.options {
            if option.code == code {
                return Some(option.data);
            }
        }
        None
    }

    pub fn encode(&self, p: &mut [u8]) -> usize {
        p[..12].clone_from_slice(&[(if self.reply {
                                       BOOT_REPLY
                                   } else {
                                       BOOT_REQUEST
                                   }),
                                   1,
                                   6,
                                   self.hops,
                                   self.xid[0],
                                   self.xid[1],
                                   self.xid[2],
                                   self.xid[3],
                                   (self.secs >> 8) as u8,
                                   (self.secs & 255) as u8,
                                   (if self.broadcast {
                                       128
                                   } else {
                                       0
                                   }),
                                   0]);
        p[12..16].clone_from_slice(&self.ciaddr);
        p[16..20].clone_from_slice(&self.yiaddr);
        p[20..24].clone_from_slice(&self.siaddr);
        p[24..28].clone_from_slice(&self.giaddr);
        p[28..34].clone_from_slice(&self.chaddr);
        p[34..236].clone_from_slice(&[0; 202]);
        p[236..240].clone_from_slice(&COOKIE);

        let mut length: usize = 240;
        for option in &self.options {
            p[length] = option.code;
            p[length + 1] = option.data.len() as u8;
            p[length + 2..length + 2 + option.data.len()].clone_from_slice(option.data);
            length += 2 + option.data.len();
        }
        p[length] = END;
        length += 1;
        if length < 272 {
            // Pad to min size
            p[length..272].clone_from_slice(&[PAD; 32][..length - 240]);
            length = 272
        }
        length
    }
}

// pub fn u32_bytes(value: u32) -> [u8; 4] {
// [(value >> 24) as u8, (value >> 16) as u8, (value >> 8) as u8, value as u8]
// }
//
// pub fn bytes_u32(bytes: &[u8; 4]) -> u32 {
// (bytes[0] as u32) << 24 + (bytes[1] as u32) << 16 + (bytes[2] as u32) << 8 + (bytes[3] as u32)
// }

const COOKIE: [u8; 4] = [99, 130, 83, 99];

const BOOT_REQUEST: u8 = 1; // From Client;
const BOOT_REPLY: u8 = 2; // From Server;

const END: u8 = 255;
const PAD: u8 = 0;

// DHCP Message Type 53;
pub const DISCOVER: u8 = 1; // Broadcast Packet From Client - Can I have an IP?
pub const OFFER: u8 = 2; // Broadcast From Server - Here's an IP
pub const REQUEST: u8 = 3; // Broadcast From Client - I'll take that IP (Also start for renewals)
pub const DECLINE: u8 = 4; // Broadcast From Client - Sorry I can't use that IP
pub const ACK: u8 = 5; // From Server, Yes you can have that IP
pub const NAK: u8 = 6; // From Server, No you cannot have that IP
pub const RELEASE: u8 = 7; // From Client, I don't need that IP anymore
pub const INFORM: u8 = 8; // From Client, I have this IP and there's nothing you can do about it

// DHCP Options;
pub const OPTION_SUBNET_MASK: u8 = 1;
pub const OPTION_TIME_OFFSET: u8 = 2;
pub const OPTION_ROUTER: u8 = 3;
pub const OPTION_TIME_SERVER: u8 = 4;
pub const OPTION_NAME_SERVER: u8 = 5;
pub const OPTION_DOMAIN_NAME_SERVER: u8 = 6;
pub const OPTION_LOG_SERVER: u8 = 7;
pub const OPTION_COOKIE_SERVER: u8 = 8;
pub const OPTION_LPR_SERVER: u8 = 9;
pub const OPTION_IMPRESS_SERVER: u8 = 10;
pub const OPTION_RESOURCE_LOCATION_SERVER: u8 = 11;
pub const OPTION_HOST_NAME: u8 = 12;
pub const OPTION_BOOT_FILE_SIZE: u8 = 13;
pub const OPTION_MERIT_DUMP_FILE: u8 = 14;
pub const OPTION_DOMAIN_NAME: u8 = 15;
pub const OPTION_SWAP_SERVER: u8 = 16;
pub const OPTION_ROOT_PATH: u8 = 17;
pub const OPTION_EXTENSIONS_PATH: u8 = 18;

// IP LAYER PARAMETERS PER HOST;
pub const OPTION_IP_FORWARDING_ENABLE_DISABLE: u8 = 19;
pub const OPTION_NON_LOCAL_SOURCE_ROUTING_ENABLE_DISABLE: u8 = 20;
pub const OPTION_POLICY_FILTER: u8 = 21;
pub const OPTION_MAXIMUM_DATAGRAM_REASSEMBLY_SIZE: u8 = 22;
pub const OPTION_DEFAULT_IP_TIME_TO_LIVE: u8 = 23;
pub const OPTION_PATH_MTU_AGING_TIMEOUT: u8 = 24;
pub const OPTION_PATH_MTU_PLATEAU_TABLE: u8 = 25;

// IP LAYER PARAMETERS PER INTERFACE;
pub const OPTION_INTERFACE_MTU: u8 = 26;
pub const OPTION_ALL_SUBNETS_ARE_LOCAL: u8 = 27;
pub const OPTION_BROADCAST_ADDRESS: u8 = 28;
pub const OPTION_PERFORM_MASK_DISCOVERY: u8 = 29;
pub const OPTION_MASK_SUPPLIER: u8 = 30;
pub const OPTION_PERFORM_ROUTER_DISCOVERY: u8 = 31;
pub const OPTION_ROUTER_SOLICITATION_ADDRESS: u8 = 32;
pub const OPTION_STATIC_ROUTE: u8 = 33;

// LINK LAYER PARAMETERS PER INTERFACE;
pub const OPTION_TRAILER_ENCAPSULATION: u8 = 34;
pub const OPTION_ARP_CACHE_TIMEOUT: u8 = 35;
pub const OPTION_ETHERNET_ENCAPSULATION: u8 = 36;

// TCP PARAMETERS;
pub const OPTION_TCP_DEFAULT_TTL: u8 = 37;
pub const OPTION_TCP_KEEPALIVE_INTERVAL: u8 = 38;
pub const OPTION_TCP_KEEPALIVE_GARBAGE: u8 = 39;

// APPLICATION AND SERVICE PARAMETERS;
pub const OPTION_NETWORK_INFORMATION_SERVICE_DOMAIN: u8 = 40;
pub const OPTION_NETWORK_INFORMATION_SERVERS: u8 = 41;
pub const OPTION_NETWORK_TIME_PROTOCOL_SERVERS: u8 = 42;
pub const OPTION_VENDOR_SPECIFIC_INFORMATION: u8 = 43;
pub const OPTION_NETBIOS_OVER_TCPIP_NAME_SERVER: u8 = 44;
pub const OPTION_NETBIOS_OVER_TCPIP_DATAGRAM_DISTRIBUTION_SERVER: u8 = 45;
pub const OPTION_NETBIOS_OVER_TCPIP_NODE_TYPE: u8 = 46;
pub const OPTION_NETBIOS_OVER_TCPIP_SCOPE: u8 = 47;
pub const OPTION_XWINDOW_SYSTEM_FONT_SERVER: u8 = 48;
pub const OPTION_XWINDOW_SYSTEM_DISPLAY_MANAGER: u8 = 49;
pub const OPTION_NETWORK_INFORMATION_SERVICEPLUS_DOMAIN: u8 = 64;
pub const OPTION_NETWORK_INFORMATION_SERVICEPLUS_SERVERS: u8 = 65;
pub const OPTION_MOBILE_IP_HOME_AGENT: u8 = 68;
pub const OPTION_SIMPLE_MAIL_TRANSPORT_PROTOCOL: u8 = 69;
pub const OPTION_POST_OFFICE_PROTOCOL_SERVER: u8 = 70;
pub const OPTION_NETWORK_NEWS_TRANSPORT_PROTOCOL: u8 = 71;
pub const OPTION_DEFAULT_WORLD_WIDE_WEB_SERVER: u8 = 72;
pub const OPTION_DEFAULT_FINGER_SERVER: u8 = 73;
pub const OPTION_DEFAULT_INTERNET_RELAY_CHAT_SERVER: u8 = 74;
pub const OPTION_STREETTALK_SERVER: u8 = 75;
pub const OPTION_STREETTALK_DIRECTORY_ASSISTANCE: u8 = 76;

pub const OPTION_RELAY_AGENT_INFORMATION: u8 = 82;

// DHCP EXTENSIONS
pub const OPTION_REQUESTED_IP_ADDRESS: u8 = 50;
pub const OPTION_IP_ADDRESS_LEASE_TIME: u8 = 51;
pub const OPTION_OVERLOAD: u8 = 52;
pub const OPTION_DHCP_MESSAGE_TYPE: u8 = 53;
pub const OPTION_SERVER_IDENTIFIER: u8 = 54;
pub const OPTION_PARAMETER_REQUEST_LIST: u8 = 55;
pub const OPTION_MESSAGE: u8 = 56;
pub const OPTION_MAXIMUM_DHCP_MESSAGE_SIZE: u8 = 57;
pub const OPTION_RENEWAL_TIME_VALUE: u8 = 58;
pub const OPTION_REBINDING_TIME_VALUE: u8 = 59;
pub const OPTION_VENDOR_CLASS_IDENTIFIER: u8 = 60;
pub const OPTION_CLIENT_IDENTIFIER: u8 = 61;

pub const OPTION_TFTP_SERVER_NAME: u8 = 66;
pub const OPTION_BOOTFILE_NAME: u8 = 67;

pub const OPTION_USER_CLASS: u8 = 77;

pub const OPTION_CLIENT_ARCHITECTURE: u8 = 93;

pub const OPTION_TZ_POSIX_STRING: u8 = 100;
pub const OPTION_TZ_DATABASE_STRING: u8 = 101;

pub const OPTION_CLASSLESS_ROUTE_FORMAT: u8 = 121;

pub fn option_title(code: u8) -> std::option::Option<&'static str> {
    Some(match code {
        OPTION_SUBNET_MASK => "Subnet Mask",

        OPTION_TIME_OFFSET => "Time Offset",
        OPTION_ROUTER => "Router",
        OPTION_TIME_SERVER => "Time Server",
        OPTION_NAME_SERVER => "Name Server",
        OPTION_DOMAIN_NAME_SERVER => "Domain Name Server",
        OPTION_LOG_SERVER => "Log Server",
        OPTION_COOKIE_SERVER => "Cookie Server",
        OPTION_LPR_SERVER => "LPR Server",
        OPTION_IMPRESS_SERVER => "Impress Server",
        OPTION_RESOURCE_LOCATION_SERVER => "Resource Location Server",
        OPTION_HOST_NAME => "Host Name",
        OPTION_BOOT_FILE_SIZE => "Boot File Size",
        OPTION_MERIT_DUMP_FILE => "Merit Dump File",
        OPTION_DOMAIN_NAME => "Domain Name",
        OPTION_SWAP_SERVER => "Swap Server",
        OPTION_ROOT_PATH => "Root Path",
        OPTION_EXTENSIONS_PATH => "Extensions Path",

        // IP LAYER PARAMETERS PER HOST",
        OPTION_IP_FORWARDING_ENABLE_DISABLE => "IP Forwarding Enable/Disable",
        OPTION_NON_LOCAL_SOURCE_ROUTING_ENABLE_DISABLE => "Non-Local Source Routing Enable/Disable",
        OPTION_POLICY_FILTER => "Policy Filter",
        OPTION_MAXIMUM_DATAGRAM_REASSEMBLY_SIZE => "Maximum Datagram Reassembly Size",
        OPTION_DEFAULT_IP_TIME_TO_LIVE => "Default IP Time-to-live",
        OPTION_PATH_MTU_AGING_TIMEOUT => "Path MTU Aging Timeout",
        OPTION_PATH_MTU_PLATEAU_TABLE => "Path MTU Plateau Table",

        // IP LAYER PARAMETERS PER INTERFACE",
        OPTION_INTERFACE_MTU => "Interface MTU",
        OPTION_ALL_SUBNETS_ARE_LOCAL => "All Subnets are Local",
        OPTION_BROADCAST_ADDRESS => "Broadcast Address",
        OPTION_PERFORM_MASK_DISCOVERY => "Perform Mask Discovery",
        OPTION_MASK_SUPPLIER => "Mask Supplier",
        OPTION_PERFORM_ROUTER_DISCOVERY => "Perform Router Discovery",
        OPTION_ROUTER_SOLICITATION_ADDRESS => "Router Solicitation Address",
        OPTION_STATIC_ROUTE => "Static Route",

        // LINK LAYER PARAMETERS PER INTERFACE",
        OPTION_TRAILER_ENCAPSULATION => "Trailer Encapsulation",
        OPTION_ARP_CACHE_TIMEOUT => "ARP Cache Timeout",
        OPTION_ETHERNET_ENCAPSULATION => "Ethernet Encapsulation",

        // TCP PARAMETERS",
        OPTION_TCP_DEFAULT_TTL => "TCP Default TTL",
        OPTION_TCP_KEEPALIVE_INTERVAL => "TCP Keepalive Interval",
        OPTION_TCP_KEEPALIVE_GARBAGE => "TCP Keepalive Garbage",

        // APPLICATION AND SERVICE PARAMETERS",
        OPTION_NETWORK_INFORMATION_SERVICE_DOMAIN => "Network Information Service Domain",
        OPTION_NETWORK_INFORMATION_SERVERS => "Network Information Servers",
        OPTION_NETWORK_TIME_PROTOCOL_SERVERS => "Network Time Protocol Servers",
        OPTION_VENDOR_SPECIFIC_INFORMATION => "Vendor Specific Information",
        OPTION_NETBIOS_OVER_TCPIP_NAME_SERVER => "NetBIOS over TCP/IP Name Server",
        OPTION_NETBIOS_OVER_TCPIP_DATAGRAM_DISTRIBUTION_SERVER => {
            "NetBIOS over TCP/IP Datagram Distribution Server"
        }
        OPTION_NETBIOS_OVER_TCPIP_NODE_TYPE => "NetBIOS over TCP/IP Node Type",
        OPTION_NETBIOS_OVER_TCPIP_SCOPE => "NetBIOS over TCP/IP Scope",
        OPTION_XWINDOW_SYSTEM_FONT_SERVER => "X Window System Font Server",
        OPTION_XWINDOW_SYSTEM_DISPLAY_MANAGER => "X Window System Display Manager",
        OPTION_NETWORK_INFORMATION_SERVICEPLUS_DOMAIN => "Network Information Service+ Domain",
        OPTION_NETWORK_INFORMATION_SERVICEPLUS_SERVERS => "Network Information Service+ Servers",
        OPTION_MOBILE_IP_HOME_AGENT => "Mobile IP Home Agent",
        OPTION_SIMPLE_MAIL_TRANSPORT_PROTOCOL => "Simple Mail Transport Protocol (SMTP) Server",
        OPTION_POST_OFFICE_PROTOCOL_SERVER => "Post Office Protocol (POP3) Server",
        OPTION_NETWORK_NEWS_TRANSPORT_PROTOCOL => "Network News Transport Protocol (NNTP) Server",
        OPTION_DEFAULT_WORLD_WIDE_WEB_SERVER => "Default World Wide Web (WWW) Server",
        OPTION_DEFAULT_FINGER_SERVER => "Default Finger Server",
        OPTION_DEFAULT_INTERNET_RELAY_CHAT_SERVER => "Default Internet Relay Chat (IRC) Server",
        OPTION_STREETTALK_SERVER => "StreetTalk Server",
        OPTION_STREETTALK_DIRECTORY_ASSISTANCE => "StreetTalk Directory Assistance (STDA) Server",

        OPTION_RELAY_AGENT_INFORMATION => "Relay Agent Information",

        // DHCP EXTENSIONS
        OPTION_REQUESTED_IP_ADDRESS => "Requested IP Address",
        OPTION_IP_ADDRESS_LEASE_TIME => "IP Address Lease Time",
        OPTION_OVERLOAD => "Overload",
        OPTION_DHCP_MESSAGE_TYPE => "DHCP Message Type",
        OPTION_SERVER_IDENTIFIER => "Server Identifier",
        OPTION_PARAMETER_REQUEST_LIST => "Parameter Request List",
        OPTION_MESSAGE => "Message",
        OPTION_MAXIMUM_DHCP_MESSAGE_SIZE => "Maximum DHCP Message Size",
        OPTION_RENEWAL_TIME_VALUE => "Renewal (T1) Time Value",
        OPTION_REBINDING_TIME_VALUE => "Rebinding (T2) Time Value",
        OPTION_VENDOR_CLASS_IDENTIFIER => "Vendor class identifier",
        OPTION_CLIENT_IDENTIFIER => "Client-identifier",

        // Find below
        OPTION_TFTP_SERVER_NAME => "TFTP server name",
        OPTION_BOOTFILE_NAME => "Bootfile name",

        OPTION_USER_CLASS => "User Class",

        OPTION_CLIENT_ARCHITECTURE => "Client Architecture",

        OPTION_TZ_POSIX_STRING => "TZ-POSIX String",
        OPTION_TZ_DATABASE_STRING => "TZ-Database String",
        OPTION_CLASSLESS_ROUTE_FORMAT => "Classless Route Format",

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
