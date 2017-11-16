use num_traits::FromPrimitive;

pub struct DhcpOption<'a> {
    pub code: u8,
    pub data: &'a [u8],
}

impl<'a> DhcpOption<'a> {
    /// Returns name of DHCP Option code
    pub fn title(&'a self) -> String {
        match title(self.code) {
            Some(t) => t.to_string(),
            None => "Unknown (".to_string() + &self.code.to_string() + ")",
        }
    }
}

// DHCP Options;
pub const SUBNET_MASK: u8 = 1;
pub const TIME_OFFSET: u8 = 2;
pub const ROUTER: u8 = 3;
pub const TIME_SERVER: u8 = 4;
pub const NAME_SERVER: u8 = 5;
pub const DOMAIN_NAME_SERVER: u8 = 6;
pub const LOG_SERVER: u8 = 7;
pub const COOKIE_SERVER: u8 = 8;
pub const LPR_SERVER: u8 = 9;
pub const IMPRESS_SERVER: u8 = 10;
pub const RESOURCE_LOCATION_SERVER: u8 = 11;
pub const HOST_NAME: u8 = 12;
pub const BOOT_FILE_SIZE: u8 = 13;
pub const MERIT_DUMP_FILE: u8 = 14;
pub const DOMAIN_NAME: u8 = 15;
pub const SWAP_SERVER: u8 = 16;
pub const ROOT_PATH: u8 = 17;
pub const EXTENSIONS_PATH: u8 = 18;

// IP LAYER PARAMETERS PER HOST;
pub const IP_FORWARDING_ENABLE_DISABLE: u8 = 19;
pub const NON_LOCAL_SOURCE_ROUTING_ENABLE_DISABLE: u8 = 20;
pub const POLICY_FILTER: u8 = 21;
pub const MAXIMUM_DATAGRAM_REASSEMBLY_SIZE: u8 = 22;
pub const DEFAULT_IP_TIME_TO_LIVE: u8 = 23;
pub const PATH_MTU_AGING_TIMEOUT: u8 = 24;
pub const PATH_MTU_PLATEAU_TABLE: u8 = 25;

// IP LAYER PARAMETERS PER INTERFACE;
pub const INTERFACE_MTU: u8 = 26;
pub const ALL_SUBNETS_ARE_LOCAL: u8 = 27;
pub const BROADCAST_ADDRESS: u8 = 28;
pub const PERFORM_MASK_DISCOVERY: u8 = 29;
pub const MASK_SUPPLIER: u8 = 30;
pub const PERFORM_ROUTER_DISCOVERY: u8 = 31;
pub const ROUTER_SOLICITATION_ADDRESS: u8 = 32;
pub const STATIC_ROUTE: u8 = 33;

// LINK LAYER PARAMETERS PER INTERFACE;
pub const TRAILER_ENCAPSULATION: u8 = 34;
pub const ARP_CACHE_TIMEOUT: u8 = 35;
pub const ETHERNET_ENCAPSULATION: u8 = 36;

// TCP PARAMETERS;
pub const TCP_DEFAULT_TTL: u8 = 37;
pub const TCP_KEEPALIVE_INTERVAL: u8 = 38;
pub const TCP_KEEPALIVE_GARBAGE: u8 = 39;

// APPLICATION AND SERVICE PARAMETERS;
pub const NETWORK_INFORMATION_SERVICE_DOMAIN: u8 = 40;
pub const NETWORK_INFORMATION_SERVERS: u8 = 41;
pub const NETWORK_TIME_PROTOCOL_SERVERS: u8 = 42;
pub const VENDOR_SPECIFIC_INFORMATION: u8 = 43;
pub const NETBIOS_OVER_TCPIP_NAME_SERVER: u8 = 44;
pub const NETBIOS_OVER_TCPIP_DATAGRAM_DISTRIBUTION_SERVER: u8 = 45;
pub const NETBIOS_OVER_TCPIP_NODE_TYPE: u8 = 46;
pub const NETBIOS_OVER_TCPIP_SCOPE: u8 = 47;
pub const XWINDOW_SYSTEM_FONT_SERVER: u8 = 48;
pub const XWINDOW_SYSTEM_DISPLAY_MANAGER: u8 = 49;
pub const NETWORK_INFORMATION_SERVICEPLUS_DOMAIN: u8 = 64;
pub const NETWORK_INFORMATION_SERVICEPLUS_SERVERS: u8 = 65;
pub const MOBILE_IP_HOME_AGENT: u8 = 68;
pub const SIMPLE_MAIL_TRANSPORT_PROTOCOL: u8 = 69;
pub const POST_OFFICE_PROTOCOL_SERVER: u8 = 70;
pub const NETWORK_NEWS_TRANSPORT_PROTOCOL: u8 = 71;
pub const DEFAULT_WORLD_WIDE_WEB_SERVER: u8 = 72;
pub const DEFAULT_FINGER_SERVER: u8 = 73;
pub const DEFAULT_INTERNET_RELAY_CHAT_SERVER: u8 = 74;
pub const STREETTALK_SERVER: u8 = 75;
pub const STREETTALK_DIRECTORY_ASSISTANCE: u8 = 76;

pub const RELAY_AGENT_INFORMATION: u8 = 82;

// DHCP EXTENSIONS
pub const REQUESTED_IP_ADDRESS: u8 = 50;
pub const IP_ADDRESS_LEASE_TIME: u8 = 51;
pub const OVERLOAD: u8 = 52;
pub const DHCP_MESSAGE_TYPE: u8 = 53;
pub const SERVER_IDENTIFIER: u8 = 54;
pub const PARAMETER_REQUEST_LIST: u8 = 55;
pub const MESSAGE: u8 = 56;
pub const MAXIMUM_DHCP_MESSAGE_SIZE: u8 = 57;
pub const RENEWAL_TIME_VALUE: u8 = 58;
pub const REBINDING_TIME_VALUE: u8 = 59;
pub const VENDOR_CLASS_IDENTIFIER: u8 = 60;
pub const CLIENT_IDENTIFIER: u8 = 61;

pub const TFTP_SERVER_NAME: u8 = 66;
pub const BOOTFILE_NAME: u8 = 67;

pub const USER_CLASS: u8 = 77;

pub const CLIENT_ARCHITECTURE: u8 = 93;

pub const TZ_POSIX_STRING: u8 = 100;
pub const TZ_DATABASE_STRING: u8 = 101;

pub const CLASSLESS_ROUTE_FORMAT: u8 = 121;

/// Returns title of DHCP Option code, if known.
pub fn title(code: u8) -> Option<&'static str> {
    Some(match code {
        SUBNET_MASK => "Subnet Mask",

        TIME_OFFSET => "Time Offset",
        ROUTER => "Router",
        TIME_SERVER => "Time Server",
        NAME_SERVER => "Name Server",
        DOMAIN_NAME_SERVER => "Domain Name Server",
        LOG_SERVER => "Log Server",
        COOKIE_SERVER => "Cookie Server",
        LPR_SERVER => "LPR Server",
        IMPRESS_SERVER => "Impress Server",
        RESOURCE_LOCATION_SERVER => "Resource Location Server",
        HOST_NAME => "Host Name",
        BOOT_FILE_SIZE => "Boot File Size",
        MERIT_DUMP_FILE => "Merit Dump File",
        DOMAIN_NAME => "Domain Name",
        SWAP_SERVER => "Swap Server",
        ROOT_PATH => "Root Path",
        EXTENSIONS_PATH => "Extensions Path",

        // IP LAYER PARAMETERS PER HOST",
        IP_FORWARDING_ENABLE_DISABLE => "IP Forwarding Enable/Disable",
        NON_LOCAL_SOURCE_ROUTING_ENABLE_DISABLE => "Non-Local Source Routing Enable/Disable",
        POLICY_FILTER => "Policy Filter",
        MAXIMUM_DATAGRAM_REASSEMBLY_SIZE => "Maximum Datagram Reassembly Size",
        DEFAULT_IP_TIME_TO_LIVE => "Default IP Time-to-live",
        PATH_MTU_AGING_TIMEOUT => "Path MTU Aging Timeout",
        PATH_MTU_PLATEAU_TABLE => "Path MTU Plateau Table",

        // IP LAYER PARAMETERS PER INTERFACE",
        INTERFACE_MTU => "Interface MTU",
        ALL_SUBNETS_ARE_LOCAL => "All Subnets are Local",
        BROADCAST_ADDRESS => "Broadcast Address",
        PERFORM_MASK_DISCOVERY => "Perform Mask Discovery",
        MASK_SUPPLIER => "Mask Supplier",
        PERFORM_ROUTER_DISCOVERY => "Perform Router Discovery",
        ROUTER_SOLICITATION_ADDRESS => "Router Solicitation Address",
        STATIC_ROUTE => "Static Route",

        // LINK LAYER PARAMETERS PER INTERFACE",
        TRAILER_ENCAPSULATION => "Trailer Encapsulation",
        ARP_CACHE_TIMEOUT => "ARP Cache Timeout",
        ETHERNET_ENCAPSULATION => "Ethernet Encapsulation",

        // TCP PARAMETERS",
        TCP_DEFAULT_TTL => "TCP Default TTL",
        TCP_KEEPALIVE_INTERVAL => "TCP Keepalive Interval",
        TCP_KEEPALIVE_GARBAGE => "TCP Keepalive Garbage",

        // APPLICATION AND SERVICE PARAMETERS",
        NETWORK_INFORMATION_SERVICE_DOMAIN => "Network Information Service Domain",
        NETWORK_INFORMATION_SERVERS => "Network Information Servers",
        NETWORK_TIME_PROTOCOL_SERVERS => "Network Time Protocol Servers",
        VENDOR_SPECIFIC_INFORMATION => "Vendor Specific Information",
        NETBIOS_OVER_TCPIP_NAME_SERVER => "NetBIOS over TCP/IP Name Server",
        NETBIOS_OVER_TCPIP_DATAGRAM_DISTRIBUTION_SERVER => {
            "NetBIOS over TCP/IP Datagram Distribution Server"
        }
        NETBIOS_OVER_TCPIP_NODE_TYPE => "NetBIOS over TCP/IP Node Type",
        NETBIOS_OVER_TCPIP_SCOPE => "NetBIOS over TCP/IP Scope",
        XWINDOW_SYSTEM_FONT_SERVER => "X Window System Font Server",
        XWINDOW_SYSTEM_DISPLAY_MANAGER => "X Window System Display Manager",
        NETWORK_INFORMATION_SERVICEPLUS_DOMAIN => "Network Information Service+ Domain",
        NETWORK_INFORMATION_SERVICEPLUS_SERVERS => "Network Information Service+ Servers",
        MOBILE_IP_HOME_AGENT => "Mobile IP Home Agent",
        SIMPLE_MAIL_TRANSPORT_PROTOCOL => "Simple Mail Transport Protocol (SMTP) Server",
        POST_OFFICE_PROTOCOL_SERVER => "Post Office Protocol (POP3) Server",
        NETWORK_NEWS_TRANSPORT_PROTOCOL => "Network News Transport Protocol (NNTP) Server",
        DEFAULT_WORLD_WIDE_WEB_SERVER => "Default World Wide Web (WWW) Server",
        DEFAULT_FINGER_SERVER => "Default Finger Server",
        DEFAULT_INTERNET_RELAY_CHAT_SERVER => "Default Internet Relay Chat (IRC) Server",
        STREETTALK_SERVER => "StreetTalk Server",
        STREETTALK_DIRECTORY_ASSISTANCE => "StreetTalk Directory Assistance (STDA) Server",

        RELAY_AGENT_INFORMATION => "Relay Agent Information",

        // DHCP EXTENSIONS
        REQUESTED_IP_ADDRESS => "Requested IP Address",
        IP_ADDRESS_LEASE_TIME => "IP Address Lease Time",
        OVERLOAD => "Overload",
        DHCP_MESSAGE_TYPE => "DHCP Message Type",
        SERVER_IDENTIFIER => "Server Identifier",
        PARAMETER_REQUEST_LIST => "Parameter Request List",
        MESSAGE => "Message",
        MAXIMUM_DHCP_MESSAGE_SIZE => "Maximum DHCP Message Size",
        RENEWAL_TIME_VALUE => "Renewal (T1) Time Value",
        REBINDING_TIME_VALUE => "Rebinding (T2) Time Value",
        VENDOR_CLASS_IDENTIFIER => "Vendor class identifier",
        CLIENT_IDENTIFIER => "Client-identifier",

        // Find below
        TFTP_SERVER_NAME => "TFTP server name",
        BOOTFILE_NAME => "Bootfile name",

        USER_CLASS => "User Class",

        CLIENT_ARCHITECTURE => "Client Architecture",

        TZ_POSIX_STRING => "TZ-POSIX String",
        TZ_DATABASE_STRING => "TZ-Database String",
        CLASSLESS_ROUTE_FORMAT => "Classless Route Format",

        _ => return None,
    })
}

///
/// DHCP Message Type (option code 53)
///
#[derive(Primitive)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl MessageType {
    pub fn from(val: u8) -> Result<MessageType, String> {
        MessageType::from_u8(val).ok_or_else(|| format!["Invalid DHCP Message Type: {:?}", val])
    }
}
