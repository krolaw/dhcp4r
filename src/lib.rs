pub mod options;
pub mod packet;
pub mod server;

/// Converts a u32 to 4 bytes (Big endian)
#[macro_export]
macro_rules! u32_bytes {
    ( $x:expr ) => {
        [($x >> 24) as u8, ($x >> 16) as u8, ($x >> 8) as u8, $x as u8]
    };
}

/// Converts 4 bytes to a u32 (Big endian)
#[macro_export]
macro_rules! bytes_u32 {
    ( $x:expr ) => {
        ($x[0] as u32) * (1 << 24) + ($x[1] as u32) * (1 << 16) + ($x[2] as u32) * (1 << 8) + ($x[3] as u32)
    };
}

// DHCP Message Type 53;
pub const DISCOVER: u8 = 1; // Broadcast Packet From Client - Can I have an IP?
pub const OFFER: u8 = 2; // Broadcast From Server - Here's an IP
pub const REQUEST: u8 = 3; // Broadcast From Client - I'll take that IP (Also start for renewals)
pub const DECLINE: u8 = 4; // Broadcast From Client - Sorry I can't use that IP
pub const ACK: u8 = 5; // From Server, Yes you can have that IP
pub const NAK: u8 = 6; // From Server, No you cannot have that IP
pub const RELEASE: u8 = 7; // From Client, I don't need that IP anymore
pub const INFORM: u8 = 8; // From Client, I'd like some other information


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
