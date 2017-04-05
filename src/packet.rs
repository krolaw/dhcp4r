use std;

use options::*;

/// DHCP Packet Structure
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

/// Parses Packet from byte array
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

impl<'a> Packet<'a> {
    /// Extracts requested option payload from packet if available
    pub fn option(&self, code: u8) -> std::option::Option<&'a [u8]> {
        for option in &self.options {
            if option.code == code {
                return Some(&option.data);
            }
        }
        None
    }

    /// Convenience function for extracting a packet's message type.
    pub fn message_type(&self) -> u8 {
        if let Some(x) = self.option(DHCP_MESSAGE_TYPE) {
            if x.len() > 0 {
                return x[0];
            }
        }
        0
    }

    /// Creates byte array DHCP packet
    pub fn encode<'c>(&'c self, p: &'c mut [u8]) -> &[u8] {
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
            p[length..272].clone_from_slice(&[PAD; 32][..272 - length]);
            length = 272
        }
        &p[..length]
    }
}

const COOKIE: [u8; 4] = [99, 130, 83, 99];

const BOOT_REQUEST: u8 = 1; // From Client;
const BOOT_REPLY: u8 = 2; // From Server;

const END: u8 = 255;
const PAD: u8 = 0;
