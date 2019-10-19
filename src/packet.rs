use crate::options::*;

use std::net::Ipv4Addr;
use nom::bytes::complete::{tag, take};
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::multi::{many0, many_till};

pub enum Err<I> {
    NomError(nom::Err<(I,nom::error::ErrorKind)>),
    NonUtf8String,
    UnrecognizedMessageType,
    InvalidHlen,
}

impl<I> nom::error::ParseError<I> for Err<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Err::NomError(nom::Err::Error((input, kind)))
    }

    fn append(_input: I, _kind: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

type IResult<I, O> = nom::IResult<I, O, Err<I>>;

/// DHCP Packet Structure
pub struct Packet {
    pub reply: bool, // false = request, true = reply
    pub hops: u8,
    pub xid: u32, // Random identifier
    pub secs: u16,
    pub broadcast: bool,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 6],
    pub options: Vec<DhcpOption>,
}

fn decode_reply(input: &[u8]) -> IResult<&[u8], bool> {
    let (input, reply) = take(1u8)(input)?;
    Ok((input, match reply[0] {
        BOOT_REPLY => true,
        BOOT_REQUEST => false,
        _ => {
            // @TODO: Throw an error
            false
        }
    }))
}

fn decode_ipv4(p: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    let (input, addr) = take(4u8)(p)?;
    Ok((input, Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])))
}

pub fn decode_option(input: &[u8]) -> IResult<&[u8], DhcpOption> {
    let (input, code) = be_u8(input)?;
    assert!(code != END);

    let (input, len) = be_u8(input)?;
    let (input, data) = take(len)(input)?;
    let option = match code {
        DHCP_MESSAGE_TYPE => DhcpOption::DhcpMessageType(
            match MessageType::from(be_u8(data)?.1) {
                Ok(x) => x,
                Err(_) => return Err(nom::Err::Error(Err::UnrecognizedMessageType)),
            }
        ),
        SERVER_IDENTIFIER => DhcpOption::ServerIdentifier(
            decode_ipv4(data)?.1
        ),
        PARAMETER_REQUEST_LIST => DhcpOption::ParameterRequestList(
            data.to_vec()
        ),
        REQUESTED_IP_ADDRESS => DhcpOption::RequestedIpAddress(
            decode_ipv4(data)?.1
        ),
        HOST_NAME => DhcpOption::HostName(
            match std::str::from_utf8(data) {
                Ok(s) => s.to_string(),
                Err(_) => return Err(nom::Err::Error(Err::NonUtf8String)),
            }
        ),
        ROUTER => DhcpOption::Router(
            many0(decode_ipv4)(data)?.1
        ),
        DOMAIN_NAME_SERVER => DhcpOption::DomainNameServer(
            many0(decode_ipv4)(data)?.1
        ),
        IP_ADDRESS_LEASE_TIME => DhcpOption::IpAddressLeaseTime(
            be_u32(data)?.1
        ),
        MESSAGE => DhcpOption::Message(
            match std::str::from_utf8(data) {
                Ok(s) => s.to_string(),
                Err(_) => return Err(nom::Err::Error(Err::NonUtf8String)),
            }
        ),
        _ => DhcpOption::Unrecognized(RawDhcpOption{
            code: code,
            data: data.to_vec(),
        })
    };
    Ok((input, option))
}

/// Parses Packet from byte array
fn decode(input: &[u8]) -> IResult<&[u8], Packet> {
    let (options_input, input) = take(236u32)(input)?;

    let (input, reply) = decode_reply(input)?;
    let (input, _htype) = take(1u8)(input)?;
    let (input, hlen) = be_u8(input)?;
    let (input, hops) = be_u8(input)?;
    let (input, xid) = be_u32(input)?;
    let (input, secs) = be_u16(input)?;
    let (input, flags) = be_u16(input)?;
    let (input, ciaddr) = decode_ipv4(input)?;
    let (input, yiaddr) = decode_ipv4(input)?;
    let (input, siaddr) = decode_ipv4(input)?;
    let (input, giaddr) = decode_ipv4(input)?;

    if hlen != 6 {
        return Err(nom::Err::Error(Err::InvalidHlen));
    }
    let (_, chaddr) = take(6u8)(input)?;

    let input = options_input;
    let (input, _) = tag(COOKIE)(input)?;

    let (input, (options, _)) = many_till(decode_option, tag(&[END]))(input)?;

    Ok((input, Packet{
        reply: reply,
        hops: hops,
        secs: secs,
        broadcast: flags & 128 == 128,
        ciaddr: ciaddr,
        yiaddr: yiaddr,
        siaddr: siaddr,
        giaddr: giaddr,
        options: options,
        chaddr: [chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]],
        xid: xid,
    }))
}

impl Packet {
    pub fn from(input: &[u8]) -> Result<Packet, nom::Err<Err<&[u8]>>> {
        Ok(decode(input)?.1)
    }

    /// Extracts requested option payload from packet if available
    pub fn option<'a>(&'a self, code: u8) -> Option<&'a DhcpOption> {
        for option in &self.options {
            if option.code() == code {
                return Some(&option);
            }
        }
        None
    }

    /// Convenience function for extracting a packet's message type.
    pub fn message_type(&self) -> Result<MessageType, String> {
        match self.option(DHCP_MESSAGE_TYPE) {
            Some(DhcpOption::DhcpMessageType(msgtype)) => Ok(*msgtype),
            Some(_) => Err(format!["Got wrong enum type for DHCP_MESSAGE_TYPE"]),
            None => Err(format!["Packet does not have MessageType option"]),
        }
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
                                   ((self.xid >> 24) & 0xFF) as u8,
                                   ((self.xid >> 16) & 0xFF) as u8,
                                   ((self.xid >> 8) & 0xFF) as u8,
                                   (self.xid & 0xFF) as u8,
                                   (self.secs >> 8) as u8,
                                   (self.secs & 255) as u8,
                                   (if self.broadcast {
                                       128
                                   } else {
                                       0
                                   }),
                                   0]);
        p[12..16].clone_from_slice(&self.ciaddr.octets());
        p[16..20].clone_from_slice(&self.yiaddr.octets());
        p[20..24].clone_from_slice(&self.siaddr.octets());
        p[24..28].clone_from_slice(&self.giaddr.octets());
        p[28..34].clone_from_slice(&self.chaddr);
        p[34..236].clone_from_slice(&[0; 202]);
        p[236..240].clone_from_slice(&COOKIE);

        let mut length: usize = 240;
        for option in &self.options {
            let option = option.to_raw();
            p[length] = option.code;
            p[length + 1] = option.data.len() as u8;
            p[length + 2..length + 2 + option.data.len()].clone_from_slice(&option.data);
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
