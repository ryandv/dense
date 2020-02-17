use docopt::Docopt;
use serde::Deserialize;
use std::convert::TryInto;
use std::marker::Copy;
use std::io::{stdout, Write};
use tokio::net::UdpSocket;

const USAGE: &'static str = "
Dense - A Rust DNS Client.

Usage:
  dense <hostname>

Options:
";

#[derive(Debug, Deserialize)]
struct Args {
    arg_hostname: String
}


#[derive(Clone, Copy)]
pub enum DNSOpcode {
    Query = 0,
    InverseQuery = 1,
    Status = 2
}

#[derive(Clone, Copy)]
pub enum DNSResponseCode {
    NoError = 0,
    Format = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5
}

pub struct DNSQuestion {
    qname: String,
    qtype: u16,
    qclass: u16
}

pub struct DNSMessage {
    id: u16,
    qr: bool,
    opcode: DNSOpcode,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
    rcode: DNSResponseCode,
    questions: Vec<DNSQuestion>
}

fn set_bit(byte: &mut u8, bit_index: usize, value: bool) {
    *byte = *byte | (value as u8) << bit_index
}

impl DNSQuestion {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = self
            .qname
            .split(".")
            .fold(Vec::new(), |mut bytes, label| {
                bytes.push(label.len().try_into().unwrap());
                label.as_bytes().iter().for_each(|byte| bytes.push(*byte));
                bytes
            });
        bytes.push(0);

        self.qtype.to_be_bytes().iter().for_each(|byte| bytes.push(*byte));
        self.qclass.to_be_bytes().iter().for_each(|byte| bytes.push(*byte));
        bytes
    }
}

impl DNSMessage {
    pub fn as_bytes(&self) -> Vec<u8> {
        let id_bytes = self.id.to_be_bytes();
        let qdcount_bytes = self.qdcount.to_be_bytes();
        let ancount_bytes = self.ancount.to_be_bytes();
        let nscount_bytes = self.nscount.to_be_bytes();
        let arcount_bytes = self.arcount.to_be_bytes();
        let mut flags_hi: u8 = 0;
        let mut flags_lo: u8 = 0;

        let mut bytes = Vec::new();

        set_bit(&mut flags_hi, 7, self.qr);
        set_bit(&mut flags_hi, 2, self.aa);
        set_bit(&mut flags_hi, 1, self.tc);
        set_bit(&mut flags_hi, 0, self.rd);
        flags_hi = flags_hi | (self.opcode as u8) << 3;

        set_bit(&mut flags_lo, 7, self.ra);
        flags_lo = flags_lo | (self.rcode as u8);

        bytes.extend_from_slice(&[
            id_bytes[0],
            id_bytes[1],
            flags_hi,
            flags_lo,
            qdcount_bytes[0],
            qdcount_bytes[1],
            ancount_bytes[0],
            ancount_bytes[1],
            nscount_bytes[0],
            nscount_bytes[1],
            arcount_bytes[0],
            arcount_bytes[1],
        ]);

        let mut question_section = (&self
                .questions)
                .iter()
                .fold(Vec::new(), |mut acc, question| {
                    let mut question_bytes = question.as_bytes();
                    acc.append(&mut question_bytes);
                    acc
                });
        bytes.append(&mut question_section);

        bytes
    }
}

async fn send_message<'a, 'b>(buf: &'a mut [u8; 512], socket: &'b mut UdpSocket, message: DNSMessage) -> Result<(), Box<dyn std::error::Error>> {
    socket.send_to(message.as_bytes().as_slice(), "8.8.8.8:53").await.unwrap();
    socket.recv(buf).await.unwrap();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let socket_result = UdpSocket::bind("0.0.0.0:10053").await;
    let mut socket = socket_result.unwrap();
    let buf: &mut[u8; 512] = &mut [0; 512];

    let query = DNSMessage {
        id: 1,
        qr: false,
        opcode: DNSOpcode::Query,
        aa: false,
        tc: false,
        rd: true,
        ra: false,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
        rcode: DNSResponseCode::NoError,
        questions: vec![DNSQuestion {
            qname: args.arg_hostname,
            qtype: 1,
            qclass: 1
        }]
    };

    send_message(buf, &mut socket, query).await.unwrap();

    let stdout = stdout();
    let mut handle = stdout.lock();
    handle.write_all(buf).unwrap();

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn constructs_a_well_formed_packet_from_a_dnsmessage() {
        let query = DNSMessage {
            id: 0,
            qr: false,
            opcode: DNSOpcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            rcode: DNSResponseCode::NoError,
            questions: vec![DNSQuestion {
                qname: String::from("google.ca"),
                qtype: 1,
                qclass: 1
            }]
        };

        let dns_packet = query.as_bytes();

        let expected_packet: &[u8] = &[
            0x00, 0x00, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x06, 0x67, 0x6f, 0x6f,
            0x67, 0x6c, 0x65, 0x02,
            0x63, 0x61, 0x00, 0x00,
            0x01, 0x00, 0x01
        ];

        assert!(dns_packet.as_slice() == expected_packet)
    }
}
