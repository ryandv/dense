use docopt::Docopt;
use serde::Deserialize;
use std::convert::TryInto;
use std::marker::Copy;
use std::str;
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


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DNSOpcode {
    Query = 0,
    InverseQuery = 1,
    Status = 2
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DNSResponseCode {
    NoError = 0,
    Format = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5
}

#[derive(Debug)]
pub struct DNSQuestion {
    qname: String,
    qtype: u16,
    qclass: u16
}

#[derive(Debug)]
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

/*
pub struct DNSResourceRecord {
    name: String,
    rrtype: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>
}
*/

fn set_bit(byte: &mut u8, bit_index: usize, value: bool) {
    *byte = *byte | (value as u8) << bit_index
}

impl DNSQuestion {
    pub fn from_slice<'a>(qdcount: u16, question_section: &'a[u8]) -> Vec<DNSQuestion> {
        let mut questions = vec![];
        let mut qbytes = question_section;

        for _ in 0..qdcount {
            let empty: &[u8] = &[0; 0];
            let mut qname = String::from("");

            loop {
                let (length, octets, rest) = qbytes
                    .first()
                    .map_or((0, empty, empty), |len| {
                        let length = usize::from(*len);
                        let (octets, rest) = &qbytes.split_at(usize::from(length + 1));

                        (length, octets, rest)
                    });

                if length == 0 {
                    questions.push(DNSQuestion {
                        qname: qname,
                        qtype: u16::from_be_bytes([rest[0], rest[1]]),
                        qclass: u16::from_be_bytes([rest[2], rest[3]])
                    });

                    let (_, next_qbytes) = &rest.split_at(4);
                    qbytes = next_qbytes;

                    break;
                }

                let label = str::from_utf8(&octets[1..length + 1]).unwrap();
                qname.push_str(label);
                qname.push('.');

                let (_, next_qbytes) = qbytes.split_at(length + 1);
                qbytes = next_qbytes;
            }
        }

        questions
    }

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
    pub fn from_slice<'a>(header: &'a[u8]) -> DNSMessage {
        let resp_id = u16::from_be_bytes([header[0], header[1]]);
        let resp_flags_hi = header[2];
        let resp_flags_lo = header[3];
        let resp_qdcount = u16::from_be_bytes([header[4], header[5]]);
        let resp_ancount = u16::from_be_bytes([header[6], header[7]]);
        let resp_nscount = u16::from_be_bytes([header[8], header[9]]);
        let resp_arcount = u16::from_be_bytes([header[10], header[11]]);

        let resp_qr = resp_flags_hi & 0b10000000 == 0b10000000;
        let resp_opcode = match resp_flags_hi & 0b01110000 {
            0 => DNSOpcode::Query,
            1 => DNSOpcode::InverseQuery,
            2 => DNSOpcode::Status,
            opcode @ _ => panic!("Got unsupported opcode: {}", opcode)
        };
        let resp_aa = resp_flags_hi & 0b00000100 == 0b00000100;
        let resp_tc = resp_flags_hi & 0b00000010 == 0b00000010;
        let resp_rd = resp_flags_hi & 0b00000001 == 0b00000001;
        let resp_ra = resp_flags_lo & 0b10000000 == 0b10000000;

        let resp_rcode = match resp_flags_lo & 0b00001111 {
            0 => DNSResponseCode::NoError,
            1 => DNSResponseCode::Format,
            2 => DNSResponseCode::ServerFailure,
            3 => DNSResponseCode::NameError,
            4 => DNSResponseCode::NotImplemented,
            5 => DNSResponseCode::Refused,
            rcode @ _ => panic!("Got unsupported rcode: {}", rcode)
        };

        DNSMessage {
            id: resp_id,
            qr: resp_qr,
            opcode: resp_opcode,
            aa: resp_aa,
            tc: resp_tc,
            rd: resp_rd,
            ra: resp_ra,
            qdcount: resp_qdcount,
            ancount: resp_ancount,
            nscount: resp_nscount,
            arcount: resp_arcount,
            rcode: resp_rcode,
            questions: vec![]
        }
    }

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

async fn send_message<'a, 'b>(buf: &'a mut [u8; 512], socket: &'b mut UdpSocket, message: &DNSMessage) -> Result<(), Box<dyn std::error::Error>> {
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
        qdcount: 2,
        ancount: 0,
        nscount: 0,
        arcount: 0,
        rcode: DNSResponseCode::NoError,
        questions: vec![DNSQuestion {
            qname: args.arg_hostname,
            qtype: 1,
            qclass: 1
        }, DNSQuestion {
            qname: String::from("example.com"),
            qtype: 1,
            qclass: 1
        }]
    };

    send_message(buf, &mut socket, &query).await.unwrap();

    let (header, rest) = buf.split_at(12);

    let mut response = DNSMessage::from_slice(header);
    response.questions = DNSQuestion::from_slice(query.qdcount, rest);

    println!("{:?}", response);

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

    #[test]
    fn unmarshals_dnsmessage_headers_from_packet() {
        let inbound_packet: &[u8] = &[
            0x00,0x01,0x81,0x80,
            0x00,0x01,0x00,0x01,
            0x00,0x00,0x00,0x00,
            0x06,0x67,0x6f,0x6f,
            0x67,0x6c,0x65,0x02,
            0x63,0x61,0x00,0x00,
            0x01,0x00,0x01,0xc0,
            0x0c,0x00,0x01,0x00,
            0x01,0x00,0x00,0x00,
            0x4f,0x00,0x04,0xac,
            0xd9,0xa4,0xc3
        ];

        let msg = DNSMessage::from_slice(inbound_packet);

        assert!(msg.id == 1);
        assert!(msg.qr);
        assert!(msg.opcode == DNSOpcode::Query);
        assert!(!msg.aa);
        assert!(!msg.tc);
        assert!(msg.rd);
        assert!(msg.ra);
        assert!(msg.qdcount == 1);
        assert!(msg.ancount == 1);
        assert!(msg.nscount == 0);
        assert!(msg.arcount == 0);
        assert!(msg.rcode == DNSResponseCode::NoError);
    }

    #[test]
    fn unmarshals_dnsquestions_from_packet() {
        let inbound_packet: &[u8] = &[
            0x06,0x67,0x6f,0x6f,
            0x67,0x6c,0x65,0x02,
            0x63,0x61,0x00,0x00,
            0x01,0x00,0x01,0x07,
            0x65,0x78,0x61,0x6d,
            0x70,0x6c,0x65,0x03,
            0x63,0x6f,0x6d,0x00,
            0x00,0x01,0x00,0x01
        ];

        let questions = DNSQuestion::from_slice(2, inbound_packet);

        assert!(questions.first().unwrap().qname == String::from("google.ca."));
        assert!(questions.first().unwrap().qtype == 1);
        assert!(questions.first().unwrap().qclass == 1);

        println!("{:?}", questions[1]);
        assert!(questions[1].qname == String::from("example.com."));
        assert!(questions[1].qtype == 1);
        assert!(questions[1].qclass == 1);
    }
}
