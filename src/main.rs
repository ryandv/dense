use std::convert::TryInto;
use tokio::net::UdpSocket;

pub enum DNSOpcode {
    Query,
    InverseQuery,
    Status
}

pub enum DNSResponseCode {
    NoError,
    Format,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused
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

fn set_bit(byte: &mut u8, bitIndex: usize) {
    *byte = *byte | (1 as u8) << bitIndex
}

impl DNSQuestion {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = self
            .qname
            .split(".")
            .fold(Vec::new(), |mut bytes, label| {
                bytes.push(label.len().try_into().unwrap());
                label.as_bytes().into_iter().for_each(|byte| bytes.push(*byte));
                bytes
            });
        self.qtype.to_be_bytes().into_iter().for_each(|byte| bytes.push(*byte));
        self.qclass.to_be_bytes().into_iter().for_each(|byte| bytes.push(*byte));
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

        let mut bytes = Vec::new();
        let mut flags1: u8 = 0;
        let mut flags2: u8 = 0;

        if self.qr {
            set_bit(&mut flags1, 7);
        }

        match &self.opcode {
            DNSOpcode::Query => { },
            DNSOpcode::InverseQuery => { flags1 = flags1 | (1 as u8) << 3; }
            DNSOpcode::Status => { flags1 = flags1 | (2 as u8) << 3; }
        }

        if self.aa {
            set_bit(&mut flags1, 7);
        }

        if self.tc {
            set_bit(&mut flags1, 6);
        }

        if self.rd {
            set_bit(&mut flags1, 5);
        }

        if self.ra {
            set_bit(&mut flags1, 4);
        }

        match &self.rcode {
            DNSResponseCode::NoError => { }
            DNSResponseCode::Format => { flags2 = flags2 | (1 as u8); }
            DNSResponseCode::ServerFailure => { flags2 = flags2 | (2 as u8); }
            DNSResponseCode::NameError => { flags2 = flags2 | (3 as u8); }
            DNSResponseCode::NotImplemented => { flags2 = flags2 | (4 as u8); }
            DNSResponseCode::Refused => { flags2 = flags2 | (5 as u8); }
        }

        // ID
        bytes.push(id_bytes[0]);
        bytes.push(id_bytes[1]);
        bytes.push(flags1);
        bytes.push(flags2);
        bytes.push(qdcount_bytes[0]);
        bytes.push(qdcount_bytes[1]);
        bytes.push(ancount_bytes[0]);
        bytes.push(ancount_bytes[1]);
        bytes.push(nscount_bytes[0]);
        bytes.push(nscount_bytes[1]);
        bytes.push(arcount_bytes[0]);
        bytes.push(arcount_bytes[1]);

        return bytes;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket_result = UdpSocket::bind("0.0.0.0:10053").await;
    let mut socket = socket_result.unwrap();
    let query: &[u8] = &[
        0, 0, // ID
        1, 0, // Flags - RD
        0, 1, // QDCOUNT
        0, 0, // ANCOUNT
        0, 0, // NSCOUNT
        0, 0, // ARCOUNT

        // Question Section
        6,
        103, 111, 111, 103, 108, 101, // GOOGLE
        2,
        99, 97, // CA
        0,
        0, 1, // A
        0, 1 // IN
    ];
    let resp: &mut[u8; 512] = &mut [0; 512];
    socket.send_to(query, "8.8.8.8:53").await.unwrap();
    socket.recv(resp).await.unwrap();
    resp.into_iter().for_each(|octet| println!("{}", octet));
    Ok(())
}
