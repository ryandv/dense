use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("8.8.8.8:53").await;
    let query: &str = "\x00\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x02ca\x01\x01";
    socket.unwrap().send(query.as_bytes()).await
}
