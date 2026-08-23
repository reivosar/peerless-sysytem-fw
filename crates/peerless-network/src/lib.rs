//! Length-delimited peer RPC transport. QUIC can replace it without changing messages.

use peerless_protocol::SignedEnvelope;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket},
    sync::Arc,
    thread,
    time::Duration,
};
use thiserror::Error;

pub mod p2p;

const MAX_FRAME: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("network I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid wire frame: {0}")]
    Json(#[from] serde_json::Error),
    #[error("wire frame exceeds the 64 MiB limit")]
    FrameTooLarge,
}

pub fn request(
    address: SocketAddr,
    envelope: &SignedEnvelope,
) -> Result<SignedEnvelope, NetworkError> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    write_frame(&mut stream, envelope)?;
    read_frame(&mut stream)
}

pub struct RpcServer {
    address: SocketAddr,
}
impl RpcServer {
    pub fn start_on(
        bind: SocketAddr,
        handler: impl Fn(SignedEnvelope) -> SignedEnvelope + Send + Sync + 'static,
    ) -> Result<Self, NetworkError> {
        let listener = TcpListener::bind(bind)?;
        let address = listener.local_addr()?;
        let handler = Arc::new(handler);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let handler = Arc::clone(&handler);
                thread::spawn(move || {
                    if let Ok(message) = read_frame(&mut stream) {
                        let _ = write_frame(&mut stream, &handler(message));
                    }
                });
            }
        });
        Ok(Self { address })
    }

    pub fn start(
        handler: impl Fn(SignedEnvelope) -> SignedEnvelope + Send + Sync + 'static,
    ) -> Result<Self, NetworkError> {
        Self::start_on(SocketAddr::from(([127, 0, 0, 1], 0)), handler)
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

pub const DISCOVERY_PORT: u16 = 45_781;
pub const DISCOVERY_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 71, 81);

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PeerAnnouncement {
    pub node: String,
    pub address: SocketAddr,
    pub expires_at: u64,
}

pub struct LanDiscovery {
    socket: UdpSocket,
}

impl LanDiscovery {
    pub fn bind() -> Result<Self, NetworkError> {
        let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        raw.set_reuse_address(true)?;
        #[cfg(unix)]
        raw.set_reuse_port(true)?;
        raw.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT).into())?;
        let socket: UdpSocket = raw.into();
        socket.join_multicast_v4(&DISCOVERY_GROUP, &Ipv4Addr::UNSPECIFIED)?;
        socket.set_multicast_loop_v4(true)?;
        Ok(Self { socket })
    }

    pub fn announce(&self, announcement: &PeerAnnouncement) -> Result<(), NetworkError> {
        let bytes = serde_json::to_vec(announcement)?;
        self.socket
            .send_to(&bytes, SocketAddrV4::new(DISCOVERY_GROUP, DISCOVERY_PORT))?;
        Ok(())
    }

    pub fn receive(&self, timeout: Duration) -> Result<PeerAnnouncement, NetworkError> {
        self.socket.set_read_timeout(Some(timeout))?;
        let mut bytes = [0; 2048];
        let (size, _) = self.socket.recv_from(&mut bytes)?;
        Ok(serde_json::from_slice(&bytes[..size])?)
    }
}

fn write_frame(stream: &mut impl Write, envelope: &SignedEnvelope) -> Result<(), NetworkError> {
    let bytes = serde_json::to_vec(envelope)?;
    if bytes.len() > MAX_FRAME {
        return Err(NetworkError::FrameTooLarge);
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}
fn read_frame(stream: &mut impl Read) -> Result<SignedEnvelope, NetworkError> {
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size > MAX_FRAME {
        return Err(NetworkError::FrameTooLarge);
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_round_trips_without_network_access() {
        let envelope = SignedEnvelope {
            version: 1,
            signer: peerless_core::NodeId::from_public_key_bytes(vec![1]),
            public_key: vec![],
            payload: b"hello".to_vec(),
            signature: vec![],
        };
        let mut frame = Vec::new();
        write_frame(&mut frame, &envelope).unwrap();
        assert_eq!(read_frame(&mut frame.as_slice()).unwrap().payload, b"hello");
    }

    #[test]
    fn announcement_wire_format_round_trips() {
        let value = PeerAnnouncement {
            node: "node-a".into(),
            address: "127.0.0.1:9010".parse().unwrap(),
            expires_at: 42,
        };
        assert_eq!(
            serde_json::from_slice::<PeerAnnouncement>(&serde_json::to_vec(&value).unwrap())
                .unwrap(),
            value
        );
    }
}
