//! wasm32 transport assembly lives here so native nodes never pull browser APIs.

use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade, Transport},
    identity::Keypair,
    noise, yamux, Multiaddr, PeerId,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct BrowserIdentity {
    keypair: Keypair,
}

#[wasm_bindgen]
impl BrowserIdentity {
    #[wasm_bindgen(constructor)]
    pub fn generate() -> Self {
        Self {
            keypair: Keypair::generate_ed25519(),
        }
    }
    pub fn peer_id(&self) -> String {
        self.keypair.public().to_peer_id().to_string()
    }
    pub fn validate_address(&self, address: &str) -> bool {
        address.parse::<Multiaddr>().is_ok()
    }
}

pub fn peer_id(identity: &BrowserIdentity) -> PeerId {
    identity.keypair.public().to_peer_id()
}

pub fn webtransport(keypair: &Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    libp2p::webtransport_websys::Transport::new(libp2p::webtransport_websys::Config::new(keypair))
        .boxed()
}

pub fn webrtc(keypair: &Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    libp2p::webrtc_websys::Transport::new(libp2p::webrtc_websys::Config::new(keypair)).boxed()
}

pub fn websocket(keypair: &Keypair) -> Result<Boxed<(PeerId, StreamMuxerBox)>, String> {
    let noise = noise::Config::new(keypair).map_err(|error| error.to_string())?;
    Ok(libp2p::websocket_websys::Transport::default()
        .upgrade(upgrade::Version::V1)
        .authenticate(noise)
        .multiplex(yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed())
}
