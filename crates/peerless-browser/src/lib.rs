//! Browser-node transport configuration and wasm32 implementation.

use libp2p::{multiaddr::Protocol, Multiaddr};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BrowserBootstrap {
    pub webtransport: Vec<String>,
    pub webrtc: Vec<String>,
    pub websocket: Vec<String>,
    #[serde(default)]
    pub relay_only: bool,
}

impl BrowserBootstrap {
    pub fn validate(&self) -> bool {
        let all_valid = self
            .webtransport
            .iter()
            .chain(&self.webrtc)
            .chain(&self.websocket)
            .all(|value| value.parse::<Multiaddr>().is_ok());
        if !all_valid {
            return false;
        }
        if self.relay_only {
            return self.webtransport.is_empty()
                && self.webrtc.is_empty()
                && !self.websocket.is_empty()
                && self.websocket.iter().all(|value| {
                    value.parse::<Multiaddr>().is_ok_and(|address| {
                        address
                            .iter()
                            .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
                    })
                });
        }
        !self.webtransport.is_empty() || !self.webrtc.is_empty() || !self.websocket.is_empty()
    }
}

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_requires_at_least_one_supported_bootstrap_transport() {
        assert!(!BrowserBootstrap {
            webtransport: vec![],
            webrtc: vec![],
            websocket: vec![],
            relay_only: false
        }
        .validate());
        assert!(BrowserBootstrap {
            webtransport: vec!["/dns/example.com/udp/443/quic-v1/webtransport".into()],
            webrtc: vec![],
            websocket: vec![],
            relay_only: false
        }
        .validate());
    }

    #[test]
    fn relay_only_browser_bootstrap_rejects_direct_transports() {
        let circuit = "/dns4/relay.example/tcp/443/wss/p2p-circuit";
        assert!(BrowserBootstrap {
            webtransport: vec![],
            webrtc: vec![],
            websocket: vec![circuit.into()],
            relay_only: true,
        }
        .validate());
        assert!(!BrowserBootstrap {
            webtransport: vec![],
            webrtc: vec!["/dns4/direct.example/udp/443/webrtc-direct".into()],
            websocket: vec![],
            relay_only: true,
        }
        .validate());
    }
}
