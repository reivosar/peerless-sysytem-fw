//! Browser-node transport configuration and wasm32 implementation.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BrowserBootstrap {
    pub webtransport: Vec<String>,
    pub webrtc: Vec<String>,
    pub websocket: Vec<String>,
}

impl BrowserBootstrap {
    pub fn validate(&self) -> bool {
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
            websocket: vec![]
        }
        .validate());
        assert!(BrowserBootstrap {
            webtransport: vec!["/dns/example.com/udp/443/quic-v1/webtransport".into()],
            webrtc: vec![],
            websocket: vec![]
        }
        .validate());
    }
}
