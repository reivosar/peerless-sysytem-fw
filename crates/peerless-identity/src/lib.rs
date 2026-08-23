//! Persistent Ed25519 identity shared by message signing and libp2p.

use libp2p::identity::{Keypair, PublicKey};
use peerless_core::NodeId;
use std::{fs, io, path::Path};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid identity key: {0}")]
    InvalidKey(String),
}

pub struct NodeIdentity {
    node_id: NodeId,
    keypair: Keypair,
    public_key: Vec<u8>,
}

impl NodeIdentity {
    pub fn load_or_generate(directory: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory)?;
        let key_path = directory.join("key.protobuf");
        let keypair = if key_path.exists() {
            let bytes = fs::read(&key_path)?;
            Keypair::from_protobuf_encoding(&bytes)
                .map_err(|error| IdentityError::InvalidKey(error.to_string()))?
        } else {
            let keypair = Keypair::generate_ed25519();
            let encoded = keypair
                .to_protobuf_encoding()
                .map_err(|error| IdentityError::InvalidKey(error.to_string()))?;
            let temporary = directory.join(".key.protobuf.tmp");
            fs::write(&temporary, encoded)?;
            fs::rename(temporary, &key_path)?;
            keypair
        };
        let public_key = keypair.public().encode_protobuf();
        Ok(Self {
            node_id: NodeId::derive(&public_key),
            keypair,
            public_key,
        })
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key
    }
    pub fn keypair(&self) -> Keypair {
        self.keypair.clone()
    }
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, IdentityError> {
        self.keypair
            .sign(message)
            .map_err(|error| IdentityError::InvalidKey(error.to_string()))
    }
}

pub fn verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    _temporary_directory: impl AsRef<Path>,
) -> Result<bool, IdentityError> {
    let public = PublicKey::try_decode_protobuf(public_key)
        .map_err(|error| IdentityError::InvalidKey(error.to_string()))?;
    Ok(public.verify(message, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_persists_and_signatures_verify() {
        let directory = tempfile::tempdir().unwrap();
        let first = NodeIdentity::load_or_generate(directory.path()).unwrap();
        let signature = first.sign(b"authentic").unwrap();
        assert!(verify(
            first.public_key_der(),
            b"authentic",
            &signature,
            directory.path()
        )
        .unwrap());
        assert!(!verify(
            first.public_key_der(),
            b"tampered",
            &signature,
            directory.path()
        )
        .unwrap());
        let second = NodeIdentity::load_or_generate(directory.path()).unwrap();
        assert_eq!(first.node_id(), second.node_id());
        assert_eq!(
            first.keypair().public().to_peer_id(),
            second.keypair().public().to_peer_id()
        );
    }
}
