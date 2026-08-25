//! Persistent Ed25519 identity shared by message signing and libp2p.

use libp2p::identity::{Keypair, PublicKey};
use peerless_core::NodeId;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
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
        let directory_metadata = fs::symlink_metadata(directory)?;
        if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
            return Err(IdentityError::InvalidKey(
                "identity directory must be a real directory".into(),
            ));
        }
        #[cfg(unix)]
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        let key_path = directory.join("key.protobuf");
        let keypair = if key_path.exists() {
            secure_key_metadata(&key_path)?;
            let bytes = fs::read(&key_path)?;
            Keypair::from_protobuf_encoding(&bytes)
                .map_err(|error| IdentityError::InvalidKey(error.to_string()))?
        } else {
            let keypair = Keypair::generate_ed25519();
            let encoded = keypair
                .to_protobuf_encoding()
                .map_err(|error| IdentityError::InvalidKey(error.to_string()))?;
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| IdentityError::InvalidKey(error.to_string()))?
                .as_nanos();
            let temporary = directory.join(format!(".key.{}.{nonce}.tmp", std::process::id()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&temporary)?;
            file.write_all(&encoded)?;
            file.sync_all()?;
            drop(file);
            match fs::hard_link(&temporary, &key_path) {
                Ok(()) => {
                    fs::remove_file(&temporary)?;
                    keypair
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    fs::remove_file(&temporary)?;
                    secure_key_metadata(&key_path)?;
                    let bytes = fs::read(&key_path)?;
                    Keypair::from_protobuf_encoding(&bytes)
                        .map_err(|error| IdentityError::InvalidKey(error.to_string()))?
                }
                Err(error) => {
                    let _ = fs::remove_file(&temporary);
                    return Err(error.into());
                }
            }
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

fn secure_key_metadata(path: &Path) -> Result<(), IdentityError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(IdentityError::InvalidKey(
            "identity key must be a regular non-symlink file".into(),
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
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

    #[cfg(unix)]
    #[test]
    fn identity_files_are_private_and_symlinks_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("identity");
        NodeIdentity::load_or_generate(&directory).unwrap();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let key = directory.join("key.protobuf");
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let linked = root.path().join("linked");
        fs::create_dir(&linked).unwrap();
        std::os::unix::fs::symlink(&key, linked.join("key.protobuf")).unwrap();
        assert!(NodeIdentity::load_or_generate(linked).is_err());
    }
}
