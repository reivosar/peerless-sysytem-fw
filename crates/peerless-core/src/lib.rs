//! Stable domain types shared by the peerless subsystems.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};
use thiserror::Error;

/// SHA-256 identity of immutable bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ContentId([u8; 32]);

impl ContentId {
    pub const ALGORITHM: &'static str = "sha256";

    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn hex_digest(&self) -> String {
        hex::encode(self.0)
    }

    pub fn verify(&self, bytes: &[u8]) -> bool {
        *self == Self::of(bytes)
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", Self::ALGORITHM, hex::encode(self.0))
    }
}

impl FromStr for ContentId {
    type Err = ContentIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let digest = value
            .strip_prefix("sha256:")
            .ok_or(ContentIdError::UnsupportedAlgorithm)?;
        let bytes = hex::decode(digest).map_err(|_| ContentIdError::InvalidDigest)?;
        let digest = bytes
            .try_into()
            .map_err(|_| ContentIdError::InvalidDigest)?;
        Ok(Self(digest))
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ContentIdError {
    #[error("only sha256 content identifiers are supported")]
    UnsupportedAlgorithm,
    #[error("content digest must be exactly 32 bytes of hexadecimal")]
    InvalidDigest,
}

/// Public-key-derived identity. Construction is owned by the identity crate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct NodeId(Vec<u8>);

impl NodeId {
    pub fn derive(public_key: &[u8]) -> Self {
        Self(Sha256::digest(public_key).to_vec())
    }

    pub fn from_public_key_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl FromStr for NodeId {
    type Err = NodeIdError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(value).map_err(|_| NodeIdError)?;
        if bytes.len() != 32 {
            return Err(NodeIdError);
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
#[error("node id must be 32 bytes of hexadecimal")]
pub struct NodeIdError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Task {
    pub task_id: String,
    pub component: ContentId,
    pub input: ContentId,
    pub requirements: Requirements,
    pub verification: VerificationPolicy,
    /// Unix time in milliseconds.
    pub deadline: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Requirements {
    pub minimum_memory: u64,
    pub minimum_storage: u64,
    pub runtime: RuntimeRequirement,
    pub estimated_cpu_cost: u64,
    pub network: NetworkRequirement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeRequirement(pub String);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NetworkRequirement {
    None,
    Optional,
    Required,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum VerificationPolicy {
    TrustExecutor,
    Replicate(u8),
    Quorum {
        executions: u8,
        required_matches: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplicationPolicy {
    pub minimum_replicas: u8,
    pub target_replicas: u8,
}

impl ReplicationPolicy {
    pub fn validate(self) -> bool {
        self.minimum_replicas > 0 && self.target_replicas >= self.minimum_replicas
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TaskState {
    Created,
    Placing,
    Offered(NodeId),
    Accepted(NodeId),
    Running(NodeId),
    Verifying,
    Completed(ContentId),
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeCapability {
    pub node: NodeId,
    pub cpu_cores: u16,
    pub available_cpu: f64,
    pub available_memory: u64,
    pub available_storage: u64,
    pub runtimes: Vec<String>,
    pub power: PowerState,
    pub load: f64,
    pub task_slots: u16,
    /// Unix time in milliseconds.
    pub expires_at: u64,
}

impl NodeCapability {
    pub fn supports(&self, runtime: &RuntimeRequirement) -> bool {
        self.runtimes
            .iter()
            .any(|candidate| candidate == &runtime.0)
    }

    pub fn is_fresh_at(&self, now: u64) -> bool {
        self.expires_at > now
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PowerState {
    Ac,
    Battery,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_id_round_trips_and_verifies() {
        let id = ContentId::of(b"peerless");
        assert!(id.verify(b"peerless"));
        assert!(!id.verify(b"tampered"));
        assert_eq!(id.to_string().parse::<ContentId>().unwrap(), id);
    }

    #[test]
    fn identifier_boundary_and_mutation_matrix() {
        for size in [0, 1, 31, 32, 33, 1024, 65_536] {
            let bytes = (0..size)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let id = ContentId::of(&bytes);
            assert!(id.verify(&bytes));
            assert_eq!(id.to_string().parse::<ContentId>().unwrap(), id);
            if !bytes.is_empty() {
                for index in [0, bytes.len() / 2, bytes.len() - 1] {
                    let mut mutated = bytes.clone();
                    mutated[index] ^= 1;
                    assert!(!id.verify(&mutated));
                }
            }
        }
        for invalid in [
            "",
            "md5:00000000000000000000000000000000",
            "sha256:",
            "sha256:00",
            "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "sha256:000000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(invalid.parse::<ContentId>().is_err(), "accepted {invalid}");
        }
        for invalid in ["", "00", "zz", &"00".repeat(31), &"00".repeat(33)] {
            assert!(invalid.parse::<NodeId>().is_err(), "accepted {invalid}");
        }
    }
}
