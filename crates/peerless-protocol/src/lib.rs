//! Versioned wire messages and signed envelopes.

use peerless_core::{ContentId, NodeCapability, NodeId, Task};
use peerless_identity::{verify, IdentityError, NodeIdentity};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub version: u16,
    pub signer: NodeId,
    pub public_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedEnvelope {
    pub fn seal<T: Serialize>(value: &T, identity: &NodeIdentity) -> Result<Self, ProtocolError> {
        let payload = serde_json::to_vec(value)?;
        Ok(Self {
            version: PROTOCOL_VERSION,
            signer: identity.node_id().clone(),
            public_key: identity.public_key_der().to_vec(),
            signature: identity.sign(&payload)?,
            payload,
        })
    }

    pub fn open<T: DeserializeOwned>(
        &self,
        temporary_directory: impl AsRef<Path>,
    ) -> Result<T, ProtocolError> {
        self.open_with_signer(temporary_directory)
            .map(|(value, _)| value)
    }

    pub fn open_with_signer<T: DeserializeOwned>(
        &self,
        temporary_directory: impl AsRef<Path>,
    ) -> Result<(T, NodeId), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        let derived = NodeId::derive(&self.public_key);
        if derived != self.signer {
            return Err(ProtocolError::SignerMismatch);
        }
        if !verify(
            &self.public_key,
            &self.payload,
            &self.signature,
            temporary_directory,
        )? {
            return Err(ProtocolError::InvalidSignature);
        }
        Ok((serde_json::from_slice(&self.payload)?, self.signer.clone()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    GetCapability,
    Capability(NodeCapability),
    TaskOffer {
        task: Task,
        requester: NodeId,
        expires_at: u64,
    },
    TaskAccept {
        task_id: String,
    },
    TaskReject {
        task_id: String,
        reason: String,
    },
    TaskCommit {
        task_id: String,
    },
    TaskStarted {
        task_id: String,
        executor: NodeId,
    },
    TaskError {
        task_id: String,
        reason: String,
    },
    TaskCancel {
        task_id: String,
    },
    HasContent(ContentId),
    CheckContent(ContentId),
    GetContent(ContentId),
    Content {
        id: ContentId,
        bytes: Vec<u8>,
    },
    ContentStart {
        id: ContentId,
        total_size: u64,
        chunk_size: u32,
    },
    ContentChunk {
        id: ContentId,
        index: u32,
        bytes: Vec<u8>,
        chunk_hash: ContentId,
    },
    ContentComplete {
        id: ContentId,
    },
    TaskResult(SignedExecutionRecord),
    StateSnapshot {
        document: String,
        snapshot: Vec<u8>,
    },
    LedgerBlock {
        block: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub task_id: String,
    pub executor: NodeId,
    pub component: ContentId,
    pub input: ContentId,
    pub output: ContentId,
    pub execution_hash: ContentId,
    pub started_at: u64,
    pub completed_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedExecutionRecord {
    pub record: ExecutionRecord,
    pub signer: NodeId,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedExecutionRecord {
    pub fn seal(record: ExecutionRecord, identity: &NodeIdentity) -> Result<Self, ProtocolError> {
        let payload = serde_json::to_vec(&record)?;
        Ok(Self {
            record,
            signer: identity.node_id().clone(),
            public_key: identity.public_key_der().to_vec(),
            signature: identity.sign(&payload)?,
        })
    }

    pub fn verify(&self, temporary_directory: impl AsRef<Path>) -> Result<bool, ProtocolError> {
        if NodeId::derive(&self.public_key) != self.signer || self.record.executor != self.signer {
            return Ok(false);
        }
        let payload = serde_json::to_vec(&self.record)?;
        Ok(verify(
            &self.public_key,
            &payload,
            &self.signature,
            temporary_directory,
        )?)
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("envelope signer does not match its public key")]
    SignerMismatch,
    #[error("invalid envelope signature")]
    InvalidSignature,
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_envelope_rejects_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(directory.path()).unwrap();
        let mut envelope = SignedEnvelope::seal(
            &Message::TaskAccept {
                task_id: "t1".into(),
            },
            &identity,
        )
        .unwrap();
        assert!(matches!(
            envelope.open::<Message>(directory.path()),
            Ok(Message::TaskAccept { .. })
        ));
        envelope.payload.push(0);
        assert!(matches!(
            envelope.open::<Message>(directory.path()),
            Err(ProtocolError::InvalidSignature)
        ));
    }

    #[test]
    fn envelope_rejects_version_signer_and_key_substitution() {
        let directory = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(directory.path().join("a")).unwrap();
        let other = NodeIdentity::load_or_generate(directory.path().join("b")).unwrap();
        let original = SignedEnvelope::seal(&Message::GetCapability, &identity).unwrap();

        let mut wrong_version = original.clone();
        wrong_version.version += 1;
        assert!(matches!(
            wrong_version.open::<Message>(directory.path()),
            Err(ProtocolError::UnsupportedVersion(_))
        ));

        let mut wrong_signer = original.clone();
        wrong_signer.signer = other.node_id().clone();
        assert!(matches!(
            wrong_signer.open::<Message>(directory.path()),
            Err(ProtocolError::SignerMismatch)
        ));

        let mut substituted_key = original;
        substituted_key.public_key = other.public_key_der().to_vec();
        substituted_key.signer = other.node_id().clone();
        assert!(matches!(
            substituted_key.open::<Message>(directory.path()),
            Err(ProtocolError::InvalidSignature)
        ));
    }

    #[test]
    fn signed_execution_record_rejects_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(directory.path()).unwrap();
        let id = ContentId::of(b"content");
        let record = ExecutionRecord {
            task_id: "t1".into(),
            executor: identity.node_id().clone(),
            component: id,
            input: id,
            output: id,
            execution_hash: id,
            started_at: 1,
            completed_at: 2,
        };
        let mut signed = SignedExecutionRecord::seal(record, &identity).unwrap();
        assert!(signed.verify(directory.path()).unwrap());
        signed.record.completed_at = 3;
        assert!(!signed.verify(directory.path()).unwrap());
        signed.record.completed_at = 2;
        signed.signer = NodeId::derive(b"substituted");
        assert!(!signed.verify(directory.path()).unwrap());
    }
}
