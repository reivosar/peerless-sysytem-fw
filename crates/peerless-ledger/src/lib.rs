//! Signed events, Merkle inclusion proofs, a persistent hash chain, and quorum finality.

use peerless_core::{ContentId, NodeId};
use peerless_identity::{verify, IdentityError, NodeIdentity};
use peerless_protocol::ExecutionRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub type Hash = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LedgerEvent {
    NodeJoined {
        member: NodeId,
    },
    NodeRevoked {
        member: NodeId,
    },
    TaskCreated {
        task_id: String,
    },
    TaskAccepted {
        task_id: String,
        executor: NodeId,
    },
    TaskCompleted(ExecutionRecord),
    TaskVerified {
        task_id: String,
        output: ContentId,
    },
    ContentPublished {
        content: ContentId,
        provider: NodeId,
    },
    StateCheckpoint {
        document: String,
        snapshot: ContentId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedEvent {
    pub event: LedgerEvent,
    pub signer: NodeId,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedEvent {
    pub fn seal(event: LedgerEvent, identity: &NodeIdentity) -> Result<Self, LedgerError> {
        let payload = serde_json::to_vec(&event)?;
        Ok(Self {
            event,
            signer: identity.node_id().clone(),
            public_key: identity.public_key_der().to_vec(),
            signature: identity.sign(&payload)?,
        })
    }
    pub fn verify(&self, temporary: impl AsRef<Path>) -> Result<bool, LedgerError> {
        Ok(NodeId::derive(&self.public_key) == self.signer
            && verify(
                &self.public_key,
                &serde_json::to_vec(&self.event)?,
                &self.signature,
                temporary,
            )?)
    }
    pub fn hash(&self) -> Result<Hash, LedgerError> {
        Ok(hash(&serde_json::to_vec(self)?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsensusSignature {
    pub signer: NodeId,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsensusProof {
    pub network_id: String,
    pub signatures: Vec<ConsensusSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub version: u16,
    pub previous: Option<Hash>,
    pub height: u64,
    pub timestamp: u64,
    pub events_root: Hash,
    pub events: Vec<SignedEvent>,
    pub consensus: ConsensusProof,
}

impl Block {
    pub fn proposal_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        Ok(serde_json::to_vec(&(
            self.version,
            self.previous,
            self.height,
            self.timestamp,
            self.events_root,
        ))?)
    }
    pub fn hash(&self) -> Result<Hash, LedgerError> {
        Ok(hash(&serde_json::to_vec(self)?))
    }
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        merkle_proof(
            &self
                .events
                .iter()
                .map(SignedEvent::hash)
                .collect::<Result<Vec<_>, _>>()
                .ok()?,
            index,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProof {
    pub index: usize,
    pub siblings: Vec<Hash>,
}
impl MerkleProof {
    pub fn verify(&self, leaf: Hash, root: Hash) -> bool {
        let mut current = leaf;
        let mut index = self.index;
        for sibling in &self.siblings {
            current = if index.is_multiple_of(2) {
                pair_hash(current, *sibling)
            } else {
                pair_hash(*sibling, current)
            };
            index /= 2;
        }
        current == root
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Membership {
    pub network_id: String,
    pub member: NodeId,
    pub issuer: NodeId,
    pub permissions: Vec<String>,
    pub expires_at: Option<u64>,
    pub issuer_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Invitation {
    pub version: u16,
    pub membership: Membership,
    pub bootstrap: Vec<String>,
    pub issued_at: u64,
}

impl Invitation {
    pub fn issue(
        network_id: String,
        member: NodeId,
        permissions: Vec<String>,
        expires_at: Option<u64>,
        bootstrap: Vec<String>,
        issued_at: u64,
        issuer: &NodeIdentity,
    ) -> Result<Self, LedgerError> {
        Ok(Self {
            version: 1,
            membership: Membership::issue(network_id, member, permissions, expires_at, issuer)?,
            bootstrap,
            issued_at,
        })
    }

    pub fn verify_for(
        &self,
        member: &NodeId,
        now: u64,
        temporary: impl AsRef<Path>,
    ) -> Result<bool, LedgerError> {
        Ok(self.version == 1
            && self.issued_at <= now
            && &self.membership.member == member
            && self.membership.verify(
                &HashSet::from([self.membership.issuer.clone()]),
                now,
                temporary,
            )?)
    }
}
impl Membership {
    pub fn issue(
        network_id: String,
        member: NodeId,
        permissions: Vec<String>,
        expires_at: Option<u64>,
        issuer: &NodeIdentity,
    ) -> Result<Self, LedgerError> {
        let mut value = Self {
            network_id,
            member,
            issuer: issuer.node_id().clone(),
            permissions,
            expires_at,
            issuer_public_key: issuer.public_key_der().to_vec(),
            signature: Vec::new(),
        };
        value.signature = issuer.sign(&value.payload()?)?;
        Ok(value)
    }
    fn payload(&self) -> Result<Vec<u8>, LedgerError> {
        Ok(serde_json::to_vec(&(
            self.network_id.as_str(),
            &self.member,
            &self.issuer,
            &self.permissions,
            self.expires_at,
        ))?)
    }
    pub fn verify(
        &self,
        trusted: &HashSet<NodeId>,
        now: u64,
        temporary: impl AsRef<Path>,
    ) -> Result<bool, LedgerError> {
        Ok(trusted.contains(&self.issuer)
            && NodeId::derive(&self.issuer_public_key) == self.issuer
            && self.expires_at.is_none_or(|expiry| expiry > now)
            && verify(
                &self.issuer_public_key,
                &self.payload()?,
                &self.signature,
                temporary,
            )?)
    }
}

pub trait ConsensusEngine {
    fn finalize(&self, block: &mut Block, approvals: &[&NodeIdentity]) -> Result<(), LedgerError>;
    fn verify(&self, block: &Block, temporary: &Path) -> Result<bool, LedgerError>;
}

pub struct QuorumConsensus {
    network_id: String,
    members: HashSet<NodeId>,
    quorum: usize,
}

pub struct BftConsensus {
    inner: QuorumConsensus,
    ordered_members: Vec<NodeId>,
    max_faults: usize,
}

impl BftConsensus {
    pub fn new(
        network_id: impl Into<String>,
        members: HashSet<NodeId>,
        max_faults: usize,
    ) -> Result<Self, LedgerError> {
        let required_members = max_faults.saturating_mul(3).saturating_add(1);
        if members.len() < required_members {
            return Err(LedgerError::InvalidQuorum);
        }
        let quorum = max_faults.saturating_mul(2).saturating_add(1);
        let mut ordered_members = members.iter().cloned().collect::<Vec<_>>();
        ordered_members.sort();
        Ok(Self {
            inner: QuorumConsensus::new(network_id, members, quorum)?,
            ordered_members,
            max_faults,
        })
    }

    pub fn leader(&self, height: u64) -> &NodeId {
        &self.ordered_members[height as usize % self.ordered_members.len()]
    }

    pub fn max_faults(&self) -> usize {
        self.max_faults
    }
}

impl ConsensusEngine for BftConsensus {
    fn finalize(&self, block: &mut Block, approvals: &[&NodeIdentity]) -> Result<(), LedgerError> {
        if !approvals
            .iter()
            .any(|identity| identity.node_id() == self.leader(block.height))
        {
            return Err(LedgerError::WrongLeader);
        }
        self.inner.finalize(block, approvals)
    }

    fn verify(&self, block: &Block, temporary: &Path) -> Result<bool, LedgerError> {
        Ok(block
            .consensus
            .signatures
            .iter()
            .any(|signature| &signature.signer == self.leader(block.height))
            && self.inner.verify(block, temporary)?)
    }
}
impl QuorumConsensus {
    pub fn new(
        network_id: impl Into<String>,
        members: HashSet<NodeId>,
        quorum: usize,
    ) -> Result<Self, LedgerError> {
        if quorum == 0 || quorum > members.len() {
            return Err(LedgerError::InvalidQuorum);
        }
        Ok(Self {
            network_id: network_id.into(),
            members,
            quorum,
        })
    }
}
impl ConsensusEngine for QuorumConsensus {
    fn finalize(&self, block: &mut Block, approvals: &[&NodeIdentity]) -> Result<(), LedgerError> {
        block.consensus = ConsensusProof {
            network_id: self.network_id.clone(),
            signatures: Vec::new(),
        };
        let payload = block.proposal_bytes()?;
        let mut seen = HashSet::new();
        for identity in approvals {
            if self.members.contains(identity.node_id()) && seen.insert(identity.node_id().clone())
            {
                block.consensus.signatures.push(ConsensusSignature {
                    signer: identity.node_id().clone(),
                    public_key: identity.public_key_der().to_vec(),
                    signature: identity.sign(&payload)?,
                });
            }
        }
        if block.consensus.signatures.len() < self.quorum {
            return Err(LedgerError::NoQuorum);
        }
        Ok(())
    }
    fn verify(&self, block: &Block, temporary: &Path) -> Result<bool, LedgerError> {
        if block.consensus.network_id != self.network_id {
            return Ok(false);
        }
        let payload = block.proposal_bytes()?;
        let mut valid = HashSet::new();
        for approval in &block.consensus.signatures {
            if self.members.contains(&approval.signer)
                && NodeId::derive(&approval.public_key) == approval.signer
                && verify(
                    &approval.public_key,
                    &payload,
                    &approval.signature,
                    temporary,
                )?
            {
                valid.insert(approval.signer.clone());
            }
        }
        Ok(valid.len() >= self.quorum)
    }
}

pub struct Ledger {
    root: PathBuf,
    blocks: Vec<Block>,
}
impl Ledger {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, LedgerError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        let mut files = fs::read_dir(&root)?.collect::<Result<Vec<_>, _>>()?;
        files.sort_by_key(|entry| entry.file_name());
        let blocks = files
            .into_iter()
            .filter(|entry| {
                entry.path().extension().and_then(|value| value.to_str()) == Some("json")
            })
            .map(|entry| {
                serde_json::from_slice(&fs::read(entry.path())?).map_err(LedgerError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { root, blocks })
    }
    pub fn next_block(
        &self,
        events: Vec<SignedEvent>,
        timestamp: u64,
        network_id: impl Into<String>,
    ) -> Result<Block, LedgerError> {
        Ok(Block {
            version: 1,
            previous: self.blocks.last().map(Block::hash).transpose()?,
            height: self.blocks.len() as u64,
            timestamp,
            events_root: merkle_root(
                &events
                    .iter()
                    .map(SignedEvent::hash)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            events,
            consensus: ConsensusProof {
                network_id: network_id.into(),
                signatures: Vec::new(),
            },
        })
    }
    pub fn append(
        &mut self,
        block: Block,
        consensus: &impl ConsensusEngine,
        temporary: &Path,
    ) -> Result<Hash, LedgerError> {
        let valid_events = block
            .events
            .iter()
            .map(|event| event.verify(temporary))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .all(|valid| valid);
        if block.height != self.blocks.len() as u64
            || block.previous != self.blocks.last().map(Block::hash).transpose()?
            || block.events_root
                != merkle_root(
                    &block
                        .events
                        .iter()
                        .map(SignedEvent::hash)
                        .collect::<Result<Vec<_>, _>>()?,
                )
            || !consensus.verify(&block, temporary)?
            || !valid_events
        {
            return Err(LedgerError::InvalidBlock);
        }
        let block_hash = block.hash()?;
        fs::create_dir_all(&self.root)?;
        let path = self.root.join(format!(
            "{:020}-{}.json",
            block.height,
            hex_string(block_hash)
        ));
        fs::write(path, serde_json::to_vec_pretty(&block)?)?;
        self.blocks.push(block);
        Ok(block_hash)
    }
    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }
}

pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return hash(&[]);
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty"));
        }
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| pair_hash(pair[0], pair[1]))
            .collect();
    }
    level[0]
}
fn merkle_proof(leaves: &[Hash], index: usize) -> Option<MerkleProof> {
    if index >= leaves.len() {
        return None;
    }
    let mut level = leaves.to_vec();
    let mut cursor = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last()?);
        }
        siblings.push(level[cursor ^ 1]);
        cursor /= 2;
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| pair_hash(pair[0], pair[1]))
            .collect();
    }
    Some(MerkleProof { index, siblings })
}
fn pair_hash(left: Hash, right: Hash) -> Hash {
    hash(&[left.as_slice(), right.as_slice()].concat())
}
fn hash(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}
fn hex_string(value: Hash) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("ledger I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("ledger serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("invalid quorum configuration")]
    InvalidQuorum,
    #[error("quorum was not reached")]
    NoQuorum,
    #[error("the deterministic leader did not approve the block")]
    WrongLeader,
    #[error("invalid block")]
    InvalidBlock,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quorum_chain_and_merkle_proof_reject_tampering() {
        let root = tempfile::tempdir().unwrap();
        let a = NodeIdentity::load_or_generate(root.path().join("a")).unwrap();
        let b = NodeIdentity::load_or_generate(root.path().join("b")).unwrap();
        let c = NodeIdentity::load_or_generate(root.path().join("c")).unwrap();
        let consensus = QuorumConsensus::new(
            "mesh",
            HashSet::from([
                a.node_id().clone(),
                b.node_id().clone(),
                c.node_id().clone(),
            ]),
            2,
        )
        .unwrap();
        let events = vec![
            SignedEvent::seal(
                LedgerEvent::TaskCreated {
                    task_id: "task-1".into(),
                },
                &a,
            )
            .unwrap(),
            SignedEvent::seal(
                LedgerEvent::ContentPublished {
                    content: ContentId::of(b"result"),
                    provider: b.node_id().clone(),
                },
                &b,
            )
            .unwrap(),
        ];
        let mut ledger = Ledger::open(root.path().join("ledger")).unwrap();
        let mut block = ledger.next_block(events, 1, "mesh").unwrap();
        consensus.finalize(&mut block, &[&a, &b]).unwrap();
        let proof = block.proof(1).unwrap();
        assert!(proof.verify(block.events[1].hash().unwrap(), block.events_root));
        assert!(!proof.verify(hash(b"tampered"), block.events_root));
        ledger.append(block, &consensus, root.path()).unwrap();
        assert_eq!(
            Ledger::open(root.path().join("ledger")).unwrap().height(),
            1
        );
    }
    #[test]
    fn quorum_requires_distinct_members_and_membership_expires() {
        let root = tempfile::tempdir().unwrap();
        let issuer = NodeIdentity::load_or_generate(root.path().join("issuer")).unwrap();
        let member = NodeIdentity::load_or_generate(root.path().join("member")).unwrap();
        let certificate = Membership::issue(
            "mesh".into(),
            member.node_id().clone(),
            vec!["execute".into()],
            Some(20),
            &issuer,
        )
        .unwrap();
        let trusted = HashSet::from([issuer.node_id().clone()]);
        assert!(certificate.verify(&trusted, 10, root.path()).unwrap());
        assert!(!certificate.verify(&trusted, 20, root.path()).unwrap());
        let consensus = QuorumConsensus::new(
            "mesh",
            HashSet::from([issuer.node_id().clone(), member.node_id().clone()]),
            2,
        )
        .unwrap();
        let event = SignedEvent::seal(
            LedgerEvent::NodeJoined {
                member: member.node_id().clone(),
            },
            &issuer,
        )
        .unwrap();
        let ledger = Ledger::open(root.path().join("ledger")).unwrap();
        let mut block = ledger.next_block(vec![event], 1, "mesh").unwrap();
        assert!(matches!(
            consensus.finalize(&mut block, &[&issuer, &issuer]),
            Err(LedgerError::NoQuorum)
        ));
    }

    #[test]
    fn invitation_is_bound_to_member_network_and_expiry() {
        let root = tempfile::tempdir().unwrap();
        let issuer = NodeIdentity::load_or_generate(root.path().join("issuer-invite")).unwrap();
        let member = NodeIdentity::load_or_generate(root.path().join("member-invite")).unwrap();
        let other = NodeIdentity::load_or_generate(root.path().join("other-invite")).unwrap();
        let invitation = Invitation::issue(
            "mesh".into(),
            member.node_id().clone(),
            vec!["execute".into()],
            Some(20),
            vec!["/ip4/127.0.0.1/udp/9718/quic-v1/p2p/12D3KooWQh".into()],
            1,
            &issuer,
        )
        .unwrap();
        assert!(invitation
            .verify_for(member.node_id(), 10, root.path())
            .unwrap());
        assert!(!invitation
            .verify_for(other.node_id(), 10, root.path())
            .unwrap());
        assert!(!invitation
            .verify_for(member.node_id(), 20, root.path())
            .unwrap());

        let future = Invitation::issue(
            "mesh".into(),
            member.node_id().clone(),
            vec!["execute".into()],
            None,
            Vec::new(),
            11,
            &issuer,
        )
        .unwrap();
        assert!(!future
            .verify_for(member.node_id(), 10, root.path())
            .unwrap());
    }

    #[test]
    fn bft_engine_requires_leader_and_two_f_plus_one_signatures() {
        let root = tempfile::tempdir().unwrap();
        let identities = (0..4)
            .map(|index| {
                NodeIdentity::load_or_generate(root.path().join(format!("bft-{index}"))).unwrap()
            })
            .collect::<Vec<_>>();
        let members = identities
            .iter()
            .map(|identity| identity.node_id().clone())
            .collect::<HashSet<_>>();
        let consensus = BftConsensus::new("bft-mesh", members, 1).unwrap();
        assert_eq!(consensus.max_faults(), 1);
        let leader_index = identities
            .iter()
            .position(|identity| identity.node_id() == consensus.leader(0))
            .unwrap();
        let leader = &identities[leader_index];
        let others = identities
            .iter()
            .filter(|identity| identity.node_id() != leader.node_id())
            .collect::<Vec<_>>();
        let event = SignedEvent::seal(
            LedgerEvent::TaskCreated {
                task_id: "bft".into(),
            },
            leader,
        )
        .unwrap();
        let ledger = Ledger::open(root.path().join("bft-ledger")).unwrap();
        let mut block = ledger.next_block(vec![event], 1, "bft-mesh").unwrap();
        assert!(matches!(
            consensus.finalize(&mut block, &[others[0], others[1], others[2]]),
            Err(LedgerError::WrongLeader)
        ));
        assert!(matches!(
            consensus.finalize(&mut block, &[leader, others[0]]),
            Err(LedgerError::NoQuorum)
        ));
        consensus
            .finalize(&mut block, &[leader, others[0], others[1]])
            .unwrap();
        assert!(consensus.verify(&block, root.path()).unwrap());
        block
            .consensus
            .signatures
            .retain(|signature| &signature.signer != leader.node_id());
        assert!(!consensus.verify(&block, root.path()).unwrap());
    }

    #[test]
    fn ledger_rejects_every_block_integrity_mutation() {
        let root = tempfile::tempdir().unwrap();
        let a = NodeIdentity::load_or_generate(root.path().join("matrix-a")).unwrap();
        let b = NodeIdentity::load_or_generate(root.path().join("matrix-b")).unwrap();
        let consensus = QuorumConsensus::new(
            "matrix",
            HashSet::from([a.node_id().clone(), b.node_id().clone()]),
            2,
        )
        .unwrap();
        let proposal = Ledger::open(root.path().join("proposal")).unwrap();
        let event = SignedEvent::seal(
            LedgerEvent::TaskCreated {
                task_id: "integrity".into(),
            },
            &a,
        )
        .unwrap();
        let mut valid = proposal.next_block(vec![event], 10, "matrix").unwrap();
        consensus.finalize(&mut valid, &[&a, &b]).unwrap();

        let mut mutations = Vec::new();
        let mut version = valid.clone();
        version.version += 1;
        mutations.push(version);
        let mut previous = valid.clone();
        previous.previous = Some(hash(b"wrong previous"));
        mutations.push(previous);
        let mut height = valid.clone();
        height.height += 1;
        mutations.push(height);
        let mut timestamp = valid.clone();
        timestamp.timestamp += 1;
        mutations.push(timestamp);
        let mut root_hash = valid.clone();
        root_hash.events_root[0] ^= 1;
        mutations.push(root_hash);
        let mut event_payload = valid.clone();
        event_payload.events[0].event = LedgerEvent::TaskCreated {
            task_id: "changed".into(),
        };
        mutations.push(event_payload);
        let mut event_signature = valid.clone();
        event_signature.events[0].signature[0] ^= 1;
        mutations.push(event_signature);
        let mut network = valid.clone();
        network.consensus.network_id = "other".into();
        mutations.push(network);
        let mut approval = valid;
        approval.consensus.signatures[0].signature[0] ^= 1;
        mutations.push(approval);

        for (index, block) in mutations.into_iter().enumerate() {
            let mut ledger = Ledger::open(root.path().join(format!("mutation-{index}"))).unwrap();
            assert!(matches!(
                ledger.append(block, &consensus, root.path()),
                Err(LedgerError::InvalidBlock)
            ));
            assert_eq!(ledger.height(), 0);
        }
    }
}
