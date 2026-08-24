use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use peerless_compute::{
    eligible, task_memory_limit, verify_outputs,
    wasm::{PureBytesModule, PureI32Module, WasmError},
    PlacementCandidate, PlacementObservation, PlacementWeights, Scheduler,
};
use peerless_core::{ContentId, NodeCapability, NodeId, PowerState, ReplicationPolicy, Task};
use peerless_identity::{IdentityError, NodeIdentity};
use peerless_ledger::{
    Block, ConsensusEngine, Hash as LedgerHash, Invitation, Ledger, LedgerError, LedgerEvent,
    Membership, MerkleProof, QuorumConsensus, SignedEvent,
};
use peerless_network::p2p::P2pRpc;
use peerless_network::{request, NetworkError, RpcServer};
use peerless_protocol::{
    ExecutionRecord, Message, ProtocolError, SignedEnvelope, SignedExecutionRecord,
};
use peerless_state::{StateDocument, StateError, StateStore};
use peerless_storage::{CasError, FileCas};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
use sysinfo::{Disks, System};
use thiserror::Error;

mod metadata;
use metadata::{Metadata, MetadataError};

const CONTENT_CHUNK_SIZE: usize = 64 * 1024;
const MAX_CONTENT_SIZE: u64 = 512 * 1024 * 1024;
const MAX_ACTIVE_UPLOADS: usize = 4;
const MAX_IN_FLIGHT_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;
const HOST_MEMORY_RESERVE: u64 = 1024 * 1024 * 1024;
const MAX_CONCURRENT_TASKS: usize = 1;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("node I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Storage(#[from] CasError),
    #[error(transparent)]
    Network(#[from] NetworkError),
    #[error(transparent)]
    Wasm(#[from] WasmError),
    #[error("peer rejected task: {0}")]
    Rejected(String),
    #[error("unexpected peer response")]
    UnexpectedResponse,
    #[error("libp2p failed: {0}")]
    P2p(String),
    #[error("replication target was not met: {actual} replicas, minimum {minimum}")]
    InsufficientReplicas { actual: usize, minimum: u8 },
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error(transparent)]
    Metadata(#[from] MetadataError),
}

struct Inner {
    identity: NodeIdentity,
    cas: FileCas,
    pending: Mutex<HashMap<String, PendingTask>>,
    completed: Mutex<HashMap<String, CompletedTask>>,
    placement_counts: Mutex<HashMap<NodeId, u64>>,
    state: StateStore,
    ledger: Mutex<Ledger>,
    membership: RwLock<Option<MembershipPolicy>>,
    uploads: Mutex<HashMap<(NodeId, ContentId), UploadSession>>,
    metadata: Metadata,
    temporary: PathBuf,
    peer_cache: PathBuf,
    membership_file: PathBuf,
}
struct UploadSession {
    total_size: u64,
    chunk_size: u32,
    chunks: Vec<Option<Vec<u8>>>,
}
struct PendingTask {
    task: Task,
    requester: NodeId,
    lease_expires_at: u64,
    running: bool,
}
struct CompletedTask {
    task: Task,
    requester: NodeId,
    result: SignedExecutionRecord,
}
struct MembershipPolicy {
    network_id: String,
    permissions: HashMap<NodeId, std::collections::HashSet<String>>,
}
#[derive(Clone)]
pub struct PeerlessNode {
    inner: Arc<Inner>,
}

pub struct PeerlessBuilder {
    storage: PathBuf,
    listen: Multiaddr,
}
pub struct Peerless {
    node: PeerlessNode,
    listen: Multiaddr,
}
pub struct ContentApi<'a>(&'a PeerlessNode);
pub struct StateApi<'a>(&'a PeerlessNode);
pub struct ComputeApi<'a>(&'a PeerlessNode);
pub struct LedgerApi<'a>(&'a PeerlessNode);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicationReport {
    pub content: ContentId,
    pub live_replicas: HashSet<PeerId>,
    pub repaired: Vec<PeerId>,
}
#[derive(Clone, Debug)]
pub struct VerifiedExecution {
    pub accepted: ExecutionRecord,
    pub output: Vec<u8>,
    pub executions: Vec<ExecutionRecord>,
}
#[derive(Clone, Debug)]
pub struct AuditProof {
    pub block_height: u64,
    pub event: SignedEvent,
    pub root: LedgerHash,
    pub proof: MerkleProof,
}

impl Peerless {
    pub fn builder() -> PeerlessBuilder {
        PeerlessBuilder {
            storage: PathBuf::from("peerless-data"),
            listen: "/ip4/0.0.0.0/udp/0/quic-v1"
                .parse()
                .expect("static multiaddress"),
        }
    }
    pub fn start(&self) -> Result<P2pRpc, NodeError> {
        self.node.serve_p2p(self.listen.clone())
    }
    pub fn content(&self) -> ContentApi<'_> {
        ContentApi(&self.node)
    }
    pub fn state(&self) -> StateApi<'_> {
        StateApi(&self.node)
    }
    pub fn compute(&self) -> ComputeApi<'_> {
        ComputeApi(&self.node)
    }
    pub fn ledger(&self) -> LedgerApi<'_> {
        LedgerApi(&self.node)
    }
    pub fn node(&self) -> &PeerlessNode {
        &self.node
    }
}
impl PeerlessBuilder {
    pub fn storage(mut self, path: impl Into<PathBuf>) -> Self {
        self.storage = path.into();
        self
    }
    pub fn listen(mut self, address: Multiaddr) -> Self {
        self.listen = address;
        self
    }
    pub fn build(self) -> Result<Peerless, NodeError> {
        Ok(Peerless {
            node: PeerlessNode::open(self.storage)?,
            listen: self.listen,
        })
    }
}
impl ContentApi<'_> {
    pub fn put(&self, bytes: &[u8]) -> Result<ContentId, NodeError> {
        self.0.put(bytes)
    }
}
impl StateApi<'_> {
    pub fn open(&self, name: &str) -> Result<StateDocument, NodeError> {
        self.0.state(name)
    }
}
impl ComputeApi<'_> {
    pub fn execute(
        &self,
        network: &P2pRpc,
        task: Task,
        component: &[u8],
        input: i32,
    ) -> Result<(ExecutionRecord, Vec<u8>), NodeError> {
        self.0.execute_best(network, task, component, input)
    }

    pub fn execute_bytes(
        &self,
        task: Task,
        component: &[u8],
        input: &[u8],
    ) -> Result<(ExecutionRecord, Vec<u8>), NodeError> {
        self.0.execute_local_bytes(task, component, input)
    }
}
impl LedgerApi<'_> {
    pub fn height(&self) -> u64 {
        self.0.ledger_height()
    }
    pub fn proof(&self, task_id: &str) -> Option<AuditProof> {
        let ledger = self.0.inner.ledger.lock().expect("ledger lock poisoned");
        for block in ledger.blocks() {
            for (index, event) in block.events.iter().enumerate() {
                if matches!(&event.event, LedgerEvent::TaskCompleted(record) if record.task_id == task_id)
                {
                    return Some(AuditProof {
                        block_height: block.height,
                        event: event.clone(),
                        root: block.events_root,
                        proof: block.proof(index)?,
                    });
                }
            }
        }
        None
    }
}

impl PeerlessNode {
    pub fn open(data: impl AsRef<Path>) -> Result<Self, NodeError> {
        let data = data.as_ref();
        let identity = NodeIdentity::load_or_generate(data.join("identity"))?;
        let cas = FileCas::open(data.join("cas"))?;
        let temporary = data.join("metadata/tmp");
        let metadata = Metadata::open(&data.join("metadata/local.db"))?;
        let completed = metadata
            .completed_tasks()?
            .into_iter()
            .filter_map(|(task, requester, result)| {
                let valid = result.verify(&temporary).ok() == Some(true)
                    && result.record.task_id == task.task_id
                    && result.record.component == task.component
                    && result.record.input == task.input
                    && cas.contains(result.record.output);
                valid.then(|| {
                    (
                        task.task_id.clone(),
                        CompletedTask {
                            task,
                            requester,
                            result,
                        },
                    )
                })
            })
            .collect();
        let node = Self {
            inner: Arc::new(Inner {
                identity,
                cas,
                pending: Mutex::new(HashMap::new()),
                completed: Mutex::new(completed),
                placement_counts: Mutex::new(HashMap::new()),
                state: StateStore::open(data.join("state/documents"))?,
                ledger: Mutex::new(Ledger::open(data.join("ledger/blocks"))?),
                membership: RwLock::new(None),
                uploads: Mutex::new(HashMap::new()),
                metadata,
                temporary,
                peer_cache: data.join("metadata/known-peers.json"),
                membership_file: data.join("metadata/membership-invitation.json"),
            }),
        };
        if node.inner.membership_file.exists() {
            let invitation: Invitation =
                serde_json::from_slice(&std::fs::read(&node.inner.membership_file)?)
                    .map_err(ProtocolError::from)?;
            node.activate_invitation(&invitation, now())?;
        }
        Ok(node)
    }
    pub fn node_id(&self) -> &NodeId {
        self.inner.identity.node_id()
    }
    pub fn issue_invitation(
        &self,
        network_id: impl Into<String>,
        member: NodeId,
        permissions: Vec<String>,
        expires_at: Option<u64>,
        bootstrap: Vec<String>,
    ) -> Result<Invitation, NodeError> {
        Ok(Invitation::issue(
            network_id.into(),
            member,
            permissions,
            expires_at,
            bootstrap,
            now(),
            &self.inner.identity,
        )?)
    }
    pub fn install_invitation(&self, invitation: &Invitation, at: u64) -> Result<(), NodeError> {
        if !invitation.verify_for(self.node_id(), at, &self.inner.temporary)? {
            return Err(NodeError::Rejected(
                "invitation is invalid, expired, or addressed to another node".into(),
            ));
        }
        if let Some(parent) = self.inner.membership_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            &self.inner.membership_file,
            serde_json::to_vec_pretty(invitation).map_err(ProtocolError::from)?,
        )?;
        self.activate_invitation(invitation, at)
    }
    fn activate_invitation(&self, invitation: &Invitation, at: u64) -> Result<(), NodeError> {
        if !invitation.verify_for(self.node_id(), at, &self.inner.temporary)? {
            return Err(NodeError::Rejected(
                "persisted invitation is invalid or expired".into(),
            ));
        }
        self.enforce_membership(
            invitation.membership.network_id.clone(),
            std::slice::from_ref(&invitation.membership),
            &std::collections::HashSet::from([invitation.membership.issuer.clone()]),
            at,
        )
    }
    pub fn apply_invitation_bootstrap(
        &self,
        network: &P2pRpc,
        invitation: &Invitation,
    ) -> Result<usize, NodeError> {
        let mut added = 0;
        for value in &invitation.bootstrap {
            let mut address: Multiaddr = value
                .parse()
                .map_err(|error: libp2p::multiaddr::Error| NodeError::P2p(error.to_string()))?;
            let peer = match address.pop() {
                Some(Protocol::P2p(peer)) => peer,
                _ => {
                    return Err(NodeError::P2p(
                        "invitation bootstrap must end in /p2p/PEER_ID".into(),
                    ))
                }
            };
            network.add_peer(peer, address).map_err(NodeError::P2p)?;
            added += 1;
        }
        Ok(added)
    }
    pub fn put(&self, bytes: &[u8]) -> Result<ContentId, NodeError> {
        Ok(self.inner.cas.put(bytes)?)
    }
    pub fn put_and_provide(&self, network: &P2pRpc, bytes: &[u8]) -> Result<ContentId, NodeError> {
        let id = self.put(bytes)?;
        network.provide(id.to_string()).map_err(NodeError::P2p)?;
        Ok(id)
    }
    pub fn fetch_p2p(&self, network: &P2pRpc, id: ContentId) -> Result<Vec<u8>, NodeError> {
        if let Ok(bytes) = self.inner.cas.get(id) {
            return Ok(bytes);
        }
        for peer in network
            .find_providers(id.to_string())
            .map_err(NodeError::P2p)?
        {
            if let Ok(Message::Content { id: found, bytes }) =
                self.send_p2p(network, peer, Message::GetContent(id))
            {
                if found == id && id.verify(&bytes) {
                    self.inner.cas.put(&bytes)?;
                    return Ok(bytes);
                }
            }
        }
        Err(NodeError::Storage(CasError::NotFound(id)))
    }
    pub fn state(&self, name: &str) -> Result<StateDocument, NodeError> {
        Ok(self.inner.state.document(name)?)
    }
    /// Imports a CRDT snapshot into the named local document. If the document
    /// does not exist, the snapshot becomes its common history; otherwise it is
    /// merged with the local history.
    pub fn merge_state_snapshot(&self, name: &str, snapshot: &[u8]) -> Result<(), NodeError> {
        self.inner.state.merge_snapshot(name, snapshot)?;
        Ok(())
    }
    pub fn publish_state(
        &self,
        network: &P2pRpc,
        document: &str,
        state: &mut StateDocument,
    ) -> Result<(), NodeError> {
        let snapshot = state.snapshot();
        state.save()?;
        let envelope = SignedEnvelope::seal(
            &Message::StateSnapshot {
                document: document.to_owned(),
                snapshot,
            },
            &self.inner.identity,
        )?;
        let bytes = serde_json::to_vec(&envelope).map_err(ProtocolError::from)?;
        network
            .publish("peerless/state/v1", bytes)
            .map_err(NodeError::P2p)
    }
    pub fn merge_state_gossip(&self, network: &P2pRpc) -> Result<usize, NodeError> {
        let mut merged = 0;
        for (topic, _, bytes) in network.drain_gossip_messages() {
            if topic != "peerless/state/v1" {
                continue;
            }
            let envelope: SignedEnvelope =
                serde_json::from_slice(&bytes).map_err(ProtocolError::from)?;
            let (message, signer): (Message, NodeId) =
                envelope.open_with_signer(&self.inner.temporary)?;
            if let Some(policy) = self
                .inner
                .membership
                .read()
                .expect("membership lock poisoned")
                .as_ref()
            {
                if !policy.permissions.get(&signer).is_some_and(|permissions| {
                    permissions.contains("*") || permissions.contains("state")
                }) {
                    continue;
                }
            }
            if let Message::StateSnapshot { document, snapshot } = message {
                self.inner.state.merge_snapshot(&document, &snapshot)?;
                merged += 1;
            }
        }
        Ok(merged)
    }
    pub fn ledger_height(&self) -> u64 {
        self.inner
            .ledger
            .lock()
            .expect("ledger lock poisoned")
            .height()
    }
    pub fn append_ledger_block(
        &self,
        block: Block,
        consensus: &impl ConsensusEngine,
    ) -> Result<(), NodeError> {
        self.inner
            .ledger
            .lock()
            .expect("ledger lock poisoned")
            .append(block, consensus, &self.inner.temporary)?;
        Ok(())
    }
    pub fn publish_ledger_block(&self, network: &P2pRpc, block: &Block) -> Result<(), NodeError> {
        let message = Message::LedgerBlock {
            block: serde_json::to_vec(block).map_err(LedgerError::from)?,
        };
        let envelope = SignedEnvelope::seal(&message, &self.inner.identity)?;
        network
            .publish(
                "peerless/ledger/v1",
                serde_json::to_vec(&envelope).map_err(ProtocolError::from)?,
            )
            .map_err(NodeError::P2p)
    }
    pub fn merge_ledger_gossip(
        &self,
        network: &P2pRpc,
        consensus: &impl ConsensusEngine,
    ) -> Result<usize, NodeError> {
        let mut appended = 0;
        for (topic, _, bytes) in network.drain_gossip_messages() {
            if topic != "peerless/ledger/v1" {
                continue;
            }
            let envelope: SignedEnvelope =
                serde_json::from_slice(&bytes).map_err(ProtocolError::from)?;
            let (message, signer): (Message, NodeId) =
                envelope.open_with_signer(&self.inner.temporary)?;
            if let Some(policy) = self
                .inner
                .membership
                .read()
                .expect("membership lock poisoned")
                .as_ref()
            {
                if !policy.permissions.get(&signer).is_some_and(|permissions| {
                    permissions.contains("*") || permissions.contains("ledger")
                }) {
                    continue;
                }
            }
            if let Message::LedgerBlock { block } = message {
                self.append_ledger_block(
                    serde_json::from_slice(&block).map_err(LedgerError::from)?,
                    consensus,
                )?;
                appended += 1;
            }
        }
        Ok(appended)
    }
    pub fn storage_stats(&self) -> Result<(u64, u64), NodeError> {
        Ok(self.inner.cas.stats()?)
    }
    pub fn task_counts(&self) -> (usize, usize) {
        (
            self.inner.pending.lock().expect("task lock poisoned").len(),
            self.inner
                .completed
                .lock()
                .expect("completed task lock poisoned")
                .len(),
        )
    }
    pub fn metadata_counts(&self) -> Result<(u64, u64), NodeError> {
        Ok(self.inner.metadata.counts()?)
    }
    pub fn persisted_peer_count(&self) -> Result<u64, NodeError> {
        Ok(self.inner.metadata.peer_count()?)
    }
    pub fn peer_reputation(
        &self,
        node: &NodeId,
    ) -> Result<peerless_compute::PeerReputation, NodeError> {
        Ok(self.inner.metadata.reputation(node)?)
    }
    pub fn enforce_membership(
        &self,
        network_id: impl Into<String>,
        certificates: &[Membership],
        trusted_issuers: &std::collections::HashSet<NodeId>,
        at: u64,
    ) -> Result<(), NodeError> {
        let network_id = network_id.into();
        let mut permissions = HashMap::new();
        for certificate in certificates {
            if certificate.network_id == network_id
                && certificate.verify(trusted_issuers, at, &self.inner.temporary)?
            {
                permissions.insert(
                    certificate.member.clone(),
                    certificate.permissions.iter().cloned().collect(),
                );
            }
        }
        *self
            .inner
            .membership
            .write()
            .expect("membership lock poisoned") = Some(MembershipPolicy {
            network_id,
            permissions,
        });
        Ok(())
    }
    pub fn replicate_p2p(
        &self,
        network: &P2pRpc,
        peers: impl IntoIterator<Item = PeerId>,
        id: ContentId,
        policy: ReplicationPolicy,
    ) -> Result<Vec<PeerId>, NodeError> {
        if !policy.validate() {
            return Err(NodeError::InsufficientReplicas {
                actual: 0,
                minimum: policy.minimum_replicas,
            });
        }
        let bytes = self.inner.cas.get(id)?;
        let mut replicas = Vec::new();
        for peer in peers {
            if replicas.len() >= usize::from(policy.target_replicas.saturating_sub(1)) {
                break;
            }
            if matches!(self.send_p2p(network, peer, Message::Content { id, bytes: bytes.clone() }), Ok(Message::HasContent(found)) if found == id)
            {
                replicas.push(peer);
            }
        }
        let actual = replicas.len() + 1;
        if actual < usize::from(policy.minimum_replicas) {
            return Err(NodeError::InsufficientReplicas {
                actual,
                minimum: policy.minimum_replicas,
            });
        }
        Ok(replicas)
    }
    pub fn repair_replication_p2p(
        &self,
        network: &P2pRpc,
        id: ContentId,
        policy: ReplicationPolicy,
        known_replicas: &mut HashSet<PeerId>,
    ) -> Result<ReplicationReport, NodeError> {
        if !policy.validate() {
            return Err(NodeError::InsufficientReplicas {
                actual: 0,
                minimum: policy.minimum_replicas,
            });
        }
        let mut live = HashSet::new();
        for peer in known_replicas.iter().copied() {
            if matches!(self.send_p2p(network, peer, Message::CheckContent(id)), Ok(Message::HasContent(found)) if found == id)
            {
                live.insert(peer);
            }
        }
        let bytes = self.inner.cas.get(id)?;
        let target_remote = usize::from(policy.target_replicas.saturating_sub(1));
        let mut repaired = Vec::new();
        for peer in network.peers().keys().copied() {
            if live.len() >= target_remote {
                break;
            }
            if live.contains(&peer) {
                continue;
            }
            let result = self.transfer_content_via(
                &mut |envelope| {
                    let response = network.request(peer, envelope).map_err(NodeError::P2p)?;
                    Self::ensure_peer_identity(&response, peer)?;
                    Ok(response)
                },
                id,
                &bytes,
            );
            if result.is_ok() {
                live.insert(peer);
                repaired.push(peer);
            }
        }
        *known_replicas = live.clone();
        let actual = live.len() + 1;
        if actual < usize::from(policy.minimum_replicas) {
            return Err(NodeError::InsufficientReplicas {
                actual,
                minimum: policy.minimum_replicas,
            });
        }
        Ok(ReplicationReport {
            content: id,
            live_replicas: live,
            repaired,
        })
    }
    pub fn serve(&self, bind: SocketAddr) -> Result<RpcServer, NodeError> {
        let node = self.clone();
        Ok(RpcServer::start_on(bind, move |message| {
            node.handle_or_reject(message)
        })?)
    }
    pub fn serve_p2p(&self, listen: Multiaddr) -> Result<P2pRpc, NodeError> {
        let node = self.clone();
        let network = P2pRpc::start(self.inner.identity.keypair(), listen, move |message| {
            node.handle_or_reject(message)
        })
        .map_err(NodeError::P2p)?;
        network
            .load_peer_cache(&self.inner.peer_cache)
            .map_err(NodeError::P2p)?;
        Ok(network)
    }
    pub fn save_peer_cache(&self, network: &P2pRpc) -> Result<(), NodeError> {
        network
            .save_peer_cache(&self.inner.peer_cache)
            .map_err(NodeError::P2p)
    }
    pub fn handle(&self, envelope: SignedEnvelope) -> Result<SignedEnvelope, NodeError> {
        let (message, signer): (Message, NodeId) =
            envelope.open_with_signer(&self.inner.temporary)?;
        if let Some(policy) = self
            .inner
            .membership
            .read()
            .expect("membership lock poisoned")
            .as_ref()
        {
            let required = permission_for(&message);
            let allowed = policy.permissions.get(&signer).is_some_and(|permissions| {
                permissions.contains("*") || permissions.contains(required)
            });
            if !allowed {
                return Ok(SignedEnvelope::seal(
                    &Message::TaskReject {
                        task_id: String::new(),
                        reason: format!(
                            "signer is not authorized for {required} in {}",
                            policy.network_id
                        ),
                    },
                    &self.inner.identity,
                )?);
            }
        }
        let response = match message {
            Message::Content { id, bytes } if id.verify(&bytes) => {
                self.inner.cas.put(&bytes)?;
                Message::HasContent(id)
            }
            Message::Content { .. } => Message::TaskReject {
                task_id: String::new(),
                reason: "content hash mismatch".into(),
            },
            Message::ContentStart {
                id,
                total_size,
                chunk_size,
            } => {
                let key = (signer.clone(), id);
                let mut uploads = self.inner.uploads.lock().expect("upload lock poisoned");
                let already_present = uploads.contains_key(&key);
                let reserved = uploads
                    .iter()
                    .filter(|(existing, _)| *existing != &key)
                    .map(|(_, session)| session.total_size)
                    .sum::<u64>();
                let valid = total_size <= MAX_CONTENT_SIZE
                    && chunk_size == CONTENT_CHUNK_SIZE as u32
                    && (already_present || uploads.len() < MAX_ACTIVE_UPLOADS)
                    && reserved
                        .checked_add(total_size)
                        .is_some_and(|total| total <= MAX_IN_FLIGHT_UPLOAD_BYTES);
                if valid {
                    let count = total_size.div_ceil(u64::from(chunk_size)) as usize;
                    uploads.insert(
                        key,
                        UploadSession {
                            total_size,
                            chunk_size,
                            chunks: vec![None; count],
                        },
                    );
                    Message::HasContent(id)
                } else {
                    Message::TaskError {
                        task_id: String::new(),
                        reason: format!("content transfer exceeds bounded upload budget for {id}"),
                    }
                }
            }
            Message::ContentChunk {
                id,
                index,
                bytes,
                chunk_hash,
            } => {
                let mut uploads = self.inner.uploads.lock().expect("upload lock poisoned");
                let key = (signer.clone(), id);
                let valid = uploads.get(&key).is_some_and(|session| {
                    chunk_hash.verify(&bytes)
                        && bytes.len() <= session.chunk_size as usize
                        && (index as usize) < session.chunks.len()
                });
                if valid {
                    let session = uploads
                        .get_mut(&key)
                        .expect("validated upload session disappeared");
                    session.chunks[index as usize] = Some(bytes);
                    Message::HasContent(chunk_hash)
                } else {
                    uploads.remove(&key);
                    Message::TaskError {
                        task_id: String::new(),
                        reason: "invalid content chunk".into(),
                    }
                }
            }
            Message::ContentComplete { id } => {
                let session = self
                    .inner
                    .uploads
                    .lock()
                    .expect("upload lock poisoned")
                    .remove(&(signer.clone(), id));
                match session {
                    Some(session) if session.chunks.iter().all(Option::is_some) => {
                        let bytes = session
                            .chunks
                            .into_iter()
                            .flatten()
                            .flatten()
                            .collect::<Vec<_>>();
                        if bytes.len() as u64 == session.total_size && id.verify(&bytes) {
                            self.inner.cas.put(&bytes)?;
                            Message::HasContent(id)
                        } else {
                            Message::TaskError {
                                task_id: String::new(),
                                reason: "content size or final hash mismatch".into(),
                            }
                        }
                    }
                    _ => Message::TaskError {
                        task_id: String::new(),
                        reason: "content transfer incomplete".into(),
                    },
                }
            }
            Message::TaskOffer {
                task,
                requester,
                expires_at,
            } => self.accept_offer(task, requester, expires_at, &signer)?,
            Message::TaskCommit { task_id } => self.execute(&task_id, &signer)?,
            Message::TaskCancel { task_id } => {
                let mut pending = self.inner.pending.lock().expect("task lock poisoned");
                match pending.get(&task_id) {
                    Some(task) if task.requester == signer && !task.running => {
                        pending.remove(&task_id);
                        Message::TaskError {
                            task_id,
                            reason: "cancelled".into(),
                        }
                    }
                    Some(task) if task.requester == signer => Message::TaskError {
                        task_id,
                        reason: "task is already running".into(),
                    },
                    _ => Message::TaskError {
                        task_id,
                        reason: "not found or not requester".into(),
                    },
                }
            }
            Message::GetContent(id) => Message::Content {
                id,
                bytes: self.inner.cas.get(id)?,
            },
            Message::CheckContent(id) if self.inner.cas.contains(id) => Message::HasContent(id),
            Message::CheckContent(_) => Message::TaskError {
                task_id: String::new(),
                reason: "content not found".into(),
            },
            Message::GetCapability => Message::Capability(self.capability()),
            Message::StateSnapshot { document, snapshot } => {
                self.inner.state.merge_snapshot(&document, &snapshot)?;
                Message::HasContent(ContentId::of(&snapshot))
            }
            Message::LedgerBlock { .. } => Message::TaskReject {
                task_id: String::new(),
                reason: "ledger block requires configured quorum verification".into(),
            },
            other => other,
        };
        Ok(SignedEnvelope::seal(&response, &self.inner.identity)?)
    }

    pub fn capability(&self) -> NodeCapability {
        let observed_at = now();
        let (reserved_memory, occupied_slots) = {
            let mut pending = self.inner.pending.lock().expect("task lock poisoned");
            pending.retain(|_, reservation| {
                reservation.running
                    || (reservation.lease_expires_at > observed_at
                        && reservation
                            .task
                            .deadline
                            .is_none_or(|deadline| deadline > observed_at))
            });
            (
                pending
                    .values()
                    .filter_map(|reservation| task_memory_limit(&reservation.task))
                    .sum::<u64>(),
                pending.len(),
            )
        };
        let mut system = System::new_all();
        system.refresh_memory();
        system.refresh_cpu_usage();
        let disks = Disks::new_with_refreshed_list();
        let available_cpu = (1.0 - f64::from(system.global_cpu_usage()) / 100.0).clamp(0.0, 1.0);
        NodeCapability {
            node: self.node_id().clone(),
            cpu_cores: system.cpus().len().min(u16::MAX as usize) as u16,
            available_cpu,
            available_memory: system
                .available_memory()
                .saturating_sub(HOST_MEMORY_RESERVE)
                .saturating_sub(reserved_memory),
            available_storage: disks.list().iter().map(|disk| disk.available_space()).sum(),
            runtimes: vec!["wasmtime-component-v1".into(), "wasmtime-bytes-v1".into()],
            power: PowerState::Unknown,
            load: 1.0 - available_cpu,
            task_slots: MAX_CONCURRENT_TASKS
                .saturating_sub(occupied_slots)
                .min(u16::MAX as usize) as u16,
            expires_at: observed_at + 30_000,
        }
    }

    fn accept_offer(
        &self,
        task: Task,
        requester: NodeId,
        expires_at: u64,
        signer: &NodeId,
    ) -> Result<Message, NodeError> {
        let id = task.task_id.clone();
        let structurally_valid = !id.is_empty()
            && requester == *signer
            && expires_at > now()
            && self.inner.cas.contains(task.component)
            && self.inner.cas.contains(task.input);
        if !structurally_valid {
            return Ok(Message::TaskReject {
                task_id: id,
                reason: "invalid, expired, unauthorised, or content missing".into(),
            });
        }
        if let Some(existing) = self
            .inner
            .completed
            .lock()
            .expect("completed task lock poisoned")
            .get(&id)
        {
            return Ok(
                if existing.requester == requester && existing.task == task {
                    Message::TaskAccept { task_id: id }
                } else {
                    Message::TaskReject {
                        task_id: id,
                        reason: "task id collision".into(),
                    }
                },
            );
        }
        let observed_at = now();
        let capability = self.capability();
        let mut pending = self.inner.pending.lock().expect("task lock poisoned");
        if let Some(existing) = pending.get(&id) {
            return Ok(
                if existing.requester == requester && existing.task == task {
                    Message::TaskAccept { task_id: id }
                } else {
                    Message::TaskReject {
                        task_id: id,
                        reason: "task id collision".into(),
                    }
                },
            );
        }
        if !eligible(&task, &capability, observed_at) || pending.len() >= MAX_CONCURRENT_TASKS {
            return Ok(Message::TaskReject {
                task_id: id,
                reason: "executor has no safe memory or task-slot capacity".into(),
            });
        }
        pending.insert(
            id.clone(),
            PendingTask {
                task,
                requester,
                lease_expires_at: expires_at,
                running: false,
            },
        );
        drop(pending);
        self.inner
            .metadata
            .task(&id, "accepted", Some(self.node_id()), now())?;
        self.inner.metadata.event(now(), "task.accepted", &id)?;
        Ok(Message::TaskAccept { task_id: id })
    }

    pub fn peer_capability(&self, address: SocketAddr) -> Result<NodeCapability, NodeError> {
        match self.send(address, Message::GetCapability)? {
            Message::Capability(value) => Ok(value),
            _ => Err(NodeError::UnexpectedResponse),
        }
    }
    pub fn peer_capability_p2p(
        &self,
        network: &P2pRpc,
        peer: PeerId,
    ) -> Result<NodeCapability, NodeError> {
        match self.send_p2p(network, peer, Message::GetCapability)? {
            Message::Capability(value) => {
                let addresses = network
                    .peers()
                    .get(&peer)
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                self.inner
                    .metadata
                    .peer(&peer.to_string(), &value.node, &addresses, now())?;
                Ok(value)
            }
            _ => Err(NodeError::UnexpectedResponse),
        }
    }
    fn execute(&self, task_id: &str, signer: &NodeId) -> Result<Message, NodeError> {
        if let Some(completed) = self
            .inner
            .completed
            .lock()
            .expect("completed task lock poisoned")
            .get(task_id)
        {
            if &completed.requester != signer {
                return Err(NodeError::Rejected(
                    "commit signer is not the requester".into(),
                ));
            }
            return Ok(Message::TaskResult(completed.result.clone()));
        }
        let mut pending = self.inner.pending.lock().expect("task lock poisoned");
        let accepted = pending
            .get_mut(task_id)
            .ok_or(NodeError::UnexpectedResponse)?;
        if &accepted.requester != signer {
            return Err(NodeError::Rejected(
                "commit signer is not the requester".into(),
            ));
        }
        if accepted.lease_expires_at <= now()
            || accepted
                .task
                .deadline
                .is_some_and(|deadline| deadline <= now())
        {
            pending.remove(task_id);
            return Err(NodeError::Rejected("task lease or deadline expired".into()));
        }
        if accepted.running {
            return Err(NodeError::Rejected("task is already running".into()));
        }
        accepted.running = true;
        let task = accepted.task.clone();
        drop(pending);
        let result = (|| -> Result<Message, NodeError> {
            self.inner
                .metadata
                .task(task_id, "running", Some(self.node_id()), now())?;
            let started_at = now();
            let component = self.inner.cas.get(task.component)?;
            let raw = self.inner.cas.get(task.input)?;
            let memory_limit = task_memory_limit(&task)
                .ok_or_else(|| NodeError::Rejected("task memory limit is unsafe".into()))?;
            let output_bytes = if task.requirements.runtime.0 == "wasmtime-bytes-v1" {
                PureBytesModule::parse(&component)?.invoke_with_limit("run", &raw, memory_limit)?
            } else {
                let input = i32::from_le_bytes(raw.try_into().map_err(|_| {
                    WasmError::Invalid("input must be one little-endian i32".into())
                })?);
                PureI32Module::parse(&component)?
                    .invoke_with_limit("run", input, memory_limit)?
                    .to_le_bytes()
                    .to_vec()
            };
            let output = self.inner.cas.put(&output_bytes)?;
            let task_for_cache = task.clone();
            let record = ExecutionRecord {
                task_id: task.task_id.clone(),
                executor: self.node_id().clone(),
                component: task.component,
                input: task.input,
                output,
                execution_hash: ContentId::of(
                    &[
                        task.component.digest().as_slice(),
                        task.input.digest().as_slice(),
                        output.digest().as_slice(),
                    ]
                    .concat(),
                ),
                started_at,
                completed_at: now(),
            };
            let signed_result = SignedExecutionRecord::seal(record, &self.inner.identity)?;
            self.inner
                .completed
                .lock()
                .expect("completed task lock poisoned")
                .insert(
                    task_id.to_owned(),
                    CompletedTask {
                        task: task_for_cache.clone(),
                        requester: signer.clone(),
                        result: signed_result.clone(),
                    },
                );
            self.append_ledger_event(LedgerEvent::TaskCompleted(signed_result.record.clone()))?;
            self.inner
                .metadata
                .completed_task(&task_for_cache, signer, &signed_result, now())?;
            self.inner
                .metadata
                .event(now(), "task.completed", task_id)?;
            Ok(Message::TaskResult(signed_result))
        })();
        self.inner
            .pending
            .lock()
            .expect("task lock poisoned")
            .remove(task_id);
        result
    }
    fn append_ledger_event(&self, event: LedgerEvent) -> Result<(), NodeError> {
        let signed = SignedEvent::seal(event, &self.inner.identity)?;
        let members = std::collections::HashSet::from([self.node_id().clone()]);
        let consensus = QuorumConsensus::new("local", members, 1)?;
        let mut ledger = self.inner.ledger.lock().expect("ledger lock poisoned");
        let mut block = ledger.next_block(vec![signed], now(), "local")?;
        consensus.finalize(&mut block, &[&self.inner.identity])?;
        ledger.append(block, &consensus, &self.inner.temporary)?;
        Ok(())
    }
    fn handle_or_reject(&self, envelope: SignedEnvelope) -> SignedEnvelope {
        self.handle(envelope).unwrap_or_else(|error| {
            SignedEnvelope::seal(
                &Message::TaskReject {
                    task_id: String::new(),
                    reason: error.to_string(),
                },
                &self.inner.identity,
            )
            .expect("local signing failed")
        })
    }
    pub fn remote_execute(
        &self,
        address: SocketAddr,
        task: Task,
        component: &[u8],
        input: i32,
    ) -> Result<(ExecutionRecord, Vec<u8>), NodeError> {
        self.remote_execute_via(task, component, input, |envelope| {
            Ok(request(address, &envelope)?)
        })
    }
    pub fn execute_local(
        &self,
        task: Task,
        component: &[u8],
        input: i32,
    ) -> Result<(ExecutionRecord, Vec<u8>), NodeError> {
        self.remote_execute_via(task, component, input, |envelope| self.handle(envelope))
    }

    pub fn execute_local_bytes(
        &self,
        task: Task,
        component: &[u8],
        input: &[u8],
    ) -> Result<(ExecutionRecord, Vec<u8>), NodeError> {
        self.remote_execute_bytes_via(task, component, input, |envelope| self.handle(envelope))
    }

    pub fn execute_best(
        &self,
        network: &P2pRpc,
        task: Task,
        component: &[u8],
        input: i32,
    ) -> Result<(ExecutionRecord, Vec<u8>), NodeError> {
        match self.select_best_executor(network, &task)? {
            Some(peer) => self.remote_execute_p2p(network, peer, task, component, input),
            None => self.execute_local(task, component, input),
        }
    }

    pub fn execute_best_bytes(
        &self,
        network: &P2pRpc,
        task: Task,
        component: &[u8],
        input: &[u8],
    ) -> Result<(ExecutionRecord, Vec<u8>), NodeError> {
        match self.select_best_executor(network, &task)? {
            Some(peer) => self.remote_execute_bytes_p2p(network, peer, task, component, input),
            None => self.execute_local_bytes(task, component, input),
        }
    }

    fn select_best_executor(
        &self,
        network: &P2pRpc,
        task: &Task,
    ) -> Result<Option<PeerId>, NodeError> {
        let mut candidates = vec![(
            None,
            PlacementCandidate {
                capability: self.capability(),
                observation: PlacementObservation {
                    locality: 1.0,
                    ..Default::default()
                },
            },
        )];
        for peer in network.peers().keys().copied() {
            if let Ok(capability) = self.peer_capability_p2p(network, peer) {
                let reputation = self.peer_reputation(&capability.node).unwrap_or_default();
                let total = reputation.success
                    + reputation.failure
                    + reputation.invalid_result
                    + reputation.timeout;
                candidates.push((
                    Some(peer),
                    PlacementCandidate {
                        capability,
                        observation: PlacementObservation {
                            inverse_latency: if reputation.average_latency_ms > 0.0 {
                                1.0 / (1.0 + reputation.average_latency_ms / 100.0)
                            } else {
                                0.5
                            },
                            historical_success: if total == 0 {
                                0.5
                            } else {
                                reputation.success as f64 / total as f64
                            },
                            trust: reputation.trust_score(),
                            ..Default::default()
                        },
                    },
                ));
            }
        }
        let views = candidates
            .iter()
            .map(|(_, candidate)| candidate.clone())
            .collect::<Vec<_>>();
        let selected = {
            let mut assignments = self
                .inner
                .placement_counts
                .lock()
                .expect("placement history lock poisoned");
            let selected = Scheduler::new(PlacementWeights::default())
                .place_balanced_with_local_fallback(
                    task,
                    &views,
                    self.node_id(),
                    &assignments,
                    now(),
                )
                .map_err(|error| NodeError::Rejected(error.to_string()))?;
            if &selected.node != self.node_id() {
                *assignments.entry(selected.node.clone()).or_insert(0) += 1;
            }
            selected
        };
        match candidates
            .into_iter()
            .find(|(_, candidate)| candidate.capability.node == selected.node)
            .and_then(|(peer, _)| peer)
        {
            Some(peer) => Ok(Some(peer)),
            None => Ok(None),
        }
    }
    pub fn execute_verified_p2p(
        &self,
        network: &P2pRpc,
        peers: impl IntoIterator<Item = PeerId>,
        task: Task,
        component: &[u8],
        input: i32,
    ) -> Result<VerifiedExecution, NodeError> {
        let required = match &task.verification {
            peerless_core::VerificationPolicy::TrustExecutor => 1,
            peerless_core::VerificationPolicy::Replicate(count) => usize::from(*count),
            peerless_core::VerificationPolicy::Quorum { executions, .. } => {
                usize::from(*executions)
            }
        };
        if required == 0 {
            return Err(NodeError::Rejected(
                "verification requires at least one execution".into(),
            ));
        }
        let mut results = Vec::new();
        let mut executors = HashSet::new();
        for peer in peers {
            if results.len() >= required {
                break;
            }
            if let Ok((record, bytes)) =
                self.remote_execute_p2p(network, peer, task.clone(), component, input)
            {
                if executors.insert(record.executor.clone()) {
                    results.push((record, bytes));
                }
            }
        }
        let outputs = results
            .iter()
            .map(|(record, _)| record.output)
            .collect::<Vec<_>>();
        let accepted_id = verify_outputs(&task.verification, &outputs)
            .map_err(|error| NodeError::Rejected(error.to_string()))?;
        let (accepted, output) = results
            .iter()
            .find(|(record, _)| record.output == accepted_id)
            .cloned()
            .ok_or(NodeError::UnexpectedResponse)?;
        Ok(VerifiedExecution {
            accepted,
            output,
            executions: results.into_iter().map(|(record, _)| record).collect(),
        })
    }
    pub fn remote_execute_p2p(
        &self,
        network: &P2pRpc,
        peer: PeerId,
        task: Task,
        component: &[u8],
        input: i32,
    ) -> Result<(ExecutionRecord, Vec<u8>), NodeError> {
        let observed_node = self
            .peer_capability_p2p(network, peer)
            .ok()
            .map(|capability| capability.node);
        let started = std::time::Instant::now();
        let result = self.remote_execute_via(task, component, input, |envelope| {
            let response = network.request(peer, envelope).map_err(NodeError::P2p)?;
            Self::ensure_peer_identity(&response, peer)?;
            Ok(response)
        });
        if let Some(node) = observed_node {
            match &result {
                Ok(_) => self
                    .inner
                    .metadata
                    .record_success(&node, started.elapsed().as_secs_f64() * 1000.0)?,
                Err(error) => {
                    let text = error.to_string();
                    self.inner.metadata.record_failure(
                        &node,
                        text.contains("invalid"),
                        text.contains("timeout"),
                    )?;
                }
            }
        }
        result
    }

    pub fn remote_execute_via(
        &self,
        task: Task,
        component: &[u8],
        input: i32,
        exchange: impl FnMut(SignedEnvelope) -> Result<SignedEnvelope, NodeError>,
    ) -> Result<(ExecutionRecord, Vec<u8>), NodeError> {
        self.remote_execute_bytes_via(task, component, &input.to_le_bytes(), exchange)
    }

    pub fn remote_execute_bytes_p2p(
        &self,
        network: &P2pRpc,
        peer: PeerId,
        task: Task,
        component: &[u8],
        input: &[u8],
    ) -> Result<(ExecutionRecord, Vec<u8>), NodeError> {
        self.remote_execute_bytes_via(task, component, input, |envelope| {
            let response = network.request(peer, envelope).map_err(NodeError::P2p)?;
            Self::ensure_peer_identity(&response, peer)?;
            Ok(response)
        })
    }

    fn remote_execute_bytes_via(
        &self,
        task: Task,
        component: &[u8],
        input: &[u8],
        mut exchange: impl FnMut(SignedEnvelope) -> Result<SignedEnvelope, NodeError>,
    ) -> Result<(ExecutionRecord, Vec<u8>), NodeError> {
        self.transfer_content_via(&mut exchange, task.component, component)?;
        self.transfer_content_via(&mut exchange, task.input, input)?;
        match self.exchange(
            &mut exchange,
            Message::TaskOffer {
                task: task.clone(),
                requester: self.node_id().clone(),
                expires_at: now() + 30_000,
            },
        )? {
            Message::TaskAccept { task_id } if task_id == task.task_id => {}
            Message::TaskReject { reason, .. } => return Err(NodeError::Rejected(reason)),
            _ => return Err(NodeError::UnexpectedResponse),
        }
        let record = match self.exchange(
            &mut exchange,
            Message::TaskCommit {
                task_id: task.task_id.clone(),
            },
        )? {
            Message::TaskResult(value)
                if value.verify(&self.inner.temporary)?
                    && value.record.task_id == task.task_id
                    && value.record.component == task.component
                    && value.record.input == task.input =>
            {
                value.record
            }
            Message::TaskResult(_) => {
                return Err(NodeError::Rejected(
                    "invalid execution record signature".into(),
                ))
            }
            Message::TaskReject { reason, .. } => return Err(NodeError::Rejected(reason)),
            _ => return Err(NodeError::UnexpectedResponse),
        };
        let bytes = match self.exchange(&mut exchange, Message::GetContent(record.output))? {
            Message::Content { id, bytes } if id == record.output && id.verify(&bytes) => bytes,
            _ => return Err(NodeError::UnexpectedResponse),
        };
        Ok((record, bytes))
    }
    fn send(&self, address: SocketAddr, message: Message) -> Result<Message, NodeError> {
        self.exchange(&mut |envelope| Ok(request(address, &envelope)?), message)
    }
    fn send_p2p(
        &self,
        network: &P2pRpc,
        peer: PeerId,
        message: Message,
    ) -> Result<Message, NodeError> {
        self.exchange(
            &mut |envelope| {
                let response = network.request(peer, envelope).map_err(NodeError::P2p)?;
                Self::ensure_peer_identity(&response, peer)?;
                Ok(response)
            },
            message,
        )
    }
    fn ensure_peer_identity(response: &SignedEnvelope, peer: PeerId) -> Result<(), NodeError> {
        let public = libp2p::identity::PublicKey::try_decode_protobuf(&response.public_key)
            .map_err(|error| NodeError::P2p(error.to_string()))?;
        if public.to_peer_id() != peer {
            return Err(NodeError::P2p(
                "signed response identity differs from connected peer".into(),
            ));
        }
        Ok(())
    }
    fn exchange(
        &self,
        exchange: &mut impl FnMut(SignedEnvelope) -> Result<SignedEnvelope, NodeError>,
        message: Message,
    ) -> Result<Message, NodeError> {
        let envelope = SignedEnvelope::seal(&message, &self.inner.identity)?;
        Ok(exchange(envelope)?.open(&self.inner.temporary)?)
    }
    fn transfer_content_via(
        &self,
        exchange: &mut impl FnMut(SignedEnvelope) -> Result<SignedEnvelope, NodeError>,
        id: ContentId,
        bytes: &[u8],
    ) -> Result<(), NodeError> {
        if !id.verify(bytes) {
            return Err(NodeError::Rejected(
                "local content does not match task ContentId".into(),
            ));
        }
        if bytes.len() <= CONTENT_CHUNK_SIZE {
            return match self.exchange(
                exchange,
                Message::Content {
                    id,
                    bytes: bytes.to_vec(),
                },
            )? {
                Message::HasContent(found) if found == id => Ok(()),
                Message::TaskError { reason, .. } | Message::TaskReject { reason, .. } => {
                    Err(NodeError::Rejected(reason))
                }
                _ => Err(NodeError::UnexpectedResponse),
            };
        }
        match self.exchange(
            exchange,
            Message::ContentStart {
                id,
                total_size: bytes.len() as u64,
                chunk_size: CONTENT_CHUNK_SIZE as u32,
            },
        )? {
            Message::HasContent(found) if found == id => {}
            _ => return Err(NodeError::UnexpectedResponse),
        }
        for (index, chunk) in bytes.chunks(CONTENT_CHUNK_SIZE).enumerate() {
            let chunk_hash = ContentId::of(chunk);
            match self.exchange(
                exchange,
                Message::ContentChunk {
                    id,
                    index: index as u32,
                    bytes: chunk.to_vec(),
                    chunk_hash,
                },
            )? {
                Message::HasContent(found) if found == chunk_hash => {}
                Message::TaskError { reason, .. } | Message::TaskReject { reason, .. } => {
                    return Err(NodeError::Rejected(reason))
                }
                _ => return Err(NodeError::UnexpectedResponse),
            }
        }
        match self.exchange(exchange, Message::ContentComplete { id })? {
            Message::HasContent(found) if found == id => Ok(()),
            Message::TaskError { reason, .. } | Message::TaskReject { reason, .. } => {
                Err(NodeError::Rejected(reason))
            }
            _ => Err(NodeError::UnexpectedResponse),
        }
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn permission_for(message: &Message) -> &'static str {
    match message {
        Message::GetCapability | Message::Capability(_) => "observe",
        Message::HasContent(_)
        | Message::CheckContent(_)
        | Message::GetContent(_)
        | Message::Content { .. }
        | Message::ContentStart { .. }
        | Message::ContentChunk { .. }
        | Message::ContentComplete { .. } => "content",
        Message::TaskOffer { .. }
        | Message::TaskAccept { .. }
        | Message::TaskReject { .. }
        | Message::TaskCommit { .. }
        | Message::TaskStarted { .. }
        | Message::TaskError { .. }
        | Message::TaskCancel { .. }
        | Message::TaskResult(_) => "execute",
        Message::StateSnapshot { .. } => "state",
        Message::LedgerBlock { .. } => "ledger",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peerless_core::{NetworkRequirement, Requirements, RuntimeRequirement, VerificationPolicy};
    const DOUBLE: &[u8] = b"\0asm\x01\0\0\0\x01\x06\x01\x60\x01\x7f\x01\x7f\x03\x02\x01\x00\x07\x07\x01\x03run\x00\x00\x0a\x09\x01\x07\x00\x20\x00\x41\x02\x6c\x0b";
    fn task(id: &str) -> Task {
        Task {
            task_id: id.into(),
            component: ContentId::of(DOUBLE),
            input: ContentId::of(&21i32.to_le_bytes()),
            requirements: Requirements {
                minimum_memory: 0,
                minimum_storage: 0,
                runtime: RuntimeRequirement("wasmtime-component-v1".into()),
                estimated_cpu_cost: 1,
                network: NetworkRequirement::None,
            },
            verification: VerificationPolicy::TrustExecutor,
            deadline: None,
        }
    }
    #[test]
    fn remote_execution_flow_returns_verified_signed_cas_output() {
        let root = tempfile::tempdir().unwrap();
        let requester = PeerlessNode::open(root.path().join("a")).unwrap();
        let executor = PeerlessNode::open(root.path().join("b")).unwrap();
        let component = ContentId::of(DOUBLE);
        let input = ContentId::of(&21i32.to_le_bytes());
        let task = Task {
            task_id: "t1".into(),
            component,
            input,
            requirements: Requirements {
                minimum_memory: 0,
                minimum_storage: 0,
                runtime: RuntimeRequirement("wasmtime-component-v1".into()),
                estimated_cpu_cost: 1,
                network: NetworkRequirement::None,
            },
            verification: VerificationPolicy::TrustExecutor,
            deadline: None,
        };
        let (record, bytes) = requester
            .remote_execute_via(task, DOUBLE, 21, |envelope| executor.handle(envelope))
            .unwrap();
        assert_eq!(record.executor, *executor.node_id());
        assert_eq!(bytes, 42i32.to_le_bytes());
        assert!(record.output.verify(&bytes));
        assert_eq!(executor.ledger_height(), 1);
    }

    #[test]
    fn libp2p_quic_remote_execution_end_to_end() {
        let root = tempfile::tempdir().unwrap();
        let requester = PeerlessNode::open(root.path().join("requester")).unwrap();
        let executor = PeerlessNode::open(root.path().join("executor")).unwrap();
        let listen: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let requester_network = requester.serve_p2p(listen.clone()).unwrap();
        let executor_network = executor.serve_p2p(listen).unwrap();
        requester_network
            .add_peer(
                executor_network.peer_id(),
                executor_network.listen_address().clone(),
            )
            .unwrap();
        let capability = requester
            .peer_capability_p2p(&requester_network, executor_network.peer_id())
            .unwrap();
        assert_eq!(capability.node, *executor.node_id());
        let replicated = requester.put(b"replicated content").unwrap();
        let replicas = requester
            .replicate_p2p(
                &requester_network,
                [executor_network.peer_id()],
                replicated,
                ReplicationPolicy {
                    minimum_replicas: 2,
                    target_replicas: 2,
                },
            )
            .unwrap();
        assert_eq!(replicas, vec![executor_network.peer_id()]);
        assert_eq!(
            executor.inner.cas.get(replicated).unwrap(),
            b"replicated content"
        );
        let provided = executor
            .put_and_provide(&executor_network, b"provider content")
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert_eq!(
            requester.fetch_p2p(&requester_network, provided).unwrap(),
            b"provider content"
        );
        let task = Task {
            task_id: "quic-task".into(),
            component: ContentId::of(DOUBLE),
            input: ContentId::of(&21i32.to_le_bytes()),
            requirements: Requirements {
                minimum_memory: 0,
                minimum_storage: 0,
                runtime: RuntimeRequirement("wasmtime-component-v1".into()),
                estimated_cpu_cost: 1,
                network: NetworkRequirement::None,
            },
            verification: VerificationPolicy::TrustExecutor,
            deadline: None,
        };
        let (record, bytes) = requester
            .remote_execute_p2p(
                &requester_network,
                executor_network.peer_id(),
                task,
                DOUBLE,
                21,
            )
            .unwrap();
        assert_eq!(record.executor, *executor.node_id());
        assert_eq!(bytes, 42i32.to_le_bytes());
        assert!(record.output.verify(&bytes));
    }

    #[test]
    fn execute_best_offloads_to_an_eligible_peer_before_using_local_compute() {
        let root = tempfile::tempdir().unwrap();
        let requester = PeerlessNode::open(root.path().join("offload-requester")).unwrap();
        let executor = PeerlessNode::open(root.path().join("offload-executor")).unwrap();
        let listen: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let requester_network = requester.serve_p2p(listen.clone()).unwrap();
        let executor_network = executor.serve_p2p(listen).unwrap();
        requester_network
            .add_peer(
                executor_network.peer_id(),
                executor_network.listen_address().clone(),
            )
            .unwrap();

        let (record, output) = requester
            .execute_best(&requester_network, task("peer-first"), DOUBLE, 21)
            .unwrap();
        assert_eq!(record.executor, *executor.node_id());
        assert_ne!(record.executor, *requester.node_id());
        assert_eq!(output, 42i32.to_le_bytes());
        assert_eq!(requester.ledger_height(), 0);
        assert_eq!(executor.ledger_height(), 1);
    }

    #[test]
    fn adding_two_peers_spreads_tasks_and_keeps_requester_execution_at_zero() {
        let root = tempfile::tempdir().unwrap();
        let requester = PeerlessNode::open(root.path().join("pool-requester")).unwrap();
        let first = PeerlessNode::open(root.path().join("pool-first")).unwrap();
        let second = PeerlessNode::open(root.path().join("pool-second")).unwrap();
        let listen: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let requester_network = requester.serve_p2p(listen.clone()).unwrap();
        let first_network = first.serve_p2p(listen.clone()).unwrap();
        let second_network = second.serve_p2p(listen).unwrap();
        for network in [&first_network, &second_network] {
            requester_network
                .add_peer(network.peer_id(), network.listen_address().clone())
                .unwrap();
        }

        let mut assignments = HashMap::new();
        for index in 0..6 {
            let (record, output) = requester
                .execute_best(
                    &requester_network,
                    task(&format!("pooled-{index}")),
                    DOUBLE,
                    21,
                )
                .unwrap();
            assert_ne!(record.executor, *requester.node_id());
            assert_eq!(output, 42i32.to_le_bytes());
            *assignments.entry(record.executor).or_insert(0u64) += 1;
        }
        assert_eq!(requester.ledger_height(), 0);
        assert_eq!(assignments.len(), 2);
        assert_eq!(first.ledger_height() + second.ledger_height(), 6);
        assert!(first.ledger_height() > 0);
        assert!(second.ledger_height() > 0);
    }

    #[test]
    fn accepted_offer_reserves_capacity_and_retry_does_not_double_reserve() {
        let root = tempfile::tempdir().unwrap();
        let requester = NodeIdentity::load_or_generate(root.path().join("requester-id")).unwrap();
        let executor = PeerlessNode::open(root.path().join("reserved-executor")).unwrap();
        let offered = task("reserved");
        executor.inner.cas.put(DOUBLE).unwrap();
        executor.inner.cas.put(&21i32.to_le_bytes()).unwrap();
        let before = executor.capability();
        assert_eq!(before.task_slots, 1);

        let offer = Message::TaskOffer {
            task: offered.clone(),
            requester: requester.node_id().clone(),
            expires_at: now() + 30_000,
        };
        let response = executor
            .handle(SignedEnvelope::seal(&offer, &requester).unwrap())
            .unwrap()
            .open(&executor.inner.temporary)
            .unwrap();
        assert!(matches!(response, Message::TaskAccept { .. }));
        let reserved = executor.capability();
        assert_eq!(reserved.task_slots, 0);
        assert!(
            reserved.available_memory
                <= before
                    .available_memory
                    .saturating_sub(peerless_compute::DEFAULT_TASK_MEMORY_LIMIT)
                    .saturating_add(8 * 1024 * 1024)
        );

        let retry = executor
            .handle(SignedEnvelope::seal(&offer, &requester).unwrap())
            .unwrap()
            .open(&executor.inner.temporary)
            .unwrap();
        assert!(matches!(retry, Message::TaskAccept { .. }));
        assert_eq!(executor.capability().task_slots, 0);

        let second = Message::TaskOffer {
            task: task("reserved-second"),
            requester: requester.node_id().clone(),
            expires_at: now() + 30_000,
        };
        let rejected = executor
            .handle(SignedEnvelope::seal(&second, &requester).unwrap())
            .unwrap()
            .open(&executor.inner.temporary)
            .unwrap();
        assert!(matches!(rejected, Message::TaskReject { .. }));

        let commit = Message::TaskCommit {
            task_id: offered.task_id,
        };
        let completed = executor
            .handle(SignedEnvelope::seal(&commit, &requester).unwrap())
            .unwrap()
            .open(&executor.inner.temporary)
            .unwrap();
        assert!(matches!(completed, Message::TaskResult(_)));
        assert_eq!(executor.capability().task_slots, 1);
    }

    #[test]
    fn failed_execution_and_expired_lease_release_reserved_capacity() {
        let root = tempfile::tempdir().unwrap();
        let node = PeerlessNode::open(root.path()).unwrap();
        let invalid_component = b"not-webassembly";
        let mut invalid_task = task("invalid-wasm-release");
        invalid_task.component = ContentId::of(invalid_component);
        let result = node.execute_local(invalid_task, invalid_component, 21);
        assert!(result.is_err());
        assert_eq!(node.capability().task_slots, 1);

        node.inner
            .pending
            .lock()
            .expect("task lock poisoned")
            .insert(
                "expired-reservation".into(),
                PendingTask {
                    task: task("expired-reservation"),
                    requester: node.node_id().clone(),
                    lease_expires_at: now().saturating_sub(1),
                    running: false,
                },
            );
        assert_eq!(node.capability().task_slots, 1);
        assert!(node
            .inner
            .pending
            .lock()
            .expect("task lock poisoned")
            .is_empty());
    }

    #[test]
    fn executor_rechecks_resources_and_requester_identity() {
        let root = tempfile::tempdir().unwrap();
        let requester = PeerlessNode::open(root.path().join("requester")).unwrap();
        let other = PeerlessNode::open(root.path().join("other")).unwrap();
        let executor = PeerlessNode::open(root.path().join("executor")).unwrap();
        executor.put(DOUBLE).unwrap();
        executor.put(&21i32.to_le_bytes()).unwrap();

        let mut impossible = task("too-large");
        impossible.requirements.minimum_memory = u64::MAX;
        let response: Message = executor
            .handle(
                SignedEnvelope::seal(
                    &Message::TaskOffer {
                        task: impossible,
                        requester: requester.node_id().clone(),
                        expires_at: now() + 1_000,
                    },
                    &requester.inner.identity,
                )
                .unwrap(),
            )
            .unwrap()
            .open(root.path())
            .unwrap();
        assert!(matches!(response, Message::TaskReject { .. }));

        let response: Message = executor
            .handle(
                SignedEnvelope::seal(
                    &Message::TaskOffer {
                        task: task("spoofed"),
                        requester: other.node_id().clone(),
                        expires_at: now() + 1_000,
                    },
                    &requester.inner.identity,
                )
                .unwrap(),
            )
            .unwrap()
            .open(root.path())
            .unwrap();
        assert!(matches!(response, Message::TaskReject { .. }));
    }

    #[test]
    fn only_original_requester_can_commit_an_accepted_task() {
        let root = tempfile::tempdir().unwrap();
        let requester = PeerlessNode::open(root.path().join("requester")).unwrap();
        let attacker = PeerlessNode::open(root.path().join("attacker")).unwrap();
        let executor = PeerlessNode::open(root.path().join("executor")).unwrap();
        executor.put(DOUBLE).unwrap();
        executor.put(&21i32.to_le_bytes()).unwrap();
        let offered = task("owned");
        let offer = SignedEnvelope::seal(
            &Message::TaskOffer {
                task: offered,
                requester: requester.node_id().clone(),
                expires_at: now() + 30_000,
            },
            &requester.inner.identity,
        )
        .unwrap();
        assert!(matches!(
            executor
                .handle(offer)
                .unwrap()
                .open::<Message>(root.path())
                .unwrap(),
            Message::TaskAccept { .. }
        ));

        let stolen = SignedEnvelope::seal(
            &Message::TaskCommit {
                task_id: "owned".into(),
            },
            &attacker.inner.identity,
        )
        .unwrap();
        assert!(matches!(
            executor
                .handle_or_reject(stolen)
                .open::<Message>(root.path())
                .unwrap(),
            Message::TaskReject { .. }
        ));

        let legitimate = SignedEnvelope::seal(
            &Message::TaskCommit {
                task_id: "owned".into(),
            },
            &requester.inner.identity,
        )
        .unwrap();
        let first = match executor
            .handle(legitimate)
            .unwrap()
            .open::<Message>(root.path())
            .unwrap()
        {
            Message::TaskResult(result) => result,
            other => panic!("unexpected response: {other:?}"),
        };

        let retry_offer = SignedEnvelope::seal(
            &Message::TaskOffer {
                task: task("owned"),
                requester: requester.node_id().clone(),
                expires_at: now() + 30_000,
            },
            &requester.inner.identity,
        )
        .unwrap();
        assert!(matches!(
            executor
                .handle(retry_offer)
                .unwrap()
                .open::<Message>(root.path())
                .unwrap(),
            Message::TaskAccept { .. }
        ));
        let retry_commit = SignedEnvelope::seal(
            &Message::TaskCommit {
                task_id: "owned".into(),
            },
            &requester.inner.identity,
        )
        .unwrap();
        let second = match executor
            .handle(retry_commit)
            .unwrap()
            .open::<Message>(root.path())
            .unwrap()
        {
            Message::TaskResult(result) => result,
            other => panic!("unexpected response: {other:?}"),
        };
        assert_eq!(first, second, "retry must replay the cached result");
    }

    #[test]
    fn requester_rejects_a_validly_signed_but_unrelated_result() {
        let root = tempfile::tempdir().unwrap();
        let requester = PeerlessNode::open(root.path().join("requester")).unwrap();
        let executor = PeerlessNode::open(root.path().join("executor")).unwrap();
        let expected = task("expected");
        let wrong_record = ExecutionRecord {
            task_id: "different".into(),
            executor: executor.node_id().clone(),
            component: ContentId::of(b"different component"),
            input: expected.input,
            output: ContentId::of(&42i32.to_le_bytes()),
            execution_hash: ContentId::of(b"unrelated execution"),
            started_at: now(),
            completed_at: now(),
        };
        let mut calls = 0;
        let result = requester.remote_execute_via(expected, DOUBLE, 21, |envelope| {
            calls += 1;
            if calls == 4 {
                Ok(SignedEnvelope::seal(
                    &Message::TaskResult(SignedExecutionRecord::seal(
                        wrong_record.clone(),
                        &executor.inner.identity,
                    )?),
                    &executor.inner.identity,
                )?)
            } else {
                executor.handle(envelope)
            }
        });
        assert!(matches!(result, Err(NodeError::Rejected(_))));
    }

    #[test]
    fn node_exposes_persistent_state_storage_and_task_observability() {
        let root = tempfile::tempdir().unwrap();
        let node = PeerlessNode::open(root.path()).unwrap();
        let mut document = node.state("settings").unwrap();
        document.put("mode", "distributed").unwrap();
        document.save().unwrap();
        node.put(b"observable").unwrap();
        let (objects, bytes) = node.storage_stats().unwrap();
        assert_eq!(objects, 1);
        assert_eq!(bytes, b"observable".len() as u64);
        assert_eq!(node.task_counts(), (0, 0));
        node.inner
            .metadata
            .task("persisted-task", "completed", Some(node.node_id()), now())
            .unwrap();
        node.inner
            .metadata
            .event(now(), "test.event", "persisted-task")
            .unwrap();
        node.inner
            .metadata
            .record_success(node.node_id(), 25.0)
            .unwrap();
        node.inner
            .metadata
            .peer("libp2p-peer", node.node_id(), "/ip4/127.0.0.1/tcp/1", now())
            .unwrap();
        drop(document);
        drop(node);
        let reopened = PeerlessNode::open(root.path()).unwrap();
        assert_eq!(
            reopened
                .state("settings")
                .unwrap()
                .get("mode")
                .unwrap()
                .as_deref(),
            Some("distributed")
        );
        assert_eq!(reopened.metadata_counts().unwrap(), (1, 1));
        let reputation = reopened.peer_reputation(reopened.node_id()).unwrap();
        assert_eq!(reputation.success, 1);
        assert_eq!(reputation.average_latency_ms, 25.0);
        assert_eq!(reopened.persisted_peer_count().unwrap(), 1);
    }

    #[test]
    fn concurrent_reputation_updates_are_not_lost() {
        let root = tempfile::tempdir().unwrap();
        let node = PeerlessNode::open(root.path()).unwrap();
        let peer = node.node_id().clone();
        let mut workers = Vec::new();
        for _ in 0..8 {
            let node = node.clone();
            let peer = peer.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    node.inner.metadata.record_success(&peer, 10.0).unwrap();
                    node.inner
                        .metadata
                        .record_failure(&peer, false, false)
                        .unwrap();
                    node.inner
                        .metadata
                        .record_failure(&peer, true, false)
                        .unwrap();
                    node.inner
                        .metadata
                        .record_failure(&peer, false, true)
                        .unwrap();
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let reputation = node.peer_reputation(&peer).unwrap();
        assert_eq!(reputation.success, 400);
        assert_eq!(reputation.failure, 400);
        assert_eq!(reputation.invalid_result, 400);
        assert_eq!(reputation.timeout, 400);
        assert_eq!(reputation.average_latency_ms, 10.0);
    }

    #[test]
    fn completed_task_idempotency_survives_executor_restart() {
        let root = tempfile::tempdir().unwrap();
        let requester = PeerlessNode::open(root.path().join("restart-requester")).unwrap();
        let executor_path = root.path().join("restart-executor");
        let executor = PeerlessNode::open(&executor_path).unwrap();
        let listen: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let requester_network = requester.serve_p2p(listen.clone()).unwrap();
        let executor_network = executor.serve_p2p(listen.clone()).unwrap();
        requester_network
            .add_peer(
                executor_network.peer_id(),
                executor_network.listen_address().clone(),
            )
            .unwrap();
        let original = requester
            .remote_execute_p2p(
                &requester_network,
                executor_network.peer_id(),
                task("restart-idempotent"),
                DOUBLE,
                21,
            )
            .unwrap()
            .0;
        let executor_peer = executor_network.peer_id();
        drop(executor_network);
        drop(executor);
        std::thread::sleep(std::time::Duration::from_millis(100));

        let reopened = PeerlessNode::open(&executor_path).unwrap();
        let reopened_network = reopened.serve_p2p(listen).unwrap();
        assert_eq!(reopened_network.peer_id(), executor_peer);
        requester_network
            .add_peer(executor_peer, reopened_network.listen_address().clone())
            .unwrap();
        let replayed = requester
            .remote_execute_p2p(
                &requester_network,
                executor_peer,
                task("restart-idempotent"),
                DOUBLE,
                21,
            )
            .unwrap()
            .0;
        assert_eq!(replayed, original);
        assert_eq!(reopened.ledger_height(), 1);
    }

    #[test]
    fn public_facade_hides_storage_state_and_local_placement_details() {
        let root = tempfile::tempdir().unwrap();
        let runtime = Peerless::builder().storage(root.path()).build().unwrap();
        assert_eq!(
            runtime.content().put(b"api").unwrap(),
            ContentId::of(b"api")
        );
        let mut state = runtime.state().open("api-state").unwrap();
        state.put("ready", "yes").unwrap();
        state.save().unwrap();
        let network = runtime.start().unwrap();
        let (record, output) = runtime
            .compute()
            .execute(&network, task("local-best"), DOUBLE, 21)
            .unwrap();
        assert_eq!(output, 42i32.to_le_bytes());
        assert_eq!(record.executor, *runtime.node().node_id());
        assert_eq!(runtime.ledger().height(), 1);
        let proof = runtime.ledger().proof("local-best").unwrap();
        assert!(proof.proof.verify(proof.event.hash().unwrap(), proof.root));
    }

    #[test]
    fn permissioned_node_rejects_non_members_and_enforces_permissions() {
        let root = tempfile::tempdir().unwrap();
        let issuer = PeerlessNode::open(root.path().join("issuer")).unwrap();
        let member = PeerlessNode::open(root.path().join("member")).unwrap();
        let attacker = PeerlessNode::open(root.path().join("attacker")).unwrap();
        let executor = PeerlessNode::open(root.path().join("executor")).unwrap();
        let certificate = Membership::issue(
            "mesh".into(),
            member.node_id().clone(),
            vec!["observe".into()],
            None,
            &issuer.inner.identity,
        )
        .unwrap();
        executor
            .enforce_membership(
                "mesh",
                &[certificate],
                &std::collections::HashSet::from([issuer.node_id().clone()]),
                now(),
            )
            .unwrap();

        let member_response: Message = executor
            .handle(SignedEnvelope::seal(&Message::GetCapability, &member.inner.identity).unwrap())
            .unwrap()
            .open(root.path())
            .unwrap();
        assert!(matches!(member_response, Message::Capability(_)));
        let attacker_response: Message = executor
            .handle(
                SignedEnvelope::seal(&Message::GetCapability, &attacker.inner.identity).unwrap(),
            )
            .unwrap()
            .open(root.path())
            .unwrap();
        assert!(matches!(attacker_response, Message::TaskReject { .. }));
        let forbidden_content: Message = executor
            .handle(
                SignedEnvelope::seal(
                    &Message::Content {
                        id: ContentId::of(b"x"),
                        bytes: b"x".to_vec(),
                    },
                    &member.inner.identity,
                )
                .unwrap(),
            )
            .unwrap()
            .open(root.path())
            .unwrap();
        assert!(matches!(forbidden_content, Message::TaskReject { .. }));
    }

    #[test]
    fn crdt_state_converges_over_signed_gossipsub_after_partition() {
        let root = tempfile::tempdir().unwrap();
        let first = PeerlessNode::open(root.path().join("first")).unwrap();
        let second = PeerlessNode::open(root.path().join("second")).unwrap();
        let listen: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let first_network = first.serve_p2p(listen.clone()).unwrap();
        let second_network = second.serve_p2p(listen).unwrap();
        first_network
            .add_peer(
                second_network.peer_id(),
                second_network.listen_address().clone(),
            )
            .unwrap();
        second_network
            .add_peer(
                first_network.peer_id(),
                first_network.listen_address().clone(),
            )
            .unwrap();
        first
            .peer_capability_p2p(&first_network, second_network.peer_id())
            .unwrap();
        first_network.subscribe("peerless/state/v1").unwrap();
        second_network.subscribe("peerless/state/v1").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));

        let mut initial = first.state("shared").unwrap();
        let bootstrap = SignedEnvelope::seal(
            &Message::StateSnapshot {
                document: "shared".into(),
                snapshot: initial.snapshot(),
            },
            &first.inner.identity,
        )
        .unwrap();
        second.handle(bootstrap).unwrap();
        initial.put("from-first", "A").unwrap();
        let mut remote = second.state("shared").unwrap();
        remote.put("from-second", "B").unwrap();
        first
            .publish_state(&first_network, "shared", &mut initial)
            .unwrap();
        second
            .publish_state(&second_network, "shared", &mut remote)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert_eq!(first.merge_state_gossip(&first_network).unwrap(), 1);
        assert_eq!(second.merge_state_gossip(&second_network).unwrap(), 1);
        for node in [&first, &second] {
            let document = node.state("shared").unwrap();
            assert_eq!(document.get("from-first").unwrap().as_deref(), Some("A"));
            assert_eq!(document.get("from-second").unwrap().as_deref(), Some("B"));
        }
    }

    #[test]
    fn quorum_finalized_ledger_block_replicates_over_gossip() {
        let root = tempfile::tempdir().unwrap();
        let first = PeerlessNode::open(root.path().join("first-ledger")).unwrap();
        let second = PeerlessNode::open(root.path().join("second-ledger")).unwrap();
        let members =
            std::collections::HashSet::from([first.node_id().clone(), second.node_id().clone()]);
        let consensus = QuorumConsensus::new("mesh", members, 2).unwrap();
        let event = SignedEvent::seal(
            LedgerEvent::TaskCreated {
                task_id: "distributed".into(),
            },
            &first.inner.identity,
        )
        .unwrap();
        let mut block = first
            .inner
            .ledger
            .lock()
            .unwrap()
            .next_block(vec![event], now(), "mesh")
            .unwrap();
        consensus
            .finalize(&mut block, &[&first.inner.identity, &second.inner.identity])
            .unwrap();
        first
            .append_ledger_block(block.clone(), &consensus)
            .unwrap();

        let listen: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let first_network = first.serve_p2p(listen.clone()).unwrap();
        let second_network = second.serve_p2p(listen).unwrap();
        first_network
            .add_peer(
                second_network.peer_id(),
                second_network.listen_address().clone(),
            )
            .unwrap();
        second_network
            .add_peer(
                first_network.peer_id(),
                first_network.listen_address().clone(),
            )
            .unwrap();
        first
            .peer_capability_p2p(&first_network, second_network.peer_id())
            .unwrap();
        first_network.subscribe("peerless/ledger/v1").unwrap();
        second_network.subscribe("peerless/ledger/v1").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        first.publish_ledger_block(&first_network, &block).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert_eq!(
            second
                .merge_ledger_gossip(&second_network, &consensus)
                .unwrap(),
            1
        );
        assert_eq!(second.ledger_height(), 1);
    }

    #[test]
    fn large_content_is_chunked_and_corrupt_chunks_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let requester = PeerlessNode::open(root.path().join("chunk-requester")).unwrap();
        let executor = PeerlessNode::open(root.path().join("chunk-executor")).unwrap();
        let bytes = (0..(CONTENT_CHUNK_SIZE * 3 + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let id = ContentId::of(&bytes);
        requester
            .transfer_content_via(&mut |envelope| executor.handle(envelope), id, &bytes)
            .unwrap();
        assert_eq!(executor.inner.cas.get(id).unwrap(), bytes);

        let bad_id = ContentId::of(b"complete object");
        let start = SignedEnvelope::seal(
            &Message::ContentStart {
                id: bad_id,
                total_size: 4,
                chunk_size: CONTENT_CHUNK_SIZE as u32,
            },
            &requester.inner.identity,
        )
        .unwrap();
        executor.handle(start).unwrap();
        let corrupt = SignedEnvelope::seal(
            &Message::ContentChunk {
                id: bad_id,
                index: 0,
                bytes: b"evil".to_vec(),
                chunk_hash: ContentId::of(b"good"),
            },
            &requester.inner.identity,
        )
        .unwrap();
        let response: Message = executor.handle(corrupt).unwrap().open(root.path()).unwrap();
        assert!(matches!(response, Message::TaskError { .. }));
        assert!(executor
            .inner
            .uploads
            .lock()
            .expect("upload lock poisoned")
            .is_empty());

        let tiny_chunks: Message = executor
            .handle(
                SignedEnvelope::seal(
                    &Message::ContentStart {
                        id: ContentId::of(b"allocation-attack"),
                        total_size: MAX_CONTENT_SIZE,
                        chunk_size: 1,
                    },
                    &requester.inner.identity,
                )
                .unwrap(),
            )
            .unwrap()
            .open(root.path())
            .unwrap();
        assert!(matches!(tiny_chunks, Message::TaskError { .. }));

        let large_id = ContentId::of(b"large-reservation");
        let reserved: Message = executor
            .handle(
                SignedEnvelope::seal(
                    &Message::ContentStart {
                        id: large_id,
                        total_size: MAX_IN_FLIGHT_UPLOAD_BYTES,
                        chunk_size: CONTENT_CHUNK_SIZE as u32,
                    },
                    &requester.inner.identity,
                )
                .unwrap(),
            )
            .unwrap()
            .open(root.path())
            .unwrap();
        assert!(matches!(reserved, Message::HasContent(id) if id == large_id));
        let over_budget: Message = executor
            .handle(
                SignedEnvelope::seal(
                    &Message::ContentStart {
                        id: ContentId::of(b"one-byte-too-many"),
                        total_size: 1,
                        chunk_size: 1,
                    },
                    &requester.inner.identity,
                )
                .unwrap(),
            )
            .unwrap()
            .open(root.path())
            .unwrap();
        assert!(matches!(over_budget, Message::TaskError { .. }));
    }

    #[test]
    fn invitation_persists_membership_and_bootstraps_the_issuer() {
        let root = tempfile::tempdir().unwrap();
        let issuer = PeerlessNode::open(root.path().join("invite-issuer")).unwrap();
        let member_path = root.path().join("invite-member");
        let member = PeerlessNode::open(&member_path).unwrap();
        let issuer_network = issuer
            .serve_p2p("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let bootstrap = format!(
            "{}/p2p/{}",
            issuer_network.listen_address(),
            issuer_network.peer_id()
        );
        let invitation = issuer
            .issue_invitation(
                "mesh",
                member.node_id().clone(),
                vec!["*".into()],
                None,
                vec![bootstrap],
            )
            .unwrap();
        member.install_invitation(&invitation, now()).unwrap();
        drop(member);

        let reopened = PeerlessNode::open(&member_path).unwrap();
        let member_network = reopened
            .serve_p2p("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        assert_eq!(
            reopened
                .apply_invitation_bootstrap(&member_network, &invitation)
                .unwrap(),
            1
        );
        let capability = reopened
            .peer_capability_p2p(&member_network, issuer_network.peer_id())
            .unwrap();
        assert_eq!(capability.node, *issuer.node_id());
    }

    #[test]
    fn replication_is_repaired_after_an_executor_disappears() {
        let root = tempfile::tempdir().unwrap();
        let owner = PeerlessNode::open(root.path().join("repair-owner")).unwrap();
        let b = PeerlessNode::open(root.path().join("repair-b")).unwrap();
        let c = PeerlessNode::open(root.path().join("repair-c")).unwrap();
        let d = PeerlessNode::open(root.path().join("repair-d")).unwrap();
        let listen: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let owner_network = owner.serve_p2p(listen.clone()).unwrap();
        let b_network = b.serve_p2p(listen.clone()).unwrap();
        let c_network = c.serve_p2p(listen.clone()).unwrap();
        let d_network = d.serve_p2p(listen).unwrap();
        for network in [&b_network, &c_network, &d_network] {
            owner_network
                .add_peer(network.peer_id(), network.listen_address().clone())
                .unwrap();
        }
        let id = owner.put(b"repairable").unwrap();
        let policy = ReplicationPolicy {
            minimum_replicas: 2,
            target_replicas: 3,
        };
        let initial = owner
            .replicate_p2p(
                &owner_network,
                [b_network.peer_id(), c_network.peer_id()],
                id,
                policy,
            )
            .unwrap();
        let departed = b_network.peer_id();
        let survivor = c_network.peer_id();
        let replacement = d_network.peer_id();
        let mut known = initial.into_iter().collect::<HashSet<_>>();
        drop(b_network);
        drop(b);
        std::thread::sleep(std::time::Duration::from_millis(200));

        let report = owner
            .repair_replication_p2p(&owner_network, id, policy, &mut known)
            .unwrap();
        assert!(!report.live_replicas.contains(&departed));
        assert!(report.live_replicas.contains(&survivor));
        assert!(report.live_replicas.contains(&replacement));
        assert_eq!(d.inner.cas.get(id).unwrap(), b"repairable");
    }

    #[test]
    fn replication_rejects_invalid_policy_and_unmet_minimum() {
        let root = tempfile::tempdir().unwrap();
        let owner = PeerlessNode::open(root.path().join("policy-owner")).unwrap();
        let network = owner
            .serve_p2p("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let id = owner.put(b"single-copy").unwrap();
        for policy in [
            ReplicationPolicy {
                minimum_replicas: 0,
                target_replicas: 0,
            },
            ReplicationPolicy {
                minimum_replicas: 2,
                target_replicas: 1,
            },
        ] {
            assert!(matches!(
                owner.replicate_p2p(&network, std::iter::empty::<PeerId>(), id, policy),
                Err(NodeError::InsufficientReplicas {
                    actual: 0,
                    minimum: _
                })
            ));
            assert!(matches!(
                owner.repair_replication_p2p(&network, id, policy, &mut HashSet::new()),
                Err(NodeError::InsufficientReplicas {
                    actual: 0,
                    minimum: _
                })
            ));
        }

        let valid_but_unmet = ReplicationPolicy {
            minimum_replicas: 2,
            target_replicas: 2,
        };
        assert!(matches!(
            owner.replicate_p2p(&network, std::iter::empty::<PeerId>(), id, valid_but_unmet),
            Err(NodeError::InsufficientReplicas {
                actual: 1,
                minimum: 2
            })
        ));
    }

    #[test]
    fn multi_executor_verification_replaces_a_departed_peer() {
        let root = tempfile::tempdir().unwrap();
        let requester = PeerlessNode::open(root.path().join("verify-requester")).unwrap();
        let dead = PeerlessNode::open(root.path().join("verify-dead")).unwrap();
        let a = PeerlessNode::open(root.path().join("verify-a")).unwrap();
        let b = PeerlessNode::open(root.path().join("verify-b")).unwrap();
        let c = PeerlessNode::open(root.path().join("verify-c")).unwrap();
        let listen: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let requester_network = requester.serve_p2p(listen.clone()).unwrap();
        let dead_network = dead.serve_p2p(listen.clone()).unwrap();
        let a_network = a.serve_p2p(listen.clone()).unwrap();
        let b_network = b.serve_p2p(listen.clone()).unwrap();
        let c_network = c.serve_p2p(listen).unwrap();
        for network in [&dead_network, &a_network, &b_network, &c_network] {
            requester_network
                .add_peer(network.peer_id(), network.listen_address().clone())
                .unwrap();
        }
        let departed = dead_network.peer_id();
        let peers = [
            departed,
            a_network.peer_id(),
            b_network.peer_id(),
            c_network.peer_id(),
        ];
        drop(dead_network);
        drop(dead);
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut replicated = task("replicated-real");
        replicated.verification = VerificationPolicy::Replicate(3);
        let verified = requester
            .execute_verified_p2p(&requester_network, peers, replicated, DOUBLE, 21)
            .unwrap();
        assert_eq!(verified.output, 42i32.to_le_bytes());
        assert_eq!(verified.executions.len(), 3);
        assert_eq!(
            verified
                .executions
                .iter()
                .map(|record| record.executor.clone())
                .collect::<HashSet<_>>()
                .len(),
            3
        );
        assert_eq!(a.ledger_height(), 1);
        assert_eq!(b.ledger_height(), 1);
        assert_eq!(c.ledger_height(), 1);
    }
}
