use futures::StreamExt;
use libp2p::{
    autonat, dcutr, gossipsub, identify,
    identity::Keypair,
    kad, mdns, noise, ping, relay, request_response,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
};
use peerless_protocol::SignedEnvelope;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc as std_mpsc, Arc, RwLock,
    },
    thread,
    time::Duration,
};
use tokio::sync::mpsc;

type GossipMessage = (String, PeerId, Vec<u8>);

#[derive(NetworkBehaviour)]
struct RelayOnlyBehaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    relay: relay::Behaviour,
}

/// A dedicated circuit-relay v2 service. It intentionally has no relay-client
/// behaviour, keeping HOP/STOP negotiation unambiguous.
pub struct CircuitRelay {
    peer_id: PeerId,
    listen_address: Multiaddr,
    reservations: Arc<AtomicU64>,
    circuits: Arc<AtomicU64>,
    shutdown: mpsc::UnboundedSender<()>,
}

impl CircuitRelay {
    pub fn start(keypair: Keypair, listen_address: Multiaddr) -> Result<Self, String> {
        let peer_id = keypair.public().to_peer_id();
        let relay_public_key = keypair.public();
        let reservations = Arc::new(AtomicU64::new(0));
        let circuits = Arc::new(AtomicU64::new(0));
        let reservations_task = Arc::clone(&reservations);
        let circuits_task = Arc::clone(&circuits);
        let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
        let (shutdown, mut shutdown_rx) = mpsc::unbounded_channel();
        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime creation failed");
            runtime.block_on(async move {
                let mut swarm = SwarmBuilder::with_existing_identity(keypair)
                    .with_tokio()
                    .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
                    .expect("relay TCP transport initialisation failed")
                    .with_quic()
                    .with_behaviour(move |_| RelayOnlyBehaviour {
                        ping: ping::Behaviour::new(ping::Config::new()),
                        identify: identify::Behaviour::new(identify::Config::new("/peerless-relay/1".into(), relay_public_key)),
                        relay: relay::Behaviour::new(peer_id, relay::Config::default()),
                    })
                    .expect("relay behaviour creation failed")
                    .build();
                swarm.listen_on(listen_address).expect("relay listen failed");
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => break,
                        event = swarm.select_next_some() => match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                swarm.add_external_address(address.clone());
                                let _ = ready_tx.try_send(address);
                            }
                            SwarmEvent::Behaviour(RelayOnlyBehaviourEvent::Relay(relay::Event::ReservationReqAccepted { .. })) => { reservations_task.fetch_add(1, Ordering::Relaxed); }
                            SwarmEvent::Behaviour(RelayOnlyBehaviourEvent::Relay(relay::Event::CircuitReqAccepted { .. })) => { circuits_task.fetch_add(1, Ordering::Relaxed); }
                            _ => {}
                        }
                    }
                }
            });
        });
        let listen_address = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            peer_id,
            listen_address,
            reservations,
            circuits,
            shutdown,
        })
    }
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub fn listen_address(&self) -> &Multiaddr {
        &self.listen_address
    }
    pub fn reservations(&self) -> u64 {
        self.reservations.load(Ordering::Relaxed)
    }
    pub fn circuits(&self) -> u64 {
        self.circuits.load(Ordering::Relaxed)
    }
}

impl Drop for CircuitRelay {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    mdns: Toggle<mdns::tokio::Behaviour>,
    rpc: request_response::cbor::Behaviour<SignedEnvelope, SignedEnvelope>,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    gossip: gossipsub::Behaviour,
    identify: identify::Behaviour,
    autonat: Toggle<autonat::Behaviour>,
    dcutr: dcutr::Behaviour,
    ping: ping::Behaviour,
    relay: relay::client::Behaviour,
}

enum Command {
    Shutdown,
    Listen(Multiaddr, std_mpsc::Sender<Result<(), String>>),
    Dial(Multiaddr, std_mpsc::Sender<Result<(), String>>),
    AddPeer(PeerId, Multiaddr),
    Request(
        PeerId,
        SignedEnvelope,
        std_mpsc::Sender<Result<SignedEnvelope, String>>,
    ),
    Provide(kad::RecordKey),
    FindProviders(
        kad::RecordKey,
        std_mpsc::Sender<Result<HashSet<PeerId>, String>>,
    ),
    Subscribe(String, std_mpsc::Sender<Result<(), String>>),
    Publish(String, Vec<u8>, std_mpsc::Sender<Result<(), String>>),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectivityStats {
    pub relay_reservations: u64,
    pub relay_circuits: u64,
    pub hole_punch_successes: u64,
    pub hole_punch_failures: u64,
    pub listener_failures: u64,
    pub connections: u64,
    pub outgoing_connection_failures: u64,
    pub relay_server_reservations: u64,
    pub relay_server_denials: u64,
    pub nat_public_transitions: u64,
    pub nat_private_transitions: u64,
}

pub struct P2pRpc {
    peer_id: PeerId,
    listen_address: Multiaddr,
    command: mpsc::UnboundedSender<Command>,
    peers: Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
    gossip_messages: Arc<RwLock<Vec<GossipMessage>>>,
    listen_addresses: Arc<RwLock<Vec<Multiaddr>>>,
    connectivity: Arc<RwLock<ConnectivityStats>>,
    connection_errors: Arc<RwLock<Vec<String>>>,
}

impl P2pRpc {
    pub fn start(
        keypair: Keypair,
        listen_address: Multiaddr,
        handler: impl Fn(SignedEnvelope) -> SignedEnvelope + Send + Sync + 'static,
    ) -> Result<Self, String> {
        Self::start_client(keypair, listen_address, handler, true)
    }

    pub fn start_private(
        keypair: Keypair,
        listen_address: Multiaddr,
        handler: impl Fn(SignedEnvelope) -> SignedEnvelope + Send + Sync + 'static,
    ) -> Result<Self, String> {
        Self::start_client(keypair, listen_address, handler, false)
    }

    fn start_client(
        keypair: Keypair,
        listen_address: Multiaddr,
        handler: impl Fn(SignedEnvelope) -> SignedEnvelope + Send + Sync + 'static,
        mdns_enabled: bool,
    ) -> Result<Self, String> {
        let peer_id = keypair.public().to_peer_id();
        let peers = Arc::new(RwLock::new(HashMap::<PeerId, Vec<Multiaddr>>::new()));
        let peers_for_task = Arc::clone(&peers);
        let gossip_messages = Arc::new(RwLock::new(Vec::new()));
        let gossip_for_task = Arc::clone(&gossip_messages);
        let listen_addresses = Arc::new(RwLock::new(Vec::new()));
        let listen_for_task = Arc::clone(&listen_addresses);
        let connectivity = Arc::new(RwLock::new(ConnectivityStats::default()));
        let connectivity_for_task = Arc::clone(&connectivity);
        let connection_errors = Arc::new(RwLock::new(Vec::new()));
        let errors_for_task = Arc::clone(&connection_errors);
        let handler = Arc::new(handler);
        let (command, mut commands) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime creation failed");
            runtime.block_on(async move {
                let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                    .expect("mDNS initialisation failed");
                let rpc = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new("/peerless/rpc/1"), request_response::ProtocolSupport::Full)],
                    request_response::Config::default().with_request_timeout(Duration::from_secs(5)),
                );
                let mut kad = kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id));
                kad.set_mode(Some(kad::Mode::Server));
                let gossip = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(keypair.clone()),
                    gossipsub::ConfigBuilder::default()
                        .validation_mode(gossipsub::ValidationMode::Strict)
                        .build()
                        .expect("gossipsub configuration failed"),
                ).expect("gossipsub initialisation failed");
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/peerless/1".into(), keypair.public(),
                ));
                let autonat_config = autonat::Config {
                    boot_delay: Duration::from_millis(250),
                    retry_interval: Duration::from_secs(1),
                    confidence_max: 1,
                    only_global_ips: false,
                    ..Default::default()
                };
                let autonat = autonat::Behaviour::new(peer_id, autonat_config);
                let dcutr = dcutr::Behaviour::new(peer_id);
                let ping = ping::Behaviour::new(ping::Config::new());
                let mut swarm = SwarmBuilder::with_existing_identity(keypair)
                    .with_tokio()
                    .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
                    .expect("TCP/Noise transport initialisation failed")
                    .with_quic()
                    .with_relay_client(noise::Config::new, yamux::Config::default)
                    .expect("relay transport initialisation failed")
                    .with_behaviour(|_, relay| Behaviour { mdns: Toggle::from(mdns_enabled.then_some(mdns)), rpc, kad, gossip, identify, autonat: Toggle::from(mdns_enabled.then_some(autonat)), dcutr, ping, relay })
                    .expect("libp2p behaviour creation failed")
                    .build();
                swarm.listen_on(listen_address).expect("QUIC listen failed");
                let mut pending = HashMap::new();
                let mut provider_queries = HashMap::new();
                loop {
                    tokio::select! {
                        Some(command) = commands.recv() => match command {
                            Command::Shutdown => break,
                            Command::Listen(address, response) => {
                                let result = swarm.listen_on(address).map(|_| ()).map_err(|error| error.to_string());
                                let _ = response.send(result);
                            }
                            Command::Dial(address, response) => {
                                let result = swarm.dial(address).map_err(|error| error.to_string());
                                let _ = response.send(result);
                            }
                            Command::AddPeer(peer, address) => {
                                swarm.add_peer_address(peer, address.clone());
                                swarm.behaviour_mut().kad.add_address(&peer, address.clone());
                                peers_for_task.write().expect("peer lock poisoned").entry(peer).or_default().push(address);
                            }
                            Command::Request(peer, envelope, response) => {
                                let id = swarm.behaviour_mut().rpc.send_request(&peer, envelope);
                                pending.insert(id, response);
                            }
                            Command::Provide(key) => { let _ = swarm.behaviour_mut().kad.start_providing(key); }
                            Command::FindProviders(key, response) => {
                                let query = swarm.behaviour_mut().kad.get_providers(key);
                                provider_queries.insert(query, response);
                            }
                            Command::Subscribe(topic, response) => {
                                let result = swarm.behaviour_mut().gossip.subscribe(&gossipsub::IdentTopic::new(topic)).map(|_| ()).map_err(|error| error.to_string());
                                let _ = response.send(result);
                            }
                            Command::Publish(topic, bytes, response) => {
                                let result = swarm.behaviour_mut().gossip.publish(gossipsub::IdentTopic::new(topic), bytes).map(|_| ()).map_err(|error| error.to_string());
                                let _ = response.send(result);
                            }
                        },
                        event = swarm.select_next_some() => match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                listen_for_task.write().expect("listen lock poisoned").push(address.clone());
                                let _ = ready_tx.try_send(address);
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(found))) => {
                                for (peer, address) in found {
                                    swarm.add_peer_address(peer, address.clone());
                                    swarm.behaviour_mut().kad.add_address(&peer, address.clone());
                                    peers_for_task.write().expect("peer lock poisoned").entry(peer).or_default().push(address);
                                }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(expired))) => {
                                let mut known = peers_for_task.write().expect("peer lock poisoned");
                                for (peer, address) in expired { if let Some(values) = known.get_mut(&peer) { values.retain(|value| value != &address); } }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Rpc(request_response::Event::Message { message, .. })) => match message {
                                request_response::Message::Request { request, channel, .. } => { let _ = swarm.behaviour_mut().rpc.send_response(channel, handler(request)); }
                                request_response::Message::Response { request_id, response } => { if let Some(sender) = pending.remove(&request_id) { let _ = sender.send(Ok(response)); } }
                            },
                            SwarmEvent::Behaviour(BehaviourEvent::Rpc(request_response::Event::OutboundFailure { request_id, error, .. })) => { if let Some(sender) = pending.remove(&request_id) { let _ = sender.send(Err(error.to_string())); } }
                            SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result: kad::QueryResult::GetProviders(result), .. })) => {
                                match result {
                                    Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) if !providers.is_empty() => {
                                        if let Some(sender) = provider_queries.remove(&id) { let _ = sender.send(Ok(providers)); }
                                    }
                                    Ok(kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. }) => {
                                        if let Some(sender) = provider_queries.remove(&id) { let _ = sender.send(Ok(HashSet::new())); }
                                    }
                                    Err(error) => { if let Some(sender) = provider_queries.remove(&id) { let _ = sender.send(Err(error.to_string())); } }
                                    _ => {}
                                }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Gossip(gossipsub::Event::Message { propagation_source, message, .. })) => {
                                gossip_for_task.write().expect("gossip lock poisoned").push((message.topic.to_string(), propagation_source, message.data));
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                                for address in info.listen_addrs { swarm.behaviour_mut().kad.add_address(&peer_id, address); }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Relay(event)) => {
                                let mut stats = connectivity_for_task.write().expect("connectivity lock poisoned");
                                match event {
                                    relay::client::Event::ReservationReqAccepted { .. } => stats.relay_reservations += 1,
                                    relay::client::Event::OutboundCircuitEstablished { .. }
                                    | relay::client::Event::InboundCircuitEstablished { .. } => stats.relay_circuits += 1,
                                }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) => {
                                let mut stats = connectivity_for_task.write().expect("connectivity lock poisoned");
                                if event.result.is_ok() { stats.hole_punch_successes += 1; } else { stats.hole_punch_failures += 1; }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Autonat(autonat::Event::StatusChanged { new, .. })) => {
                                let mut stats = connectivity_for_task.write().expect("connectivity lock poisoned");
                                match new {
                                    autonat::NatStatus::Public(_) => stats.nat_public_transitions += 1,
                                    autonat::NatStatus::Private => stats.nat_private_transitions += 1,
                                    autonat::NatStatus::Unknown => {}
                                }
                            }
                            SwarmEvent::ListenerError { .. } => {
                                connectivity_for_task.write().expect("connectivity lock poisoned").listener_failures += 1;
                            }
                            SwarmEvent::ConnectionEstablished { .. } => {
                                connectivity_for_task.write().expect("connectivity lock poisoned").connections += 1;
                            }
                            SwarmEvent::OutgoingConnectionError { error, .. } => {
                                connectivity_for_task.write().expect("connectivity lock poisoned").outgoing_connection_failures += 1;
                                errors_for_task.write().expect("connection error lock poisoned").push(error.to_string());
                            }
                            _ => {}
                        }
                    }
                }
            });
        });
        let listen_address = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            peer_id,
            listen_address,
            command,
            peers,
            gossip_messages,
            listen_addresses,
            connectivity,
            connection_errors,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub fn listen_address(&self) -> &Multiaddr {
        &self.listen_address
    }
    pub fn listen_addresses(&self) -> Vec<Multiaddr> {
        self.listen_addresses
            .read()
            .expect("listen lock poisoned")
            .clone()
    }
    pub fn listen_on(&self, address: Multiaddr) -> Result<(), String> {
        let (tx, rx) = std_mpsc::channel();
        self.command
            .send(Command::Listen(address, tx))
            .map_err(|error| error.to_string())?;
        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|error| error.to_string())?
    }
    pub fn dial(&self, address: Multiaddr) -> Result<(), String> {
        let (tx, rx) = std_mpsc::channel();
        self.command
            .send(Command::Dial(address, tx))
            .map_err(|error| error.to_string())?;
        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|error| error.to_string())?
    }
    pub fn connectivity_stats(&self) -> ConnectivityStats {
        self.connectivity
            .read()
            .expect("connectivity lock poisoned")
            .clone()
    }
    pub fn connection_errors(&self) -> Vec<String> {
        self.connection_errors
            .read()
            .expect("connection error lock poisoned")
            .clone()
    }
    pub fn peers(&self) -> HashMap<PeerId, Vec<Multiaddr>> {
        self.peers.read().expect("peer lock poisoned").clone()
    }
    pub fn add_peer(&self, peer: PeerId, address: Multiaddr) -> Result<(), String> {
        self.command
            .send(Command::AddPeer(peer, address))
            .map_err(|error| error.to_string())
    }
    pub fn load_peer_cache(&self, path: impl AsRef<Path>) -> Result<usize, String> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(0);
        }
        let entries: Vec<(String, String)> =
            serde_json::from_slice(&std::fs::read(path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        let mut loaded = 0;
        for (peer, address) in entries {
            self.add_peer(
                peer.parse()
                    .map_err(|error: libp2p::identity::ParseError| error.to_string())?,
                address
                    .parse::<Multiaddr>()
                    .map_err(|error| error.to_string())?,
            )?;
            loaded += 1;
        }
        Ok(loaded)
    }
    pub fn save_peer_cache(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let entries = self
            .peers()
            .into_iter()
            .flat_map(|(peer, addresses)| {
                addresses
                    .into_iter()
                    .map(move |address| (peer.to_string(), address.to_string()))
            })
            .collect::<Vec<_>>();
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let temporary = path.with_extension("json.tmp");
        std::fs::write(
            &temporary,
            serde_json::to_vec_pretty(&entries).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        std::fs::rename(temporary, path).map_err(|error| error.to_string())
    }
    pub fn provide(&self, key: impl AsRef<[u8]>) -> Result<(), String> {
        self.command
            .send(Command::Provide(kad::RecordKey::new(&key)))
            .map_err(|error| error.to_string())
    }
    pub fn find_providers(&self, key: impl AsRef<[u8]>) -> Result<HashSet<PeerId>, String> {
        let (tx, rx) = std_mpsc::channel();
        self.command
            .send(Command::FindProviders(kad::RecordKey::new(&key), tx))
            .map_err(|error| error.to_string())?;
        rx.recv_timeout(Duration::from_secs(35))
            .map_err(|error| error.to_string())?
    }
    pub fn subscribe(&self, topic: impl Into<String>) -> Result<(), String> {
        let (tx, rx) = std_mpsc::channel();
        self.command
            .send(Command::Subscribe(topic.into(), tx))
            .map_err(|error| error.to_string())?;
        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|error| error.to_string())?
    }
    pub fn publish(&self, topic: impl Into<String>, bytes: Vec<u8>) -> Result<(), String> {
        let (tx, rx) = std_mpsc::channel();
        self.command
            .send(Command::Publish(topic.into(), bytes, tx))
            .map_err(|error| error.to_string())?;
        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|error| error.to_string())?
    }
    pub fn gossip_messages(&self) -> Vec<GossipMessage> {
        self.gossip_messages
            .read()
            .expect("gossip lock poisoned")
            .clone()
    }
    pub fn drain_gossip_messages(&self) -> Vec<GossipMessage> {
        std::mem::take(&mut *self.gossip_messages.write().expect("gossip lock poisoned"))
    }
    pub fn request(
        &self,
        peer: PeerId,
        envelope: SignedEnvelope,
    ) -> Result<SignedEnvelope, String> {
        let (tx, rx) = std_mpsc::channel();
        self.command
            .send(Command::Request(peer, envelope, tx))
            .map_err(|error| error.to_string())?;
        rx.recv_timeout(Duration::from_secs(7))
            .map_err(|error| error.to_string())?
    }
}

impl Drop for P2pRpc {
    fn drop(&mut self) {
        let _ = self.command.send(Command::Shutdown);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peerless_core::NodeId;
    use peerless_identity::NodeIdentity;

    fn envelope(payload: &[u8]) -> SignedEnvelope {
        SignedEnvelope {
            version: 1,
            signer: NodeId::from_public_key_bytes(vec![1]),
            public_key: Vec::new(),
            payload: payload.to_vec(),
            signature: Vec::new(),
        }
    }

    #[test]
    fn quic_request_response_round_trip() {
        let root = tempfile::tempdir().unwrap();
        let first_identity = NodeIdentity::load_or_generate(root.path().join("first")).unwrap();
        let second_identity = NodeIdentity::load_or_generate(root.path().join("second")).unwrap();
        let listen: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let first =
            P2pRpc::start(first_identity.keypair(), listen.clone(), |request| request).unwrap();
        let second = P2pRpc::start(second_identity.keypair(), listen, |request| request).unwrap();
        second
            .add_peer(first.peer_id(), first.listen_address().clone())
            .unwrap();
        assert_eq!(
            second
                .request(first.peer_id(), envelope(b"peerless"))
                .unwrap()
                .payload,
            b"peerless"
        );
    }

    #[test]
    fn mdns_discovers_another_local_swarm() {
        let root = tempfile::tempdir().unwrap();
        let first_identity =
            NodeIdentity::load_or_generate(root.path().join("mdns-first")).unwrap();
        let second_identity =
            NodeIdentity::load_or_generate(root.path().join("mdns-second")).unwrap();
        let listen: Multiaddr = "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap();
        let first =
            P2pRpc::start(first_identity.keypair(), listen.clone(), |request| request).unwrap();
        let second = P2pRpc::start(second_identity.keypair(), listen, |request| request).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if first.peers().contains_key(&second.peer_id())
                && second.peers().contains_key(&first.peer_id())
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("mDNS did not discover both local swarms");
    }

    #[test]
    fn kademlia_provider_discovery_and_signed_gossip_work() {
        let root = tempfile::tempdir().unwrap();
        let first_identity = NodeIdentity::load_or_generate(root.path().join("wan-first")).unwrap();
        let second_identity =
            NodeIdentity::load_or_generate(root.path().join("wan-second")).unwrap();
        let listen: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let first =
            P2pRpc::start(first_identity.keypair(), listen.clone(), |request| request).unwrap();
        let second = P2pRpc::start(second_identity.keypair(), listen, |request| request).unwrap();
        first
            .add_peer(second.peer_id(), second.listen_address().clone())
            .unwrap();
        second
            .add_peer(first.peer_id(), first.listen_address().clone())
            .unwrap();
        first.subscribe("peerless/state/v1").unwrap();
        second.subscribe("peerless/state/v1").unwrap();

        first.provide(b"sha256:content").unwrap();
        std::thread::sleep(Duration::from_secs(1));
        let providers = second.find_providers(b"sha256:content").unwrap();
        assert!(providers.contains(&first.peer_id()));

        let subscription_deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match first.publish("peerless/state/v1", b"change".to_vec()) {
                Ok(()) => break,
                Err(error)
                    if error.contains("NoPeersSubscribedToTopic")
                        && std::time::Instant::now() < subscription_deadline =>
                {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => panic!("signed gossip publish failed: {error}"),
            }
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if second
                .gossip_messages()
                .iter()
                .any(|(topic, source, bytes)| {
                    topic == "peerless/state/v1" && *source == first.peer_id() && bytes == b"change"
                })
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("signed gossipsub message was not delivered");
    }

    #[test]
    fn circuit_relay_reservation_carries_rpc_between_private_peers() {
        let root = tempfile::tempdir().unwrap();
        let relay_identity = NodeIdentity::load_or_generate(root.path().join("relay")).unwrap();
        let private_identity = NodeIdentity::load_or_generate(root.path().join("private")).unwrap();
        let caller_identity = NodeIdentity::load_or_generate(root.path().join("caller")).unwrap();
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        probe.connect("192.0.2.1:9").unwrap();
        let container_ip = probe.local_addr().unwrap().ip();
        let relay_tcp: Multiaddr = format!("/ip4/{container_ip}/tcp/0").parse().unwrap();
        let tcp: Multiaddr = format!("/ip4/{container_ip}/tcp/0").parse().unwrap();
        let relay = CircuitRelay::start(relay_identity.keypair(), relay_tcp).unwrap();
        let private =
            P2pRpc::start_private(private_identity.keypair(), tcp.clone(), |mut request| {
                request.payload.extend_from_slice(b"-handled");
                request
            })
            .unwrap();
        let caller =
            P2pRpc::start_private(caller_identity.keypair(), tcp, |request| request).unwrap();

        let reservation: Multiaddr = format!(
            "{}/p2p/{}/p2p-circuit",
            relay.listen_address(),
            relay.peer_id()
        )
        .parse()
        .unwrap();
        private
            .dial(
                format!("{}/p2p/{}", relay.listen_address(), relay.peer_id())
                    .parse()
                    .unwrap(),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(500));
        private.listen_on(reservation.clone()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline && relay.reservations() == 0 {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            relay.reservations(),
            1,
            "private={:?} reservation={reservation} listen={:?} errors={:?}",
            private.connectivity_stats(),
            private.listen_addresses(),
            private.connection_errors()
        );
        let client_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < client_deadline
            && private.connectivity_stats().relay_reservations == 0
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            private.connectivity_stats().relay_reservations,
            1,
            "reservation acknowledgement was not observed: {:?}",
            private.connection_errors()
        );

        caller
            .dial(
                format!("{}/p2p/{}", relay.listen_address(), relay.peer_id())
                    .parse()
                    .unwrap(),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let relayed_destination: Multiaddr = format!("{reservation}/p2p/{}", private.peer_id())
            .parse()
            .unwrap();
        caller
            .add_peer(private.peer_id(), relayed_destination.clone())
            .unwrap();
        caller.dial(relayed_destination).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let response = caller.request(private.peer_id(), envelope(b"rpc")).unwrap_or_else(|error| {
            panic!("{error}; caller={:?}; relay-reservations={}; relay-circuits={}; private={:?}; errors={:?}", caller.connectivity_stats(), relay.reservations(), relay.circuits(), private.connectivity_stats(), caller.connection_errors())
        });
        assert_eq!(response.payload, b"rpc-handled");
        assert!(caller.connectivity_stats().relay_circuits > 0);
        assert!(relay.circuits() > 0);
        let punch_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < punch_deadline
            && caller.connectivity_stats().hole_punch_successes
                + private.connectivity_stats().hole_punch_successes
                == 0
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            caller.connectivity_stats().hole_punch_successes
                + private.connectivity_stats().hole_punch_successes
                > 0
        );
        drop(relay);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            caller
                .request(private.peer_id(), envelope(b"mesh-survives"))
                .unwrap()
                .payload,
            b"mesh-survives-handled"
        );
    }

    #[test]
    fn autonat_performs_dial_back_and_classifies_reachable_node() {
        let root = tempfile::tempdir().unwrap();
        let first_identity = NodeIdentity::load_or_generate(root.path().join("nat-first")).unwrap();
        let second_identity =
            NodeIdentity::load_or_generate(root.path().join("nat-second")).unwrap();
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        probe.connect("192.0.2.1:9").unwrap();
        let ip = probe.local_addr().unwrap().ip();
        let listen: Multiaddr = format!("/ip4/{ip}/tcp/0").parse().unwrap();
        let first =
            P2pRpc::start(first_identity.keypair(), listen.clone(), |request| request).unwrap();
        let second = P2pRpc::start(second_identity.keypair(), listen, |request| request).unwrap();
        first
            .add_peer(second.peer_id(), second.listen_address().clone())
            .unwrap();
        second
            .add_peer(first.peer_id(), first.listen_address().clone())
            .unwrap();
        first
            .dial(
                format!("{}/p2p/{}", second.listen_address(), second.peer_id())
                    .parse()
                    .unwrap(),
            )
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline
            && first.connectivity_stats().nat_public_transitions
                + second.connectivity_stats().nat_public_transitions
                == 0
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            first.connectivity_stats().nat_public_transitions
                + second.connectivity_stats().nat_public_transitions
                > 0,
            "first={:?} second={:?}",
            first.connectivity_stats(),
            second.connectivity_stats()
        );
    }
}
