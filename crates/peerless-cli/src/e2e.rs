use libp2p::Multiaddr;
use peerless_core::ReplicationPolicy;
use peerless_identity::NodeIdentity;
use peerless_ledger::{BftConsensus, ConsensusEngine, Ledger, LedgerEvent, SignedEvent};
use peerless_network::p2p::{CircuitRelay, P2pRpc};
use peerless_node::PeerlessNode;
use peerless_protocol::SignedEnvelope;
use std::{
    collections::HashSet,
    error::Error,
    path::Path,
    thread,
    time::{Duration, Instant},
};

type E2eResult<T = ()> = Result<T, Box<dyn Error>>;

pub fn run(root: &Path) -> E2eResult {
    std::fs::create_dir_all(root)?;
    content_state_membership(root)?;
    replication_repair(root)?;
    bft_ledger_gossip(root)?;
    relay_and_hole_punch(root)?;
    println!("result=PASS content=true crdt=true membership=true replication=true repair=true bft=true ledger_gossip=true relay=true dcutr=true");
    Ok(())
}

fn listen() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1"
        .parse()
        .expect("static multiaddr")
}

fn connect(a: &P2pRpc, b: &P2pRpc) -> E2eResult {
    a.add_peer(b.peer_id(), b.listen_address().clone())?;
    b.add_peer(a.peer_id(), a.listen_address().clone())?;
    Ok(())
}

fn content_state_membership(root: &Path) -> E2eResult {
    let first = PeerlessNode::open(root.join("mesh-first"))?;
    let second = PeerlessNode::open(root.join("mesh-second"))?;
    let unauthorized = PeerlessNode::open(root.join("mesh-unauthorized"))?;
    let first_net = first.serve_p2p(listen())?;
    let second_net = second.serve_p2p(listen())?;
    let unauthorized_net = unauthorized.serve_p2p(listen())?;
    connect(&first_net, &second_net)?;
    connect(&unauthorized_net, &second_net)?;
    first.peer_capability_p2p(&first_net, second_net.peer_id())?;

    let payload = b"provider-discovered-content";
    let id = first.put_and_provide(&first_net, payload)?;
    let fetched = second.fetch_p2p(&second_net, id)?;
    ensure(
        fetched == payload,
        "DHT provider fetch returned wrong bytes",
    )?;
    println!("feature=content status=PASS id={id}");

    first_net.subscribe("peerless/state/v1")?;
    second_net.subscribe("peerless/state/v1")?;
    thread::sleep(Duration::from_secs(1));
    let mut left = first.state("shared")?;
    let bootstrap = left.snapshot();
    left.save()?;
    second.merge_state_snapshot("shared", &bootstrap)?;
    let mut right = second.state("shared")?;
    left.put("left", "A")?;
    right.put("right", "B")?;
    left.save()?;
    right.save()?;
    let mut converged = false;
    for _ in 0..5 {
        let mut current_left = first.state("shared")?;
        let mut current_right = second.state("shared")?;
        publish_until(|| first.publish_state(&first_net, "shared", &mut current_left))?;
        publish_until(|| second.publish_state(&second_net, "shared", &mut current_right))?;
        thread::sleep(Duration::from_millis(500));
        first.merge_state_gossip(&first_net)?;
        second.merge_state_gossip(&second_net)?;
        let left_view = first.state("shared")?;
        let right_view = second.state("shared")?;
        converged = [&left_view, &right_view].into_iter().all(|doc| {
            doc.get("left").ok().flatten().as_deref() == Some("A")
                && doc.get("right").ok().flatten().as_deref() == Some("B")
        });
        if converged {
            break;
        }
    }
    ensure(converged, "CRDT replicas did not converge")?;
    println!("feature=crdt status=PASS converged=true");

    let invitation = first.issue_invitation(
        "e2e-mesh",
        first.node_id().clone(),
        vec!["*".into()],
        None,
        Vec::new(),
    )?;
    second.enforce_membership(
        "e2e-mesh",
        std::slice::from_ref(&invitation.membership),
        &HashSet::from([invitation.membership.issuer.clone()]),
        crate::now(),
    )?;
    first.peer_capability_p2p(&first_net, second_net.peer_id())?;
    ensure(
        unauthorized
            .peer_capability_p2p(&unauthorized_net, second_net.peer_id())
            .is_err(),
        "unauthorized peer was accepted",
    )?;
    println!("feature=membership status=PASS authorized=true rejected_unauthorized=true");
    Ok(())
}

fn replication_repair(root: &Path) -> E2eResult {
    let owner = PeerlessNode::open(root.join("repair-owner"))?;
    let b = PeerlessNode::open(root.join("repair-b"))?;
    let c = PeerlessNode::open(root.join("repair-c"))?;
    let d = PeerlessNode::open(root.join("repair-d"))?;
    let owner_net = owner.serve_p2p(listen())?;
    let b_net = b.serve_p2p(listen())?;
    let c_net = c.serve_p2p(listen())?;
    let d_net = d.serve_p2p(listen())?;
    for network in [&b_net, &c_net, &d_net] {
        owner_net.add_peer(network.peer_id(), network.listen_address().clone())?;
    }
    let id = owner.put(b"repairable-content")?;
    let policy = ReplicationPolicy {
        minimum_replicas: 2,
        target_replicas: 3,
    };
    let initial =
        owner.replicate_p2p(&owner_net, [b_net.peer_id(), c_net.peer_id()], id, policy)?;
    let departed = b_net.peer_id();
    let survivor = c_net.peer_id();
    let replacement = d_net.peer_id();
    let mut known = initial.into_iter().collect::<HashSet<_>>();
    drop(b_net);
    drop(b);
    thread::sleep(Duration::from_millis(250));
    let report = owner.repair_replication_p2p(&owner_net, id, policy, &mut known)?;
    ensure(
        !report.live_replicas.contains(&departed),
        "departed replica stayed live",
    )?;
    ensure(
        report.live_replicas.contains(&survivor),
        "surviving replica was lost",
    )?;
    ensure(
        report.live_replicas.contains(&replacement),
        "replacement replica missing",
    )?;
    ensure(
        d.fetch_p2p(&d_net, id)? == b"repairable-content",
        "replacement bytes differ",
    )?;
    println!(
        "feature=replication status=PASS initial=3 repaired=true live={}",
        report.live_replicas.len() + 1
    );
    Ok(())
}

fn bft_ledger_gossip(root: &Path) -> E2eResult {
    let first = PeerlessNode::open(root.join("ledger-first"))?;
    let second = PeerlessNode::open(root.join("ledger-second"))?;
    let identities = (0..4)
        .map(|i| NodeIdentity::load_or_generate(root.join(format!("voter-{i}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let members = identities.iter().map(|i| i.node_id().clone()).collect();
    let consensus = BftConsensus::new("e2e-bft", members, 1)?;
    let ledger = Ledger::open(root.join("proposal-ledger"))?;
    let event = SignedEvent::seal(
        LedgerEvent::TaskCreated {
            task_id: "bft-e2e".into(),
        },
        &identities[0],
    )?;
    let mut block = ledger.next_block(vec![event], crate::now(), "e2e-bft")?;
    let leader = consensus.leader(0).clone();
    let mut approvals = identities
        .iter()
        .filter(|identity| identity.node_id() == &leader)
        .collect::<Vec<_>>();
    approvals.extend(
        identities
            .iter()
            .filter(|identity| identity.node_id() != &leader)
            .take(2),
    );
    consensus.finalize(&mut block, &approvals)?;
    first.append_ledger_block(block.clone(), &consensus)?;
    let first_net = first.serve_p2p(listen())?;
    let second_net = second.serve_p2p(listen())?;
    connect(&first_net, &second_net)?;
    first.peer_capability_p2p(&first_net, second_net.peer_id())?;
    first_net.subscribe("peerless/ledger/v1")?;
    second_net.subscribe("peerless/ledger/v1")?;
    thread::sleep(Duration::from_secs(1));
    publish_until(|| first.publish_ledger_block(&first_net, &block))?;
    wait_for(Duration::from_secs(5), || {
        second.merge_ledger_gossip(&second_net, &consensus).is_ok() && second.ledger_height() == 1
    })?;
    ensure(block.proof(0).is_some(), "Merkle inclusion proof missing")?;
    println!("feature=ledger status=PASS bft=3-of-4 height=1 gossip=true merkle=true");
    Ok(())
}

fn relay_and_hole_punch(root: &Path) -> E2eResult {
    let relay_identity = NodeIdentity::load_or_generate(root.join("relay"))?;
    let private_identity = NodeIdentity::load_or_generate(root.join("private"))?;
    let caller_identity = NodeIdentity::load_or_generate(root.join("caller"))?;
    let tcp: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse()?;
    let relay = CircuitRelay::start(relay_identity.keypair(), tcp.clone())?;
    let private = P2pRpc::start_private(private_identity.keypair(), tcp.clone(), |mut request| {
        request.payload.extend_from_slice(b"-handled");
        request
    })?;
    let caller = P2pRpc::start_private(caller_identity.keypair(), tcp, |request| request)?;
    let relay_address: Multiaddr =
        format!("{}/p2p/{}", relay.listen_address(), relay.peer_id()).parse()?;
    let reservation: Multiaddr = format!("{relay_address}/p2p-circuit").parse()?;
    private.dial(relay_address.clone())?;
    thread::sleep(Duration::from_millis(500));
    private.listen_on(reservation.clone())?;
    wait_for(Duration::from_secs(10), || relay.reservations() == 1)?;
    wait_for(Duration::from_secs(5), || {
        private.connectivity_stats().relay_reservations == 1
    })?;
    caller.dial(relay_address)?;
    thread::sleep(Duration::from_millis(500));
    let destination: Multiaddr = format!("{reservation}/p2p/{}", private.peer_id()).parse()?;
    caller.add_peer(private.peer_id(), destination.clone())?;
    caller.dial(destination)?;
    thread::sleep(Duration::from_millis(500));
    let response = caller.request(private.peer_id(), opaque_envelope(b"rpc"))?;
    ensure(
        response.payload == b"rpc-handled",
        "relay RPC response differs",
    )?;
    ensure(relay.circuits() > 0, "relay circuit was not established")?;
    wait_for(Duration::from_secs(5), || {
        caller.connectivity_stats().hole_punch_successes
            + private.connectivity_stats().hole_punch_successes
            > 0
    })?;
    drop(relay);
    thread::sleep(Duration::from_millis(100));
    ensure(
        caller
            .request(private.peer_id(), opaque_envelope(b"direct"))?
            .payload
            == b"direct-handled",
        "direct RPC failed after relay departure",
    )?;
    println!("feature=nat status=PASS relay=true dcutr=true direct_after_relay=true");
    Ok(())
}

fn opaque_envelope(payload: &[u8]) -> SignedEnvelope {
    SignedEnvelope {
        version: 1,
        signer: peerless_core::NodeId::from_public_key_bytes(vec![1]),
        public_key: Vec::new(),
        payload: payload.to_vec(),
        signature: Vec::new(),
    }
}

fn publish_until<E>(mut publish: impl FnMut() -> Result<(), E>) -> Result<(), E> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match publish() {
            Ok(()) => return Ok(()),
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error),
        }
    }
}

fn wait_for(timeout: Duration, mut condition: impl FnMut() -> bool) -> E2eResult {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("timed out waiting for E2E condition".into())
}

fn ensure(condition: bool, message: &'static str) -> E2eResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
