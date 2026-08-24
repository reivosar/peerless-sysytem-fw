use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use peerless_compute::{PlacementCandidate, PlacementObservation, PlacementWeights, Scheduler};
use peerless_core::{
    ContentId, NetworkRequirement, NodeId, Requirements, RuntimeRequirement, Task,
    VerificationPolicy,
};
use peerless_ledger::Invitation;
use peerless_network::p2p::P2pRpc;
use peerless_node::PeerlessNode;
use std::{
    env,
    error::Error,
    fs,
    path::PathBuf,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod e2e;

fn main() {
    if let Err(error) = run() {
        eprintln!("peerless: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref().unwrap_or("help") {
        "start" => {
            let data = PathBuf::from(args.next().unwrap_or_else(|| "peerless-data".into()));
            let listen: Multiaddr = args
                .next()
                .unwrap_or_else(|| "/ip4/0.0.0.0/udp/9718/quic-v1".into())
                .parse()?;
            let node = PeerlessNode::open(data)?;
            let network = node.serve_p2p(listen)?;
            println!(
                "node     {}\npeer     {}\nlisten   {}",
                node.node_id(),
                network.peer_id(),
                network.listen_address()
            );
            loop {
                thread::sleep(Duration::from_secs(30));
                node.save_peer_cache(&network)?;
            }
        }
        "identity" => {
            let data = PathBuf::from(args.next().unwrap_or_else(|| "peerless-data".into()));
            println!("{}", PeerlessNode::open(data)?.node_id());
        }
        "invite" => {
            let data = PathBuf::from(
                args.next()
                    .ok_or("usage: peerless invite DATA NETWORK MEMBER OUTPUT [BOOTSTRAP...]")?,
            );
            let network_id = args.next().ok_or("missing network id")?;
            let member: NodeId = args.next().ok_or("missing member NodeId")?.parse()?;
            let output = PathBuf::from(args.next().ok_or("missing output file")?);
            let issuer = PeerlessNode::open(data)?;
            let invitation = issuer.issue_invitation(
                network_id,
                member,
                vec!["*".into()],
                None,
                args.collect(),
            )?;
            let bytes = serde_json::to_vec_pretty(&invitation)?;
            fs::write(&output, &bytes)?;
            println!(
                "invitation\t{}\nissuer\t{}",
                output.display(),
                issuer.node_id()
            );
            print_qr(&bytes)?;
        }
        "join" => {
            let data = PathBuf::from(args.next().ok_or("usage: peerless join DATA INVITATION")?);
            let invitation_path = PathBuf::from(args.next().ok_or("missing invitation file")?);
            let invitation: Invitation = serde_json::from_slice(&fs::read(invitation_path)?)?;
            let node = PeerlessNode::open(data)?;
            node.install_invitation(&invitation, now())?;
            let network = node.serve_p2p("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
            let count = node.apply_invitation_bootstrap(&network, &invitation)?;
            node.save_peer_cache(&network)?;
            println!(
                "joined\t{}\nnetwork\t{}\nbootstrap\t{}",
                node.node_id(),
                invitation.membership.network_id,
                count
            );
        }
        "qr" => {
            let path = PathBuf::from(args.next().ok_or("usage: peerless qr INVITATION")?);
            print_qr(&fs::read(path)?)?;
        }
        "peers" => {
            let data = PathBuf::from(args.next().unwrap_or_else(|| "peerless-data".into()));
            let node = PeerlessNode::open(data)?;
            let network = node.serve_p2p("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
            thread::sleep(Duration::from_secs(3));
            println!("PEER\tADDRESS");
            for (peer, addresses) in network.peers() {
                for address in addresses {
                    println!("{peer}\t{address}");
                }
            }
        }
        "status" => {
            let data = PathBuf::from(args.next().unwrap_or_else(|| "peerless-data".into()));
            let node = PeerlessNode::open(data)?;
            let network = node.serve_p2p("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
            thread::sleep(Duration::from_secs(1));
            let (pending, completed) = node.task_counts();
            let (objects, bytes) = node.storage_stats()?;
            println!("Node\n  id          {}\n  peers       {}\n  tasks       {} pending, {} completed\n  storage     {} objects, {} bytes\n  ledger      height {}", node.node_id(), network.peers().len(), pending, completed, objects, bytes, node.ledger_height());
        }
        "inspect" => {
            let subject = args
                .next()
                .ok_or("usage: peerless inspect peers|tasks|storage|ledger [DATA]")?;
            let data = PathBuf::from(args.next().unwrap_or_else(|| "peerless-data".into()));
            let node = PeerlessNode::open(data)?;
            match subject.as_str() {
                "tasks" => {
                    let (pending, completed) = node.task_counts();
                    println!("pending\t{pending}\ncompleted\t{completed}");
                }
                "storage" => {
                    let (objects, bytes) = node.storage_stats()?;
                    println!("objects\t{objects}\nbytes\t{bytes}");
                }
                "ledger" => println!("height\t{}", node.ledger_height()),
                "peers" => {
                    let network = node.serve_p2p("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
                    thread::sleep(Duration::from_secs(1));
                    for (peer, addresses) in network.peers() {
                        println!(
                            "{peer}\t{}",
                            addresses
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(",")
                        );
                    }
                }
                _ => return Err("inspect subject must be peers, tasks, storage, or ledger".into()),
            }
        }
        "run" => run_task(args.collect())?,
        "e2e-features" => {
            let data = PathBuf::from(
                args.next()
                    .unwrap_or_else(|| "peerless-e2e-features".into()),
            );
            e2e::run(&data)?;
        }
        "demo-images" => {
            let data = PathBuf::from(args.next().unwrap_or_else(|| "peerless-image-demo".into()));
            let count = args
                .next()
                .map(|value| value.parse())
                .transpose()?
                .unwrap_or(100);
            run_image_demo(data, count)?;
        }
        _ => print_help(),
    }
    Ok(())
}

fn run_task(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    if args.len() < 3 {
        return Err("usage: peerless run DATA WASM INTEGER [MULTIADDR...]".into());
    }
    let node = PeerlessNode::open(&args[0])?;
    let component = fs::read(&args[1])?;
    let input: i32 = args[2].parse()?;
    let network = node.serve_p2p("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    for value in &args[3..] {
        add_peer(&network, value)?;
    }
    if args.len() == 3 {
        thread::sleep(Duration::from_secs(3));
    }

    let timestamp = now();
    let mut candidates = Vec::new();
    for peer in network.peers().keys().copied() {
        if let Ok(capability) = node.peer_capability_p2p(&network, peer) {
            candidates.push((
                peer,
                PlacementCandidate {
                    capability,
                    observation: PlacementObservation::default(),
                },
            ));
        }
    }
    let task = Task {
        task_id: format!("{}-{timestamp}", node.node_id()),
        component: ContentId::of(&component),
        input: ContentId::of(&input.to_le_bytes()),
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
    let views: Vec<_> = candidates.iter().map(|(_, value)| value.clone()).collect();
    let selected = Scheduler::new(PlacementWeights::default()).place(&task, &views, timestamp)?;
    let peer = candidates
        .iter()
        .find(|(_, value)| value.capability.node == selected.node)
        .ok_or("selected peer disappeared")?
        .0;
    let (record, bytes) = node.remote_execute_p2p(&network, peer, task, &component, input)?;
    let output = i32::from_le_bytes(bytes.try_into().map_err(|_| "invalid result")?);
    println!(
        "task      {}\nexecutor  {}\noutput    {} ({output})\nverified  true",
        record.task_id, record.executor, record.output
    );
    Ok(())
}

fn run_image_demo(data: PathBuf, count: usize) -> Result<(), Box<dyn Error>> {
    if count == 0 {
        return Err("image count must be positive".into());
    }
    fs::create_dir_all(data.join("input"))?;
    fs::create_dir_all(data.join("output"))?;
    let component = wat::parse_str(
        r#"(module
        (memory (export "memory") 1)
        (func (export "run") (param $ptr i32) (param $len i32) (result i64)
          (local $x i32) (local $y i32)
          (block $done_y
            (loop $rows
              local.get $y i32.const 32 i32.ge_u br_if $done_y
              i32.const 0 local.set $x
              (block $done_x
                (loop $cols
                  local.get $x i32.const 32 i32.ge_u br_if $done_x
                  i32.const 8192
                  local.get $y i32.const 32 i32.mul i32.add
                  local.get $x i32.add
                  local.get $ptr
                  local.get $y i32.const 128 i32.mul i32.add
                  local.get $x i32.const 2 i32.mul i32.add
                  i32.load8_u
                  i32.store8
                  local.get $x i32.const 1 i32.add local.set $x
                  br $cols))
              local.get $y i32.const 1 i32.add local.set $y
              br $rows))
          i64.const 35184372089856))"#,
    )?;
    fs::write(data.join("resize.wasm"), &component)?;
    let coordinator = PeerlessNode::open(data.join("coordinator"))?;
    let coordinator_net = coordinator.serve_p2p("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;
    let mut executors = Vec::new();
    let mut networks = Vec::new();
    for index in 0..2 {
        let node = PeerlessNode::open(data.join(format!("node-{index}")))?;
        let network = node.serve_p2p("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;
        coordinator_net.add_peer(network.peer_id(), network.listen_address().clone())?;
        executors.push(node);
        networks.push(network);
    }
    let run_id = now();
    let initial_ledger_heights = std::iter::once(coordinator.ledger_height())
        .chain(executors.iter().map(PeerlessNode::ledger_height))
        .collect::<Vec<_>>();
    let mut distribution = [0usize; 3];
    for index in 0..count {
        let intensity = (index % 256) as u8;
        let raw = vec![intensity; 64 * 64];
        fs::write(
            data.join("input").join(format!("image-{index:03}.pgm")),
            pgm_with_pixels(&raw, 64, 64),
        )?;
        let task = Task {
            task_id: format!("demo-{run_id}-image-{index:03}"),
            component: ContentId::of(&component),
            input: ContentId::of(&raw),
            requirements: Requirements {
                minimum_memory: 0,
                minimum_storage: 0,
                runtime: RuntimeRequirement("wasmtime-bytes-v1".into()),
                estimated_cpu_cost: 1,
                network: NetworkRequirement::None,
            },
            verification: VerificationPolicy::TrustExecutor,
            deadline: None,
        };
        let (record, bytes) =
            coordinator.execute_best_bytes(&coordinator_net, task, &component, &raw)?;
        if bytes.len() != 32 * 32 || bytes.iter().any(|pixel| *pixel != intensity) {
            return Err(format!("image {index} verification failed").into());
        }
        fs::write(
            data.join("output").join(format!("image-{index:03}.pgm")),
            pgm_with_pixels(&bytes, 32, 32),
        )?;
        let selected = if record.executor == *coordinator.node_id() {
            0
        } else {
            executors
                .iter()
                .position(|executor| record.executor == *executor.node_id())
                .map(|index| index + 1)
                .ok_or("selected executor disappeared")?
        };
        distribution[selected] += 1;
    }
    let final_ledger_heights = std::iter::once(coordinator.ledger_height())
        .chain(executors.iter().map(PeerlessNode::ledger_height))
        .collect::<Vec<_>>();
    let ledger_height_deltas = final_ledger_heights
        .iter()
        .zip(&initial_ledger_heights)
        .map(|(after, before)| after - before)
        .collect::<Vec<_>>();
    let evidence = serde_json::json!({
        "run_id": run_id,
        "images": count,
        "executors": std::iter::once(coordinator.node_id()).chain(executors.iter().map(PeerlessNode::node_id)).map(ToString::to_string).collect::<Vec<_>>(),
        "distribution": distribution,
        "requester_executions": distribution[0],
        "requester_ledger_delta": ledger_height_deltas[0],
        "placement": "peer-first weighted-fair Scheduler with local availability fallback",
        "component": "resize.wasm",
        "operation": "64x64 to 32x32 nearest-neighbour resize executed as WebAssembly",
        "verified_outputs": count,
        "initial_ledger_heights": initial_ledger_heights,
        "ledger_heights": final_ledger_heights,
        "ledger_height_deltas": ledger_height_deltas
    });
    fs::write(
        data.join("evidence.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!(
        "processed\t{count}\ndistribution\t{},{},{}\nevidence\t{}",
        distribution[0],
        distribution[1],
        distribution[2],
        data.join("evidence.json").display()
    );
    Ok(())
}

fn pgm_with_pixels(pixels: &[u8], width: usize, height: usize) -> Vec<u8> {
    assert_eq!(pixels.len(), width * height);
    let mut bytes = format!("P5\n{width} {height}\n255\n").into_bytes();
    bytes.extend_from_slice(pixels);
    bytes
}

fn add_peer(network: &P2pRpc, value: &str) -> Result<(), Box<dyn Error>> {
    let mut address: Multiaddr = value.parse()?;
    let peer: PeerId = match address.pop() {
        Some(Protocol::P2p(peer)) => peer,
        _ => return Err("bootstrap address must end in /p2p/PEER_ID".into()),
    };
    network.add_peer(peer, address).map_err(Into::into)
}

fn print_help() {
    println!("peerless start [DATA] [QUIC_MULTIADDR]\npeerless identity [DATA]\npeerless invite DATA NETWORK MEMBER OUTPUT [BOOTSTRAP...]\npeerless join DATA INVITATION\npeerless qr INVITATION\npeerless peers [DATA]\npeerless status [DATA]\npeerless inspect peers|tasks|storage|ledger [DATA]\npeerless run DATA WASM INTEGER [QUIC_MULTIADDR/p2p/PEER_ID ...]\npeerless e2e-features [DATA]\npeerless demo-images [DATA] [COUNT]");
}
fn print_qr(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let code = qrcode::QrCode::new(bytes)?;
    println!(
        "{}",
        code.render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .build()
    );
    Ok(())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
