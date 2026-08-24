# peerless

peerless is a serverless distributed runtime for pooling compute, immutable
content, mutable state, and verifiable execution history across ordinary
machines. Participants are cryptographically identified nodes, not permanent
clients or servers.

## Why this exists

Most distributed applications embed infrastructure location into application
logic: which server receives a request, which database owns state, which worker
runs a job, and which audit service is trusted. That makes workstations, edge
devices, and temporary peers hard to use as one resource pool, while central
control planes remain failure and authority points.

peerless moves those decisions behind a runtime. Applications name content and
describe tasks. Each requester uses its current local view of the mesh to decide
where content is fetched, where work runs, how many replicas are required, how
state converges, and whether independent executions agree.

For peerless-managed work, an eligible connected peer is selected before the
requester's own machine. Local execution is the availability fallback. Adding
eligible peers therefore reduces requester-side task execution instead of
merely adding more processes to the local machine. This does not migrate
arbitrary operating-system processes or create cross-machine shared memory.

The application-facing idea is deliberately small:

~~~text
put(content)
open(state)
execute(task)
verify(result)
~~~

Storage location, compute location, and network topology belong inside the
runtime.

## Problems and mechanisms

| Problem | Runtime mechanism |
|---|---|
| Nodes appear and disappear | mDNS, static bootstrap, Identify, peer cache, TTLs, leases |
| WAN peers and content are hard to locate | Kademlia routing and provider discovery |
| NAT prevents direct connectivity | AutoNAT, Circuit Relay v2, and DCUtR |
| Placement becomes centralized | Per-requester adaptive scheduler |
| Remote code may be hostile | Wasmtime sandbox with no ambient host imports |
| Immutable data needs location-independent names | SHA-256 content-addressed storage |
| One storage peer may disappear | Replica liveness checks and automatic target repair |
| Mutable state must survive partitions | Automerge CRDT over signed Gossipsub |
| A peer may lie about authorship | Ed25519 envelopes and execution records |
| Results need independent checking | Replicate and quorum verification |
| Audit history may be rewritten | Signed events, Merkle roots, hash chain, quorum finality |
| Open admission enables Sybil attacks | Signed membership certificates and permissions |

## Architecture

~~~mermaid
flowchart TB
    APP[Application] --> API[peerless Node API]
    API --> CONTENT[Content API]
    API --> STATE[State API]
    API --> COMPUTE[Compute API]
    API --> AUDIT[Ledger API]
    CONTENT --> CAS[Verified filesystem CAS]
    STATE --> CRDT[Automerge CRDT]
    COMPUTE --> SCHED[Adaptive scheduler]
    COMPUTE --> WASM[Wasmtime executor]
    AUDIT --> LEDGER[Signed Merkle hash-chain ledger]
    CAS --> REPL[Replication policy]
    CRDT --> GOSSIP[Gossipsub]
    SCHED --> CAP[Capability and reputation view]
    LEDGER --> QUORUM[Membership and quorum]
    REPL --> MESH[P2P mesh]
    GOSSIP --> MESH
    CAP --> MESH
    QUORUM --> MESH
    WASM --> MESH
    MESH --> LAN[mDNS]
    MESH --> WAN[Kademlia and Identify]
    MESH --> DIRECT[QUIC or TCP plus Noise]
    MESH --> NAT[AutoNAT and DCUtR]
    NAT --> RELAY[Replaceable Circuit Relay v2 node]
    MESH --> BROWSER[Browser WebTransport, WebRTC, WebSocket]
~~~

~~~mermaid
flowchart LR
    NODE[peerless-node] --> NETWORK[peerless-network]
    NODE --> COMPUTE[peerless-compute]
    NODE --> STATE[peerless-state]
    NODE --> LEDGER[peerless-ledger]
    NODE --> STORAGE[peerless-storage]
    NETWORK --> IDENTITY[peerless-identity]
    NETWORK --> PROTOCOL[peerless-protocol]
    COMPUTE --> CORE[peerless-core]
    STATE --> CORE
    LEDGER --> IDENTITY
    LEDGER --> PROTOCOL
    STORAGE --> CORE
~~~

The node composes the subsystems. Lower layers never depend back on the node,
which keeps transport, consensus, and execution policies replaceable.

## Identity and membership

Each node generates one persistent Ed25519 keypair. The same key establishes
the libp2p Peer ID and signs versioned protocol envelopes. The peerless Node ID
is derived from the encoded public key. Responses are bound to the connected
libp2p identity, so a valid response signed by a different peer is rejected.

Identity is not membership. A permissioned mesh installs certificates issued
by trusted members. A certificate binds network ID, member ID, permissions,
expiry, issuer, and signature. Nodes enforce permissions separately for
observation, content, execution, state, and ledger operations.

## Network

Each native peer libp2p Swarm contains:

- QUIC as the preferred native transport;
- TCP secured by Noise with Yamux as fallback;
- mDNS for authority-free LAN discovery;
- Kademlia for WAN routing and ContentId-to-provider lookup;
- signed Gossipsub for state and ledger propagation;
- Identify and Ping;
- AutoNAT reachability detection;
- Circuit Relay v2 client behaviour; and
- DCUtR relay-assisted direct connection upgrades.

Relay service is a separate, replaceable `CircuitRelay` role with Ping,
Identify, external-address advertisement, reservation accounting, and circuit
accounting. It is a connectivity aid, not an authority. Keeping HOP service out
of ordinary peer Swarms prevents relay client/server protocol ambiguity.

The `peerless-browser` crate compiles for `wasm32-unknown-unknown` and constructs
real WebTransport, WebRTC, and WebSocket+Noise+Yamux transports. Browser peers
use the same identity and signed protocol types as native peers.

Static multiaddresses, LAN discovery, invitation data, and cached peers can
bootstrap a node. Cached addresses live under metadata/known-peers.json.
Bootstrap nodes introduce peers but have no authority over the established
mesh.

## Remote execution

~~~mermaid
sequenceDiagram
    participant R as Requester
    participant D as DHT and CAS
    participant E as Executor
    participant L as Ledger
    R->>E: signed GetCapability
    E-->>R: signed Capability with TTL
    R->>R: constraints and adaptive score
    R->>D: find component and input providers
    D-->>R: hash-verified CAS bytes
    R->>E: ContentStart, hash-checked ContentChunks, ContentComplete
    R->>E: signed TaskOffer with lease
    E->>E: recheck resources, deadline, membership
    E-->>R: TaskAccept
    R->>E: TaskCommit
    E->>E: execute sandboxed WASM
    E->>E: store output in CAS
    E->>L: append signed completion event
    E-->>R: signed ExecutionRecord
    R->>E: GetContent output
    E-->>R: hash-verified result
~~~

Offers are bound to their signing requester; another node cannot steal a
commit. Leases and deadlines are checked again by the executor. Task IDs are
idempotent: retrying a completed task replays the cached signed result instead
of executing it twice. Task cancellation and explicit error messages are part
of the wire protocol.

## Resource and memory model

Nodes do not expose a cross-machine shared address space. They advertise
available CPU, memory, storage, runtime support, load, power, task slots, and
expiry. Memory is pooled at the scheduling level: a task is placed on a node
with enough local RAM. Both requester and executor enforce the minimum.

The native executor keeps 1 GiB of currently available host memory outside its
advertised capacity. A task reserves one execution slot and an enforceable
memory budget when its offer is accepted; that reservation remains visible in
capabilities while pending and running and is released after completion,
failure, cancellation, or lease expiry. The default task budget is 64 MiB and
the accepted maximum is 512 MiB. The declared `minimum_memory` raises both the
placement requirement and enforced Wasmtime limit; it is not only a scheduling
hint. The current conservative concurrency policy is one task per node.

WASM code cannot read another node's memory or ambient host files. The current
executor provides no filesystem or network imports. Component and input CAS
objects are explicit reads; the result CAS object is the explicit write.

Two capability-free ABIs are supported: `run(i32) -> i32` for scalar jobs and
`run(ptr, len) -> packed(ptr, len)` over exported linear memory for bounded byte
buffers such as images. Content transfer uses 64 KiB chunks, verifies every
chunk hash and final ContentId, and rejects objects above the configured 512 MiB
limit. Inbound chunk sessions are limited to four and 512 MiB in aggregate;
non-64-KiB chunk declarations, corrupt chunks, and budget overflow release or
reject the reservation without allocating attacker-controlled chunk tables.

## Scheduling and result verification

Hard constraints reject stale or incompatible candidates before scoring:
memory, storage, runtime, slots, deadline, and membership/security policy.

The adaptive score considers CPU, memory, latency, power, locality, transfer
cost, load, historical success, local reputation, congestion, and replication
availability. Eligible remote candidates are considered first; self is used
only when no remote candidate satisfies the hard constraints. Per-requester
weighted assignment history spreads short sequential tasks across peers even
before operating-system load metrics have time to change.

Verification policies:

- TrustExecutor accepts one authentic executor result.
- Replicate(n) requires n identical deterministic outputs.
- Quorum requires a configured number of matching independent executions.

## Data and consistency

Immutable bytes use SHA-256 CAS. Reads recompute the hash; corrupt local objects
and corrupt transfers are rejected. Replication policies declare minimum and
target counts. Repair checks each known replica through the signed protocol,
removes departed peers, and copies to replacements until the target is restored;
it fails if the minimum cannot be reached.

Mutable documents use Automerge. Replicas can update while partitioned, then
exchange signed snapshots and converge after reconnection.

Strong operations use membership-aware quorum consensus. A minority partition
cannot finalize a block without enough distinct member signatures. Consistency
is selected per data type:

- immutable data: CAS;
- eventual data: CRDT plus gossip;
- strong operations: leases and quorum consensus.

## Verifiable ledger

Ledger events cover membership, task lifecycle, content publication, execution,
verification, and state checkpoints. Every event is signed.

Blocks contain the previous block hash, height, timestamp, signed events,
Merkle root, and consensus proof. Inclusion proofs verify one event without the
whole block. Changing history changes the event signature/hash, Merkle root,
block hash, and every following link.

ConsensusEngine separates storage from finality. The included engine requires a
configurable quorum of distinct known members; duplicate signatures do not
count twice. `BftConsensus` additionally enforces `3f+1` membership, `2f+1`
signatures, and a deterministic height-specific leader. The engine remains
replaceable through `ConsensusEngine`. Finalized blocks replicate over signed
Gossipsub.

## Local persistence and bootstrap

SQLite runs in WAL mode under `metadata/local.db` and persists task state,
peer reputation, latency history, and observability events across restarts.
CAS objects, Automerge documents, ledger blocks, identity, membership, and the
known-peer cache use their own durable stores.

An issuer creates a signed, member-bound invitation containing network ID,
permissions, expiry, and bootstrap multiaddresses. The CLI writes JSON and a QR
representation. `join` verifies the issuer signature, intended NodeId, and
expiry before persisting membership and populating the peer cache.

## Repository layout

~~~text
crates/
├── peerless-core       domain types and policies
├── peerless-identity   persistent Ed25519 identity
├── peerless-network    libp2p discovery, DHT, gossip, transports, NAT
├── peerless-protocol   signed versioned wire messages
├── peerless-storage    verified filesystem CAS
├── peerless-state      persistent Automerge documents
├── peerless-compute    scheduler, verification, Wasmtime
├── peerless-ledger     events, Merkle proofs, chain, membership, consensus
├── peerless-node       integrated runtime and public facade
└── peerless-cli        operation and local inspection
~~~

## Docker quick start

Only this repository is mounted into development containers. Cargo caches,
build output, and node data use dedicated Docker volumes.

~~~sh
docker compose run --rm dev
docker compose up -d node-a node-b node-c

docker compose run --rm dev cargo build \\
  --manifest-path examples/double-wasm/Cargo.toml \\
  --target wasm32-unknown-unknown --release

docker compose run --rm dev cargo run -p peerless-cli -- peers /tmp/observer
docker compose run --rm dev cargo run -p peerless-cli -- run \\
  /tmp/requester \\
  /target/wasm32-unknown-unknown/release/double.wasm \\
  21

docker compose run --rm dev cargo run -p peerless-cli -- demo-images \\
  /workspace/demo-output 100
~~~

The demo discovers three nodes, exchanges capabilities, places the task,
transfers verified content, executes remotely, writes an audit block, and
returns 42 with a verified signature.

`demo-images` creates 100 real 64x64 PGM inputs, connects a requester to two
cryptographic executor identities, transfers the bytes through CAS, executes
the same `resize.wasm` byte-buffer component, verifies 32x32 outputs, and writes
PGM results plus `evidence.json`. The production peer-first weighted-fair path
must keep requester execution at zero while both eligible peers receive work;
the evidence records that invariant and all signed outputs.

## CLI

~~~text
peerless start [DATA] [QUIC_MULTIADDR]
peerless identity [DATA]
peerless invite DATA NETWORK MEMBER OUTPUT [BOOTSTRAP...]
peerless join DATA INVITATION
peerless qr INVITATION
peerless peers [DATA]
peerless status [DATA]
peerless inspect peers|tasks|storage|ledger [DATA]
peerless run DATA WASM INTEGER [QUIC_MULTIADDR/p2p/PEER_ID ...]
peerless e2e-features [DATA]
peerless demo-images [DATA] [COUNT]
~~~

Status and inspection show a node's local observation, not a fictional
perfectly consistent global view.

## Validation

### Full application E2E

Run the reproducible application-level gate from the repository root:

~~~sh
./scripts/e2e.sh
~~~

The script creates a unique Docker Compose project with clean Cargo, build, and
node-data volumes. It then:

1. starts three independent node containers with distinct persistent identities;
2. starts a fourth requester container and discovers executors through mDNS;
3. transfers a real WASM module and input over libp2p QUIC;
4. verifies the signed remote result is `42` and inspects executor CAS, Task, and Ledger state;
5. stops the selected executor and proves a different live peer executes the next request;
6. restarts the first executor and proves its Task and Ledger survive restart;
7. stops the application nodes to isolate the remaining network scenarios;
8. runs the public application APIs five times with independent state over real
   sockets for DHT content fetch,
   signed CRDT convergence, membership rejection, replica repair, 3-of-4 BFT
   finality, ledger gossip, Relay v2, DCUtR, and direct communication after relay
   departure;
9. runs every workspace test, including CRDT, membership, replication repair,
   BFT, tampering, AutoNAT, Relay v2, DCUtR, resource limits, and restart replay;
10. compiles the browser transports for `wasm32-unknown-unknown`; and
11. removes only the dedicated E2E containers, network, and volumes.

The final line must be:

~~~text
result=PASS falsification_passes=5 p2p=true remote_execution=true signature=true cas=true ledger=true departure=true restart=true content=true crdt=true membership=true replication=true repair=true bft=true ledger_gossip=true relay=true dcutr=true adversarial=true browser_build=true
~~~

The concise execution trace is written to `e2e-output/latest.txt`. A failed
assertion terminates the script with a non-zero status and never prints PASS.

### Individual quality gates

~~~sh
docker compose run --rm dev sh -c \\
  'cargo fmt --all -- --check && \\
   cargo clippy --workspace --all-targets -- -D warnings && \\
   cargo test --workspace'
docker compose run --rm dev cargo check -p peerless-browser \\
  --target wasm32-unknown-unknown
docker compose run --rm dev cargo run -p peerless-cli -- e2e-features \
  /tmp/peerless-e2e-features
docker compose config --quiet
~~~

The adversarial suite covers signature, version, signer and public-key
substitution; requester spoofing and commit theft; Task ID replay; unrelated
signed results; resource boundaries; denied WASM host imports; corrupt CAS;
Kademlia provider discovery; signed Gossipsub; CRDT partition and merge;
membership expiry and permissions; distinct-member quorum; Merkle tampering;
ledger persistence and replication; QUIC RPC; mDNS; replication policy; and
restart persistence. It also performs real AutoNAT dial-back classification,
Relay v2 reservation and circuit RPC, successful DCUtR upgrade, corrupt chunk
rejection, departed-executor replacement, three-distinct-executor verification,
BFT leader/quorum rejection, SQLite recovery, and restart-safe TaskId replay.

### Requirement evidence

| Requirement | Authoritative check |
|---|---|
| Chunked large-object transfer | `large_content_is_chunked_and_corrupt_chunks_are_rejected` |
| Invitation, QR, and bootstrap persistence | `invitation_is_bound_to_member_network_and_expiry`; `invitation_persists_membership_and_bootstraps_the_issuer` |
| SQLite Task/Peer/Reputation/Event metadata | `node_exposes_persistent_state_storage_and_task_observability` |
| Atomic concurrent reputation accounting | `concurrent_reputation_updates_are_not_lost` |
| Peer-first requester load relief | `execute_best_offloads_to_an_eligible_peer_before_using_local_compute` |
| Multi-peer task spreading | `adding_two_peers_spreads_tasks_and_keeps_requester_execution_at_zero`; `short_tasks_are_balanced_across_equal_remote_peers` |
| Reserved slot and memory accounting | `accepted_offer_reserves_capacity_and_retry_does_not_double_reserve` |
| Reservation cleanup on failure and expiry | `failed_execution_and_expired_lease_release_reserved_capacity` |
| Enforced WASM memory ceiling | `linear_memory_cannot_grow_past_the_task_limit`; `byte_input_larger_than_the_task_limit_is_rejected_before_instantiation` |
| At-least-once TaskId deduplication across restart | `completed_task_idempotency_survives_executor_restart` |
| Replica repair after departure | `replication_is_repaired_after_an_executor_disappears` |
| Actual independent execution and relocation | `multi_executor_verification_replaces_a_departed_peer` |
| Replaceable leader/BFT finality | `bft_engine_requires_leader_and_two_f_plus_one_signatures` |
| WAN discovery and content providers | `kademlia_provider_discovery_and_signed_gossip_work` |
| AutoNAT detection | `autonat_performs_dial_back_and_classifies_reachable_node` |
| Relay and DCUtR | `circuit_relay_reservation_carries_rpc_between_private_peers` asserts reservation, circuit RPC, successful hole punch, relay shutdown, and continued direct RPC |
| Public application feature boundary | `peerless e2e-features ...` exercises content, CRDT, membership, replication repair, BFT ledger gossip, Relay, and DCUtR through exported APIs over live sockets |
| Browser transports | Docker `cargo check -p peerless-browser --target wasm32-unknown-unknown` |
| 100-image distributed resize | `peerless demo-images ... 100`, 100 verified outputs, zero requester executions, two executor ledgers, and `evidence.json` |

The final audit is intentionally adversarial in five passes: cryptographic and
content tampering; transport and browser boundary checks; departure, lease, and
restart recovery; multi-replica, CRDT, quorum, and BFT correctness; and a clean
Docker reproduction using format, warning-free clippy, the serial full test
suite, WASM target check, Compose validation, and the 100-image run.

The complete finite failure-mode and equivalence-class matrix is documented in
[`docs/TEST-MATRIX.md`](docs/TEST-MATRIX.md). It distinguishes covered state
transitions from mathematically unbounded input and network schedules.

## Core principle

A machine is not permanently a client or a server. It is a node. Applications
describe content, state, and work; the runtime decides location.
