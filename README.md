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
| Nodes appear and disappear | Signed invitations, explicit bootstrap, peer cache, TTLs, leases |
| WAN peers and content are hard to locate | Kademlia routing and provider discovery |
| NAT prevents direct connectivity | AutoNAT, Circuit Relay v2, and DCUtR |
| Placement becomes centralized | Per-requester fair ordering and blind executor admission |
| Host metrics reveal a participant's machine | Blind signed task admission; exact capability values remain local |
| One task cannot use several machines | Bounded input shards execute concurrently across distinct peer memory domains |
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
    COMPUTE --> SCHED[Blind admission scheduler]
    COMPUTE --> SHARD[Parallel shard executor]
    COMPUTE --> WASM[Wasmtime executor]
    AUDIT --> LEDGER[Signed Merkle hash-chain ledger]
    CAS --> REPL[Replication policy]
    CRDT --> GOSSIP[Gossipsub]
    SCHED --> CAP[Capability and reputation view]
    SHARD --> MESH
    LEDGER --> QUORUM[Membership and quorum]
    REPL --> MESH[P2P mesh]
    GOSSIP --> MESH
    CAP --> MESH
    QUORUM --> MESH
    WASM --> MESH
    MESH --> BOOT[Invitation bootstrap and peer cache]
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
is derived from the encoded public key. Requests and responses are bound to the
connected libp2p identity, so a valid envelope relayed by a different transport
peer is rejected.

Identity is not membership. A permissioned mesh installs certificates issued
by trusted members. A certificate binds network ID, member ID, permissions,
expiry, issuer, and signature. Nodes enforce permissions separately for
observation, content, execution, state, and ledger operations.

The normal listener is closed by default: it refuses to start until the node is
initialised or has joined a signed permissioned network. `--unsafe-open` is
reserved for an isolated test network such as the Docker E2E environment.

~~~bash
peerless init peerless-data my-network
peerless start peerless-data /ip4/0.0.0.0/udp/9718/quic-v1
~~~

## Source-address privacy and hardening

Direct P2P necessarily reveals endpoint addresses to the two peers. When that
is unacceptable, start a member through a trusted circuit relay:

~~~bash
peerless start-relayed peerless-data \
  /dns4/relay-a.example/tcp/9718/p2p/RELAY_A_PEER_ID \
  /dns4/relay-b.example/tcp/9718/p2p/RELAY_B_PEER_ID
~~~

Relay-only mode disables ambient discovery, Identify, AutoNAT, and DCUtR,
requires its base listener to be loopback-only, accepts circuit paths only
through explicitly configured relays, rejects direct peer addresses/listeners/
dials, and therefore prevents an application peer
from learning the other endpoint's direct IP. Each selected relay still sees
the network endpoints using it; Peerless does not claim anonymity from a relay or a global
traffic observer. See [SECURITY.md](SECURITY.md) for the exact guarantee,
remaining risks, key protection, runtime limits, and deployment requirements.

## Network

Each native peer libp2p Swarm contains:

- QUIC as the preferred native transport;
- TCP secured by Noise with Yamux as fallback;
- explicit invitation/bootstrap addresses (ambient mDNS discovery is disabled);
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

Static multiaddresses, invitation data, and cached peers can bootstrap a node.
Cached addresses live under metadata/known-peers.json.
Bootstrap nodes introduce peers but have no authority over the established
mesh.

## Remote execution

~~~mermaid
sequenceDiagram
    participant R as Requester
    participant D as DHT and CAS
    participant E as Executor
    participant L as Ledger
    R->>R: fair peer order from local assignment history
    R->>D: find component and input providers
    D-->>R: hash-verified CAS bytes
    R->>E: ContentStart, hash-checked ContentChunks, ContentComplete
    R->>E: signed TaskOffer with requirements and lease
    E->>E: privately check local resources, deadline, membership
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

Nodes do not expose unsafe cross-machine pointers or a transparent shared
address space. Exact CPU, memory, storage, runtime inventory, load, power, and
slot values stay local. A wire `GetCapability` response is deliberately
redacted; placement does not consume it. The requester orders peers using only
its local assignment history and submits a concrete signed `TaskOffer`. Each
executor evaluates the requirements against its private current capacity and
returns only accept or reject.

Memory is pooled through bounded data-parallel execution. The
`execute_sharded_bytes` API splits one application input into independently
addressed shards, runs one shard per peer concurrently in each wave, preserves
result order, and retries a departed executor on another peer. The aggregate
working set can therefore span several isolated peer RAM domains without
making one machine's pointers accessible to another. Applications define how
shard outputs are reduced; this is a task/data pool, not distributed virtual
memory.

The native executor keeps 1 GiB of currently available host memory outside its
private admission capacity. A task reserves one execution slot and an enforceable
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

Remote placement uses blind admission. The requester fairly orders connected
peers from local assignment history; each executor applies CPU, memory,
storage, runtime, slot, deadline, and membership constraints without disclosing
the underlying host measurements. Rejected or departed peers are skipped and
local execution remains the final availability fallback.

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

Mutable files are written through unique exclusive temporary files, flushed,
and atomically published; private membership and peer-cache files are created
as `0600`. CRDT saves take both an in-process mutex and an operating-system file
lock, merge the latest on-disk snapshot, and then publish, so concurrent stale
writers do not silently discard one another. Startup reads enforce byte and
entry limits before deserializing untrusted local metadata. Ledger reopen also
checks the encoded filename hash, height/previous-hash chain, event Merkle root,
network continuity, and monotonic timestamps.

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

./scripts/e2e.sh

docker compose run --rm dev cargo run -p peerless-cli -- demo-images \\
  /workspace/demo-output 100
~~~

The E2E connects three nodes by explicit multiaddress, exchanges capabilities, places the task,
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
peerless init DATA NETWORK
peerless start [--unsafe-open] [DATA] [QUIC_MULTIADDR]
peerless start-relayed DATA RELAY_MULTIADDR [RELAY_MULTIADDR...]
peerless identity [DATA]
peerless invite DATA NETWORK MEMBER OUTPUT [BOOTSTRAP...]
peerless join DATA INVITATION
peerless qr INVITATION
peerless peers [DATA]
peerless status [DATA]
peerless inspect peers|tasks|storage|ledger [DATA]
peerless run [--unsafe-open] DATA WASM INTEGER [QUIC_MULTIADDR/p2p/PEER_ID ...]
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
node-data volumes. Runtime peers and the requester are attached only to a
Docker `internal: true` network, so they cannot contact an Internet-hosted or
LAN-hosted coordinator. Dependency downloads happen separately on the build
network before runtime verification. It then:

1. starts three independent node containers with distinct persistent identities;
2. constructs each peer's direct internal QUIC multiaddr from its container IP
   and Peer ID, then gives all addresses to an ephemeral fourth requester; no
   discovery, coordinator, API, or database server is involved in this proof;
3. transfers a real WASM module and input over libp2p QUIC;
4. verifies the signed remote result is `42` and inspects executor CAS, Task, and Ledger state;
5. stops the selected executor and proves a different live peer executes the next request;
6. restarts the first executor and proves its Task and Ledger survive restart;
7. stops the application nodes to isolate the remaining network scenarios;
8. runs the public application APIs five times with independent state over real
   sockets for DHT content fetch,
   signed CRDT convergence, membership rejection, replica repair, 3-of-4 BFT
   finality, ledger gossip, Relay v2, DCUtR, relay-only source-address privacy,
   direct-path rejection, Wasm fuel exhaustion, rate/connection limits, and
   direct communication after relay in non-private mode;
9. runs every workspace test, including CRDT, membership, replication repair,
   BFT, tampering, AutoNAT, Relay v2, DCUtR, resource limits, and restart replay;
10. compiles the browser transports for `wasm32-unknown-unknown`; and
11. removes only the dedicated E2E containers, network, and volumes.

The final line must be:

~~~text
result=PASS server_free=true runtime_network_internal=true secure_default=true relay_privacy=true wasm_fuel=true rate_limit=true connection_limit=true key_permissions=true container_hardened=true falsification_passes=5 p2p=true remote_execution=true signature=true cas=true ledger=true departure=true restart=true content=true crdt=true membership=true replication=true repair=true bft=true ledger_gossip=true relay=true dcutr=true adversarial=true browser_build=true
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
ledger persistence and replication; QUIC RPC; explicit bootstrap; replication policy; and
restart persistence. It also performs real AutoNAT dial-back classification,
Relay v2 reservation and circuit RPC, successful DCUtR upgrade, corrupt chunk
rejection, departed-executor replacement, three-distinct-executor verification,
BFT leader/quorum rejection, SQLite recovery, and restart-safe TaskId replay.
Provider publication is acknowledged only after the Kademlia
`StartProviding` query completes; immediate lookup is tested without sleeps.

### Requirement evidence

| Requirement | Authoritative check |
|---|---|
| Chunked large-object transfer | `large_content_is_chunked_and_corrupt_chunks_are_rejected` |
| Invitation, QR, and bootstrap persistence | `invitation_is_bound_to_member_network_and_expiry`; `invitation_persists_membership_and_bootstraps_the_issuer` |
| Immediate and restart-persistent member revocation | `finalized_revocation_blocks_member_immediately_and_after_restart` |
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
| Atomic bounded persistence | `concurrent_atomic_replacements_never_expose_partial_data`; `limited_read_stops_at_the_boundary`; `oversized_membership_metadata_is_rejected_before_json_allocation` |
| Concurrent CRDT persistence | `concurrent_stale_documents_merge_instead_of_losing_updates` uses separate stores sharing one path |
| AutoNAT detection | `autonat_performs_dial_back_and_classifies_reachable_node` |
| Relay and DCUtR | `circuit_relay_reservation_carries_rpc_between_private_peers` asserts reservation, circuit RPC, successful hole punch, relay shutdown, and continued direct RPC |
| Public application feature boundary | `peerless e2e-features ...` exercises content, CRDT, membership, replication repair, BFT ledger gossip, Relay, and DCUtR through exported APIs over live sockets |
| Browser transports | Docker `cargo check -p peerless-browser --target wasm32-unknown-unknown` |
| Known dependency vulnerabilities | Docker `cargo audit` and the scheduled Security workflow |
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
