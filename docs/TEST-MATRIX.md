# Peerless Test and Falsification Matrix

## Scope and meaning of coverage

This matrix covers every implemented public subsystem, protocol state
transition, documented boundary, and known failure class. It does not claim an
impossible enumeration of every byte string, machine speed, packet schedule, or
operating-system failure. Those unbounded spaces are reduced into explicit
equivalence classes and boundary representatives below.

The authoritative gate is `./scripts/e2e.sh`. It uses a unique Docker Compose
project, clean build and node volumes, independent processes, five fresh
public-API falsification runs, the complete serial Rust suite, warning-free
Clippy, formatting, and the browser WASM build.

## Equivalence classes

| Area | Success classes | Rejection and boundary classes | Recovery and concurrency classes | Evidence |
|---|---|---|---|---|
| Content identity | Empty, 1, 31, 32, 33, 1 KiB, and 64 KiB content; display/parse round trip | First, middle, and last byte mutation; wrong algorithm; empty, short, long, and non-hex digest; malformed NodeId | Same immutable value repeatedly addressed | `identifier_boundary_and_mutation_matrix`; `content_id_round_trips_and_verifies` |
| Filesystem persistence | CAS put/get, idempotent put, missing object; atomic metadata replacement | On-disk corruption and oversized bounded reads are rejected; temporary files excluded from stats | Sixteen simultaneous CAS puts produce one object; sixteen simultaneous replacements leave one complete value | Storage suite, including `concurrent_atomic_replacements_never_expose_partial_data` and `limited_read_stops_at_the_boundary` |
| Identity and envelopes | Persistent Ed25519 identity; valid signed message and execution record | Version, signer, public key, payload, signature, transport-peer mismatch, wrong JSON schema, and every execution-record field mutated independently | Identity survives reopen | `identity_persists_and_signatures_verify`; P2P transport binding; protocol mutation tests |
| Key protection | Atomic key creation; private identity directory and key | Symlink key and symlink identity directory rejected | Existing key permissions are repaired to `0600` on open | `identity_files_are_private_and_symlinks_are_rejected`; Docker hardening assertions |
| Public-source security | Source, wire formats, binaries, and tests are assumed public; authority comes only from verified runtime credentials and keys | CI rejects tracked private-key files, operational-secret formats, hard-coded secret assignments, and deterministic secret-bypass switches | Fresh runtime keys and future per-circuit secrets are independent of repository contents | `scripts/check-public-source-security.sh`; ADR 0001; Security workflow and Docker E2E |
| Admission and abuse control | Initialised/invited members communicate in both directions | Normal listener without membership rejected; unauthorized member, expired certificate, excessive per-ID/global RPC, stream and connection excess rejected | Issuer authorization survives restart; expiry is enforced while running | Membership, request-budget, and secure-default tests; Docker E2E |
| Framing and native RPC | Frame round trip; TCP and QUIC request/response | Declared oversize, serialized oversize, truncated body, malformed JSON, corrupt chunk, over-budget upload | Chunked large transfer and bounded concurrent uploads | `frame_rejects_oversize_truncation_and_invalid_json`; `large_content_is_chunked_and_corrupt_chunks_are_rejected` |
| Discovery and routing | Explicit invitation/bootstrap address; acknowledged Kademlia provider lookup; signed GossipSub | Ambient discovery is absent; oversized/over-count peer cache and unknown provider do not fabricate content | `provide` waits for `StartProviding`; immediate lookup needs no sleep; independent Docker nodes reconnect explicitly | `peer_cache_parser_stops_at_the_entry_limit`; `kademlia_provider_discovery_and_signed_gossip_work`; `scripts/e2e.sh` |
| Server-free topology | Identical peer binaries call one another through direct QUIC multiaddrs; no coordinator service or published port exists | Runtime peers and requester are confined to a Docker `internal: true` network with no Internet/LAN route | Any selected executor can be stopped and another peer completes the task; restarted peer retains only its own state | Docker network assertion, Compose topology, remote execution, failover, and restart phases |
| Private capability and scheduling | Exact CPU/RAM/storage/runtime/load/power/slot values stay local; wire capability is redacted; concrete signed offers are checked privately; eligible remote preferred and local fallback retained | Expired deadline, no slot, wrong runtime, low memory/storage, oversized memory, malformed resource values, unauthorized offers | Synchronous peer registration prevents empty-view races; local assignment history spreads work; rejected peers are skipped | `libp2p_quic_remote_execution_end_to_end`; `execute_best_offloads_to_an_eligible_peer_before_using_local_compute`; compute boundary tests |
| Distributed memory pool | Input shards run concurrently across distinct peer memory domains and ordered outputs return to the requester | Zero or per-node-oversized shard rejected; component/input IDs verified | Departed shard executor is retried on a surviving peer; requester performs no shard execution | `sharded_execution_uses_multiple_peer_memory_domains_without_host_disclosure`; `adding_two_peers_spreads_tasks_and_keeps_requester_execution_at_zero` |
| WASM sandbox | Core Wasm, component model, and byte-buffer ABI execution | Non-Wasm, host import, memory growth, oversized input, and out-of-bounds output | Failure releases reserved capacity | `peerless-compute::wasm` suite; lease/resource node tests |
| Untrusted compute DoS | Finite Wasm completes under memory and fuel budgets | Infinite loop traps when fuel is exhausted; excessive memory/input rejected | Failed execution releases capacity | `infinite_loop_is_stopped_by_fuel_limit`; Wasm and lease tests |
| Task protocol | Offer, accept, commit, run, signed result, CAS output | Spoofed requester, commit theft, unrelated result, replayed TaskId, resource recheck | Lease expiry, failed execution cleanup, restart-safe idempotency, executor departure and relocation | Node task tests; Docker remote execution and failover |
| Verification policy | Trust executor, identical replicas, quorum majority | Empty trust result, replicate zero, disagreement, insufficient executions, zero quorum, matches greater than executions | Departed verifier replaced by a distinct peer | `replicated_and_quorum_verification_reject_disagreement`; `multi_executor_verification_replaces_a_departed_peer` |
| Membership and bootstrap | Correct member, network, permission, QR payload, and bootstrap address | Wrong member, expired certificate, expiry boundary, future-issued invitation, non-member, missing operation permission, finalized revocation | Invitation, issued authorization, and revocation survive restart; expiry is live | Ledger invitation tests; node permission, bootstrap, issued-membership, and revocation tests |
| Mutable CRDT state | Local update, snapshot import, signed gossip, bidirectional merge | Hostile document names cannot alias or escape storage root; oversized snapshots and unauthorized gossip rejected | Offline edits converge; separate stores concurrently save without lost updates; state survives restart; five fresh E2E runs | State suite, especially `concurrent_stale_documents_merge_instead_of_losing_updates`; node gossip test; `peerless e2e-features` |
| Replication | Valid minimum/target and three live copies | Zero minimum, target below minimum, and unmet valid minimum | Abrupt replica departure is detected and a replacement receives verified bytes | Replication policy tests; repair test; public API E2E |
| Ledger and Merkle | Signed events, atomic create-only append, inclusion proof, persistence | Version, filename/hash, previous hash, height, timestamp order, event root/payload/signature, network ID, approval signature, and oversized file rejected | Replicated finalized block survives structurally verified reopen | `ledger_rejects_every_block_integrity_mutation`; `persisted_ledger_rejects_renamed_and_oversized_blocks`; ledger suite |
| Quorum and BFT | Deterministic rotating leader and 2f+1 signatures for f=1 | Invalid quorum, missing leader, duplicate member, insufficient signatures, minority partition, removed leader signature | Strong operations continue only with quorum | BFT and quorum tests; public API ledger E2E |
| NAT traversal | AutoNAT dial-back, Relay v2 reservation, circuit RPC, DCUtR upgrade | Private peer is not assumed directly reachable | Relay departure followed by continued direct RPC | Network NAT tests; public API E2E |
| Source-address privacy | Relay-private RPC succeeds through a circuit | Non-loopback base/direct listener, direct peer address, and direct dial rejected; ambient discovery, Identify, AutoNAT, and DCUtR disabled | No direct upgrade occurs after relayed RPC | `relay_private_mode_disables_address_discovery_and_rejects_direct_paths`; `relay_private_rpc_never_upgrades_to_a_direct_connection` |
| Persistence and observation | Identity, CAS, CRDT, Task, SQLite metadata, reputation, ledger, peer cache, CLI status/inspect | Corrupt CAS and replay are surfaced, not silently accepted | Executor container restart retains completed Task and ledger height | Storage/state/node tests; Docker restart phase |
| Browser boundary | WebTransport, WebRTC, and WebSocket transport construction for `wasm32-unknown-unknown`; circuit WebSocket accepted in relay-only mode | Empty bootstrap set and direct transports in relay-only mode rejected | Native/browser protocol types compile together | Browser bootstrap tests and Docker WASM target check |

## Five adversarial passes

1. Cryptographic substitution and mutation of every signed field.
2. Content, frame, chunk, storage-path, resource, and numeric boundaries.
3. Authorization, invitation time, replay, lease, restart, and idempotency.
4. Partition convergence, quorum loss, BFT leader failure, replica departure,
   relay departure, and executor relocation.
5. Five fresh public-API runs plus clean Docker reproduction of the complete
   serial suite and browser build.

Any failed assertion terminates the gate before the final `result=PASS` line.
