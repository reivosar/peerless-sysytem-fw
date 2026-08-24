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
| Filesystem CAS | Put/get, idempotent put, missing object | On-disk corruption is rejected on get and put; temporary files excluded from stats | Sixteen simultaneous puts produce one complete object | `put_is_idempotent_and_get_verifies_content`; `missing_content_is_distinct`; `corrupted_content_is_never_returned_or_silently_replaced`; `concurrent_idempotent_puts_leave_one_complete_object` |
| Identity and envelopes | Persistent Ed25519 identity; valid signed message and execution record | Version, signer, public key, payload, signature, wrong JSON schema, and every execution-record field mutated independently | Identity survives reopen | `identity_persists_and_signatures_verify`; protocol mutation tests |
| Framing and native RPC | Frame round trip; TCP and QUIC request/response | Declared oversize, serialized oversize, truncated body, malformed JSON, corrupt chunk, over-budget upload | Chunked large transfer and bounded concurrent uploads | `frame_rejects_oversize_truncation_and_invalid_json`; `large_content_is_chunked_and_corrupt_chunks_are_rejected` |
| Discovery and routing | mDNS discovery; explicit address; Kademlia provider lookup; signed GossipSub | Unknown provider and connection failures do not fabricate content | Peer cache survives restart; independent Docker nodes rediscover | Network suite; `scripts/e2e.sh` |
| Capability and scheduling | Eligible remote preferred; local fallback; weighted fair spreading | Expired TTL, expired deadline, no slot, wrong runtime, low memory/storage, oversized memory, zero/negative/>1/NaN/infinite CPU, negative/>1/NaN/infinite load | Reputation updates remain atomic; placement reacts to trust, latency, locality, replication, and congestion | Compute boundary tests; node placement tests |
| WASM sandbox | Core Wasm, component model, and byte-buffer ABI execution | Non-Wasm, host import, memory growth, oversized input, and out-of-bounds output | Failure releases reserved capacity | `peerless-compute::wasm` suite; lease/resource node tests |
| Task protocol | Offer, accept, commit, run, signed result, CAS output | Spoofed requester, commit theft, unrelated result, replayed TaskId, resource recheck | Lease expiry, failed execution cleanup, restart-safe idempotency, executor departure and relocation | Node task tests; Docker remote execution and failover |
| Verification policy | Trust executor, identical replicas, quorum majority | Empty trust result, replicate zero, disagreement, insufficient executions, zero quorum, matches greater than executions | Departed verifier replaced by a distinct peer | `replicated_and_quorum_verification_reject_disagreement`; `multi_executor_verification_replaces_a_departed_peer` |
| Membership and bootstrap | Correct member, network, permission, QR payload, and bootstrap address | Wrong member, expired certificate, expiry boundary, future-issued invitation, non-member, missing operation permission | Invitation and membership survive restart | Ledger invitation tests; node permission and bootstrap tests |
| Mutable CRDT state | Local update, snapshot import, signed gossip, bidirectional merge | Hostile document names cannot alias or escape storage root; unauthorized gossip ignored | Offline partition edits converge; state survives restart; five fresh E2E convergence runs | State suite; node gossip test; `peerless e2e-features` |
| Replication | Valid minimum/target and three live copies | Zero minimum, target below minimum, and unmet valid minimum | Abrupt replica departure is detected and a replacement receives verified bytes | Replication policy tests; repair test; public API E2E |
| Ledger and Merkle | Signed events, chain append, inclusion proof, persistence | Version, previous hash, height, timestamp, event root, event payload, event signature, network ID, and approval signature mutations; duplicate approver | Replicated finalized block survives reopen | `ledger_rejects_every_block_integrity_mutation`; ledger suite |
| Quorum and BFT | Deterministic rotating leader and 2f+1 signatures for f=1 | Invalid quorum, missing leader, duplicate member, insufficient signatures, minority partition, removed leader signature | Strong operations continue only with quorum | BFT and quorum tests; public API ledger E2E |
| NAT traversal | AutoNAT dial-back, Relay v2 reservation, circuit RPC, DCUtR upgrade | Private peer is not assumed directly reachable | Relay departure followed by continued direct RPC | Network NAT tests; public API E2E |
| Persistence and observation | Identity, CAS, CRDT, Task, SQLite metadata, reputation, ledger, peer cache, CLI status/inspect | Corrupt CAS and replay are surfaced, not silently accepted | Executor container restart retains completed Task and ledger height | Storage/state/node tests; Docker restart phase |
| Browser boundary | WebTransport, WebRTC, and WebSocket transport construction for `wasm32-unknown-unknown` | Empty bootstrap transport set rejected | Native/browser protocol types compile together | Browser unit test and Docker WASM target check |

## Five adversarial passes

1. Cryptographic substitution and mutation of every signed field.
2. Content, frame, chunk, storage-path, resource, and numeric boundaries.
3. Authorization, invitation time, replay, lease, restart, and idempotency.
4. Partition convergence, quorum loss, BFT leader failure, replica departure,
   relay departure, and executor relocation.
5. Five fresh public-API runs plus clean Docker reproduction of the complete
   serial suite and browser build.

Any failed assertion terminates the gate before the final `result=PASS` line.
