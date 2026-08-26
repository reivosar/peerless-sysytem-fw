# ADR 0001: Threat model and public-knowledge security for anonymous P2P

- Status: Accepted for implementation; protocol stability requires independent review
- Date: 2026-08-26
- Parent issue: https://github.com/reivosar/peerless-sysytem-fw/issues/9
- Tracking issue: https://github.com/reivosar/peerless-sysytem-fw/issues/10

## Decision

Peerless will add a distinct, fail-closed anonymous data-plane profile. It will
not rename the existing relay-only profile or treat ordinary libp2p Circuit
Relay traffic as anonymous routing.

The anonymous profile assumes that an attacker knows the complete source code,
wire format, architecture, dependencies, binaries, configuration schema, and
test suite. Security must depend only on cryptographic secrets generated at
runtime and kept outside the source tree: long-term enrollment keys, approved
issuer keys, short-lived anonymous authorization tokens, per-circuit ephemeral
handshake secrets, and per-hop traffic keys.

Reading or copying the repository must not enable an attacker to:

- impersonate a member, relay, issuer, or executor;
- decrypt a recorded or live circuit;
- derive a node's long-term identity from an anonymous data-plane message;
- predict fresh circuit identities, keys, nonces, or token inputs;
- forge relay descriptors, credentials, cells, task results, or revocations;
- bypass route diversity, replay limits, resource limits, or privacy-profile
  negotiation; or
- discover a hidden fallback, master password, fixed key, or secret algorithm.

This is the project's public-knowledge security rule. Obfuscation may be used
only as a packaging inconvenience and never as a security control.

## Why this decision is necessary

Peerless currently protects a direct address from another application peer
when relay-only mode is selected, but it remains linkable:

1. `P2pRpc` creates a libp2p swarm from the persistent node keypair, exposing a
   stable adjacent-hop Peer ID.
2. `SignedEnvelope` contains the persistent signer `NodeId`, public key,
   payload, and signature.
3. `PeerlessNode::handle_p2p_or_reject` requires the application signing key to
   derive to the connected transport Peer ID.
4. `TaskOffer` repeats the persistent requester `NodeId`.
5. A selected Circuit Relay sees both network endpoints and timing.
6. Application frames vary in length and timing.
7. Permission checks, request budgets, task ownership, and metadata are keyed
   by the persistent signer.

These properties are useful for accountable direct P2P, but they prevent
anonymous requester operation. Removing identity without replacing
authorization would create an unauthenticated network. Adding more independent
one-hop relays would add failover but would not prevent the selected relay from
linking the connection.

## Terminology and roles

| Role | Purpose | Long-term identity allowed on anonymous data plane? |
| --- | --- | --- |
| Member | Enrolled human-controlled node | No |
| Attester | Confirms that a member may receive anonymous tokens | Enrollment flow only |
| Token issuer | Blindly issues short-lived anonymous capabilities | Issuer key is public; member identity is not redeemed |
| Origin | Machine initiating an anonymous operation | No |
| Guard | First circuit hop | Relay descriptor only |
| Middle | Separates entry and exit knowledge | Relay descriptor only |
| Exit gateway | Delivers an inner operation to its destination | Relay descriptor only |
| Destination/executor | Handles compute, content, or state operation | May be accountable; must not learn requester identity |
| Governance quorum | Admits issuers and relay descriptors; finalizes revocation | Accountable control plane only |
| Partial observer | Observes one or some, but not all, network links | Not applicable |
| Global observer | Observes every relevant entry and exit | Explicit residual risk |

“Anonymous” in this ADR means requester unlinkability within the stated threat
model. It does not mean that an endpoint cannot identify its own operator, that
an executor must be anonymous, or that all traffic is invisible.

## Assets

The design protects:

- requester network address;
- requester enrollment `NodeId`, public key, and membership record;
- linkage between token issuance and token redemption;
- linkage between two independent circuits from one member;
- selected destination, task, content identifier, and operation type from
  relays that are not entitled to process them;
- payload confidentiality and integrity;
- circuit forward and reverse keys;
- authorization scope and revocation state;
- task idempotency and accountable executor results; and
- the availability of bounded node resources under hostile traffic.

## Adversaries in scope

The implementation must resist:

- a malicious destination trying to identify or link requesters;
- one compromised or honest-but-curious guard, middle, or exit;
- a passive observer that sees only part of the circuit;
- an unauthorized node creating arbitrary Sybil identities without
  governance-approved relay descriptors or valid anonymous credentials;
- replay, duplication, mutation, truncation, reordering outside the accepted
  window, delay, and injection;
- malformed cryptographic points, keys, descriptors, tokens, and cells;
- a valid member exceeding its permission, request, circuit, queue, or traffic
  budget;
- relay departure and path failure;
- a downgrade attempt to direct, one-hop, stable-identity, variable-length, or
  incompatible transport; and
- a source-code reader who can build a modified client and coordinate hostile
  nodes but does not possess uncompromised runtime secrets.

## Explicit limits

The following are not solved by publishing more code or adding another relay,
and must never be hidden by wording:

- A global passive observer can correlate entry and exit timing unless a
  sufficiently large deployment maintains an appropriate constant-rate or mix
  traffic policy.
- Colluding entry and exit operators can combine their observations.
- A compromised origin host can observe the user, plaintext, tokens, and
  ephemeral keys before or during use.
- A compromised destination can observe the operation it is asked to execute,
  although it must not receive the requester's stable identity.
- An attester that authenticates a member necessarily knows the enrollment
  event. Issuance and redemption must be separated in time and network path so
  this fact does not trivially identify redemption.
- A small or partitioned anonymity set provides correspondingly weak
  anonymity.
- Denial of service cannot be eliminated; it is bounded, rejected, and made
  observable without retaining identifying path logs.
- Cryptographic primitives may become obsolete. Algorithm agility is allowed
  only through authenticated version negotiation with no silent downgrade.

“Source code was read” is distinct from “the running host and its key material
were compromised.” The former must not reduce protocol security. The latter is
an endpoint compromise and cannot be repaired by an in-process protocol.

## Required guarantees

### G1: Destination unlinkability

The destination must not receive the origin IP, persistent Peer ID, enrollment
`NodeId`, enrollment public key, membership certificate, issuance transcript,
or a cross-circuit identifier.

### G2: Single-relay unlinkability

A single non-colluding relay may know only its adjacent transport peers,
circuit-local identifiers, bounded scheduling metadata, and its own layer's
forwarding instruction. It must not learn both origin and destination.

### G3: Anonymous authorization

A destination must verify network, permission scope, epoch, expiry, issuer,
and one-time use without learning the enrolled member identity.

### G4: Cross-circuit unlinkability

Every circuit uses fresh transport identity, circuit identifier, handshakes,
traffic keys, request handles, and authorization tokens. Values that must be
stable for replay prevention are scoped so they cannot become global member
identifiers.

### G5: Cryptographic protection

Every hop uses authenticated key establishment. Every cell authenticates the
protocol version, circuit, direction, sequence, type, epoch, and expiry.
Relays remove or add exactly one layer.

### G6: Traffic-shape normalization

Inner operations are fragmented into one configured fixed cell size. The last
cell is padded. Relay queues, bounded random delay, mixing, and optional cover
traffic follow explicit resource budgets.

### G7: Replay and abuse resistance

Tokens are one-use. Cells use bounded replay windows. Circuits, queues,
issuance, redemption, cryptographic work, memory, bandwidth, and retries have
per-adjacent-peer and global limits.

### G8: Fail-closed operation

Failure to obtain credentials, construct a diverse route, negotiate the exact
profile, maintain padding, or rebuild a failed route returns an error. It never
falls back to direct or relay-only mode.

### G9: Revocation with a stated bound

Finalized `NodeRevoked` state stops new token issuance or refresh. Previously
issued tokens remain valid only until a short, documented epoch expiry. The UI
and documentation must report this maximum revocation delay.

### G10: Public-knowledge security

Repository scanning and built-artifact scanning must find no operational
private keys, token seeds, fixed symmetric keys, passwords, hidden peers,
secret salts, or privileged bypass values. Protocol test vectors contain only
published non-operational material.

## Visibility matrix

| Observer | May learn | Must not learn |
| --- | --- | --- |
| Attester | Enrolled member, requested public capability class and epoch | Token input/value, redemption, destination |
| Issuer | Blinded issuance request, common public metadata, issuance time | Token input/value, later redemption, destination, member identity unless issuer and attester are explicitly the same trust domain |
| Guard | Origin's ephemeral adjacent connection, middle hop, cell timing | Destination, operation, plaintext, enrollment identity |
| Middle | Ephemeral guard and exit adjacency, cell timing | Origin, destination identity, operation, plaintext |
| Exit | Ephemeral middle adjacency, destination gateway, cell timing | Origin IP, enrollment identity, token issuance linkage, plaintext protected for destination |
| Destination | Inner operation, anonymous capability scope, circuit-scoped request handle | Origin IP, stable Peer/Node ID, enrollment key, path, issuance transcript |
| One-link observer | That link's endpoints, timing and volume | Complete path, plaintext, stable origin identity derived from protocol fields |
| Governance | Issuer/relay admission and revocation votes | Per-circuit activity, token redemption, origin-destination linkage |

If one organization operates multiple roles, it can combine the columns for
those roles. Deployment tooling must report this loss of independence instead
of presenting nominal process count as operator diversity.

## Cryptographic and protocol choices

### Anonymous authorization: Privacy Pass public tokens

The baseline anonymous capability will follow the Privacy Pass architecture in
[RFC 9576], its one-time redemption rules in [RFC 9577], and the publicly
verifiable issuance protocol in [RFC 9578]. Public verification is required so
executors can authorize locally without contacting a central issuer during a
task. Issuance must be blind, tokens must be one-use, and public metadata must
use common anonymity-set buckets rather than member-specific values.

The token challenge/input will bind a versioned, domain-separated encoding of:

- network identifier;
- coarse permission class;
- common epoch and expiry class;
- issuer key identifier; and
- fresh client-generated randomness.

It must not bind a member `NodeId`, destination, task, exact timestamp, unique
resource requirement, or other value that partitions one member into a unique
anonymity set. A token hash/nullifier is stored only for its validity window to
prevent replay.

The first implementation must use the RFC's public-verification construction
and test vectors. A threshold blind issuer is not invented as part of this
baseline. Networks may approve multiple issuer keys through the existing
governance ledger; runtime verification remains decentralized. Threshold
issuance requires a separately reviewed standard and ADR amendment.

#### Implementation record and security status

Issue #11 is implemented in `peerless-anonymous-auth` with the RFC 9578 public
token suite: RSA-2048, SHA-384, deterministic RSASSA-PSS encoding, and blind
RSA issuance. Client blinding/finalization and verifier public-key operations
use exactly `privacypass = 0.2.0-pre.3`. Issuer key generation and the private
raw-RSA blind-signing operation use OpenSSL with RSA blinding. The
`privacypass` source forbids unsafe Rust and contains public-token known-answer
tests, including vectors cross-checked with a Go implementation. Its upstream
repository explicitly states that the library has not received an independent
professional audit. Peerless therefore treats this dependency and the
anonymous profile as pre-stable until that review occurs; passing local tests
is not represented as a cryptographic audit.

`privacypass` currently records the RustCrypto `rsa` crate for its public and
private modules. RustSec RUSTSEC-2023-0071 reports a timing side channel in
that crate's private-key operations with no patched release. Peerless does not
call or expose those private-key APIs: its repository gate rejects
`IssuerServer`, `IssuerKeyStore`, private RustCrypto keypairs, and
`blind_sign` in Rust source. RustCrypto is used only for public client and
verifier mathematics, for which the advisory's key-recovery condition does
not exist. The Security workflow's targeted advisory exception is conditional
on that machine-enforced reachability rule. Removing the transitive RSA crate
or moving to a patched upstream remains preferable when available.

Peerless adds the application constraints that RFC 9578 intentionally leaves
to deployments:

- a separate issuer key is generated for each network, coarse permission,
  epoch, and expiry class;
- every scope-key descriptor is signed by an accountable control-plane issuer,
  and each verifier checks that signature against its trusted issuer set before
  accepting the key;
- the SHA-256 key identifier is inside the public scope and the signed token
  input, preventing a blind request authorized for one class from being
  redeemed for another;
- membership and finalized revocation are checked only during blind issuance;
- the destination reconstructs and compares the complete challenge digest
  before offline signature verification;
- the RFC nonce is a one-use, scope-limited nullifier retained for a bounded
  time and in a bounded store;
- issuance counts are bounded per enrolled member and epoch at the issuer;
- request, response, token, network, permission, key, descriptor, and parsing
  sizes are bounded before allocation or cryptographic work; and
- normal error values contain no member identity, token, nonce, key, or
  issuance transcript, and `Debug` output redacts blind state, blind messages,
  responses, and bearer-token bytes.

Blind signing hides the token challenge from the issuer. Consequently, using
one issuer key across permissions would allow a malicious client to request an
authorized class while blinding a different class. Scope-specific epoch keys
and exact key-to-scope verification are mandatory, not an optimization.

The current issuer key store is process-local. Durable hardware-backed or
encrypted issuer-key custody and explicit OpenSSL secure-heap/key-destruction
review are required before operational deployment. This is an explicit
residual host-compromise risk and part of the independent review gate.

### Circuit key establishment: anonymous initiator, authenticated relay

Issue #12 implements this cryptographic wire layer in
`peerless-onion-protocol`; the exact v1 layouts, bounds, primitive selection,
known-answer vector, and failure behavior are recorded in
`docs/ONION-PROTOCOL.md`. Setup combines an initiator ephemeral-to-relay
service-key X25519 result with an initiator-to-relay-session-ephemeral result.
The HKDF transcript binds the expected relay service key and all public setup
fields. A ChaCha20-Poly1305 confirmation proves possession of that service key.
Governance signing and distribution of the public service-key descriptor is
deliberately the route-governance responsibility in issue #15; accepting an
unverified public key from the same transport would not authenticate a relay.

Forward and reverse AEAD keys and nonce prefixes are independently derived.
Sender objects own non-cloneable hop-key values and monotonically assign the
sequence component of each nonce. Cells are exactly 1,024 bytes on every link;
the terminal type and payload are encrypted, while authenticated compact inner
layers are zero-padded back to the fixed link size after each relay removes
exactly one layer. Bounded replay windows commit a sequence only after valid
authentication. X25519 secrets and derived buffers use zeroizing types.

Each approved relay descriptor carries a short-lived onion key separate from
its governance identity. The circuit protocol will use a reviewed Noise
handshake pattern with an anonymous ephemeral initiator and authenticated
responder, carried end-to-end to each hop through already established layers.
The selected pattern must provide fresh traffic keys and forward secrecy after
ephemeral state deletion. The exact pattern, transcript prologue, algorithms,
and test vectors are frozen by issue #12 after library review.

Adjacent libp2p Noise/QUIC protects each physical link but is not treated as
the onion layer. Anonymous circuits use fresh adjacent transport identities;
long-term enrollment keys never create anonymous data-plane swarms.

### Cell protection and framing

The baseline uses reviewed AEAD, KDF, and CSPRNG implementations. The intended
suite is X25519-class ephemeral key agreement, HKDF-SHA-256 key separation, and
ChaCha20-Poly1305 traffic protection, subject to the Noise library's supported
and independently reviewed suite. Nonces are derived from independent
direction keys and monotonically checked sequence numbers; nonce reuse is a
fatal circuit error.

Cells are fixed-size at the wire layer. Relay-visible headers contain only the
minimum circuit-local forwarding data. The protected body includes version,
direction, sequence, inner type, fragment metadata, expiry, payload, and
padding. Setup, traffic, reverse traffic, padding, rotation, and teardown use
distinct domains and types.

### Interactive circuit instead of raw Sphinx packets

Sphinx provides a compact, formally analyzed packet format for mix networks,
including per-hop unlinkability and path-position hiding. It is retained as a
design and review reference. Peerless, however, needs bidirectional,
long-running, flow-controlled task and content streams with cancellation,
idempotency, and executor responses. A Tor-style interactive layered circuit
and fixed cells fit that workload more directly than applying a one-way
message packet format as if it were an interactive session protocol.

This decision does not permit copying obsolete Tor cryptography. Tor's circuit
roles, fixed relay-cell concept, padding analysis, and rendezvous separation
are protocol references; Peerless uses current reviewed handshakes and AEAD.

## Route and deployment requirements

Anonymous mode requires at least three positions: guard, middle, and exit
gateway. Route construction enforces distinct relay identities and, when the
descriptor set permits, distinct operator, network prefix, and failure domain.
One relay cannot occupy multiple positions.

Relay descriptors are signed, epoch-bound, governance-approved, capacity
bounded, and revocable. Arbitrary self-reported Peer IDs are not eligible.
Guard stickiness is bounded to reduce repeated exposure to new potentially
malicious guards without creating a permanent application identifier.

If fewer than three eligible independent positions exist, anonymous startup or
circuit construction fails. It never reduces the hop count.

## Identity separation

Long-term `NodeIdentity` remains valid for:

- enrollment and invitation issuance;
- governance and ledger quorum signatures;
- relay and issuer descriptor approval;
- revocation and recovery; and
- optional accountable executor results.

It is prohibited from:

- anonymous transport identity;
- anonymous requester envelope signing;
- anonymous task ownership and request budgeting;
- anonymous token input or public metadata;
- circuit identifiers, replay identifiers, or route history; and
- normal anonymous data-plane logs.

Anonymous request ownership uses a fresh circuit-scoped handle plus the
verified one-time capability. Executor accountability is an independent
policy: an executor may sign a result with its accountable identity without
revealing the requester.

## Logging and observability

Production anonymous mode must not log:

- source and destination pairs;
- circuit IDs or request handles;
- cell timing traces;
- token values/nullifiers;
- ephemeral Peer IDs alongside enrollment identities;
- onion keys, traffic keys, nonces, plaintext, or padded cells; or
- task/content identifiers alongside adjacent-hop addresses.

It may expose bounded aggregate counts for active circuits, queue occupancy,
padding cells, dropped/expired cells, route failures, and cryptographic errors.
Adversarial test instrumentation is compile/test scoped and cannot be enabled
by a production runtime flag.

## Failure behavior

Circuits have maximum lifetime, idle lifetime, and cell count. Relay failure or
protocol violation destroys circuit keys and state, then constructs a fresh
complete route with bounded exponential backoff. Application idempotency
prevents duplicate task commits after uncertain delivery.

The following always fail closed:

- missing/expired/replayed anonymous capability;
- stale or unapproved relay descriptor;
- insufficient route diversity;
- handshake, AEAD, replay-window, padding, or version error;
- queue/resource limit exhaustion;
- unsupported browser transport; and
- attempted downgrade or direct fallback.

## Source and binary disclosure controls

The project will add automated checks alongside implementation issues:

1. Secret scanning covers the repository, generated packages, container image,
   examples, fixtures, and logs.
2. Operational keys are generated on first use from the OS CSPRNG and never
   committed, embedded, or derived from predictable node metadata.
3. Ephemeral keys and token inputs are generated independently per circuit or
   issuance operation.
4. Configuration contains public policy and key identifiers, never private key
   material by default.
5. Error messages and metrics are mutation-tested for secret and stable-ID
   leakage.
6. Public deterministic test vectors are explicitly marked and rejected by
   production key-loading paths.
7. Release artifacts are inspected for known fixture secrets and forbidden
   bypass strings.
8. Modified clients gain no privilege merely by changing local source; every
   authorization, descriptor, result, and revocation is cryptographically
   verified by the receiving node.

Code confidentiality is not an acceptance criterion. Key confidentiality,
protocol correctness, authorization, compartmentalization, and forward secrecy
are.

## Rejected alternatives

### Keep one relay and trust it

Rejected because the relay links origin and destination and is one compromise
and availability point.

### Configure multiple one-hop relays

Rejected as an anonymity solution because the selected relay still links both
ends. It remains useful for availability in relay-only mode.

### Rotate only Peer ID or Node ID

Rejected because IP, membership proof, message size, timing, task fields, and
destination still correlate sessions.

### Remove signatures and membership checks

Rejected because it permits unauthorized compute, storage access, flooding,
and unaccountable result forgery.

### Encrypt payloads without onion routing or padding

Rejected because encryption hides content, not the communication graph, size,
or timing.

### Hide the implementation or obfuscate the binary

Rejected because source and binaries can be copied or reverse engineered. A
secret algorithm cannot be rotated safely and cannot receive effective public
review. Runtime keys and standardized cryptographic assumptions are the
security boundary.

### Embed the stable membership certificate inside the onion payload

Rejected because the destination would still identify and correlate the
requester.

### Use Sphinx unchanged for an interactive compute session

Rejected for the baseline because one-way packet semantics do not directly
provide Peerless's bidirectional flow control, cancellation, retries, and
long-running response stream. Sphinx remains a review reference and may be
used for a future store-and-forward message profile.

### Claim global-observer resistance from bounded cover traffic

Rejected because optional, locally bounded cover traffic does not equal a
network-wide constant-rate anonymity system.

## Verification plan

Issue #19 must observe every role in a clean multi-process topology and prove:

- the destination never receives stable requester identity or source address;
- guard, middle, and exit receive only the fields allowed by the visibility
  matrix;
- one compromised relay cannot link origin to destination using protocol
  fields;
- source/binary disclosure plus a modified unauthorized client cannot forge
  credentials, descriptors, cells, or results;
- every stable identity and secret is absent from anonymous cells, normal logs,
  errors, and destination metadata;
- fixed-size, replay, mutation, resource, failure, rotation, Sybil, and
  downgrade tests pass; and
- five independent clean Docker falsification passes leave no resources.

This verification establishes the stated information-flow properties. It does
not prove resistance to the explicit global-observer or endpoint-compromise
limits.

## Consequences

Positive consequences:

- reading the source does not reveal an operational bypass or secret;
- permissioned operation no longer requires requester identification at the
  destination;
- a single relay no longer links origin and destination;
- privacy failures are explicit instead of silently downgraded; and
- claims can be tested against a role-specific visibility matrix.

Costs and tradeoffs:

- at least three independently governed routing positions are required;
- blind token issuance and replay state add operational complexity;
- cell padding, mixing, cover traffic, and additional hops consume bandwidth,
  memory, CPU, and latency;
- revocation is bounded by short token lifetime rather than instantaneous for
  already issued tokens;
- executor accountability may remain visible by policy; and
- independent cryptographic review is required before stability claims.

## Follow-up issues

- #11: unlinkable short-lived membership credentials
- #12: versioned onion cell protocol and reviewed cryptographic suite
- #13: three-hop circuits and ephemeral identities
- #14: fixed-size traffic shaping, mixing, and cover cells
- #15: governed relay descriptors and Sybil-resistant routes
- #16: rotation, failover, and no downgrade
- #17: anonymous framework request integration
- #18: fail-closed CLI and browser profiles
- #19: adversarial metadata-capture E2E
- #20: architecture, operations, and measured tradeoffs

## References

- IETF RFC 9576, Privacy Pass Architecture:
  https://www.rfc-editor.org/rfc/rfc9576.html
- IETF RFC 9577, Privacy Pass HTTP Authentication Scheme:
  https://www.rfc-editor.org/rfc/rfc9577.html
- IETF RFC 9578, Privacy Pass Issuance Protocols:
  https://www.rfc-editor.org/rfc/rfc9578.html
- IETF RFC 9497, Oblivious Pseudorandom Functions:
  https://www.rfc-editor.org/rfc/rfc9497.html
- Tor protocol specification, relay cells:
  https://spec.torproject.org/tor-spec/relay-cells.html
- Tor protocol specification, circuit padding:
  https://spec.torproject.org/padding-spec/circuit-level-padding.html
- Tor onion-service protocol overview:
  https://spec.torproject.org/rend-spec/protocol-overview.html
- Noise Protocol Framework:
  https://noiseprotocol.org/noise.html
- Danezis and Goldberg, Sphinx: A Compact and Provably Secure Mix Format:
  https://eprint.iacr.org/2008/475
