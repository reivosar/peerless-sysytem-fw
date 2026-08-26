# Peerless Onion Cell Protocol v1

## Purpose

Circuit Relay v2 hides reachability but does not provide layered routing. This
protocol gives every selected relay a distinct cryptographic layer, so a relay
can authenticate and remove only its own layer. It is a transport primitive;
route diversity, descriptor governance, traffic mixing, and application
integration are separate layers.

The design assumes the implementation, wire format, and test vectors are
public. Security comes from runtime-generated X25519 secrets, not hidden source
code. Persistent Peer IDs, Node IDs, membership certificates, identity public
keys, and direct addresses are not fields in setup messages or cells.

## Cryptographic construction

- Per-hop setup combines two X25519 results: initiator ephemeral × relay
  epoch/service key, and initiator ephemeral × relay session ephemeral.
- The relay service public key must arrive in a governance-signed descriptor.
  Setup proves possession of its private half through the transcript
  confirmation tag. Descriptor distribution is implemented by issue #15.
- HKDF-SHA-256 binds protocol version, circuit ID, hop index, epoch, expiry,
  both session public keys, and the expected relay service public key.
- HKDF emits independent ChaCha20-Poly1305 forward/reverse keys, independent
  four-byte nonce prefixes, and a setup-confirmation key.
- Cell nonces are `direction-specific-prefix || u64-sequence`. `CircuitSender`
  owns its keys and assigns sequence numbers monotonically; callers cannot
  supply or reuse a nonce.
- X25519 session secrets and derived key buffers use zeroizing types. Secret
  values have redacted `Debug` implementations.

This is protocol engineering with established primitives, not an independent
cryptographic audit.

## Fixed wire formats

All integers are unsigned big-endian. Reserved and external-padding bytes must
be zero. Exact lengths are checked before parsing or allocation.

### Setup request: 128 bytes

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | `PLS1` magic |
| 4 | 2 | protocol version |
| 6 | 1 | hop index (`0..2`) |
| 7 | 1 | reserved zero |
| 8 | 16 | random circuit ID |
| 24 | 8 | epoch |
| 32 | 8 | expiry (Unix seconds) |
| 40 | 32 | initiator session X25519 public key |
| 72 | 32 | expected relay service X25519 public key |
| 104 | 24 | zero padding |

### Setup response: 160 bytes

Offsets 0–71 repeat the request context and initiator key. Offsets 72–103 hold
the relay session public key, 104–135 repeat the expected relay service public
key, 136–151 hold the 16-byte transcript confirmation tag, and 152–159 are zero
padding.

### Onion cell: exactly 1,024 bytes at every hop

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | `PLC1` magic |
| 4 | 2 | protocol version |
| 6 | 1 | generic encrypted-layer marker |
| 7 | 1 | direction |
| 8 | 16 | circuit ID |
| 24 | 8 | epoch |
| 32 | 8 | expiry |
| 40 | 8 | sequence |
| 48 | 2 | bounded ciphertext-plus-tag length |
| 50 | variable | encrypted layer plus 16-byte Poly1305 tag |
| remainder | variable | authenticated zero padding to 1,024 bytes |

The encrypted layer contains an encrypted type byte, a two-byte payload length,
and either a compact next layer or a terminal payload. Terminal types are
setup, data, padding, response, rotation, and teardown. A transit relay sees
only the generic outer marker and, after authentication, that it must forward a
still-encrypted compact layer. Re-expansion always produces a 1,024-byte cell.

The maximum terminal payload is 955, 886, or 817 bytes for one, two, or three
hops respectively. Larger application messages use bounded fragments. A
message is limited to 512 KiB, 1,024 fragments, and 16 simultaneous incomplete
reassemblies.

## Replay and failure behavior

Receivers require sequence zero first, reject duplicates, retain a bounded
128-bit replay bitmap, and reject jumps larger than 64. A sequence is committed
only after successful AEAD authentication, so forged traffic cannot consume a
valid sequence. Version, direction, circuit, epoch, expiry, ciphertext length,
padding, layer type, and declared inner length fail closed.

## Stable HKDF known-answer vector

The unit vector uses circuit ID `11` repeated 16 times, hop 2, epoch 7, expiry
9999, initiator public input `22` repeated 32 times, responder input `33`
repeated 32 times, relay service input `55` repeated 32 times, and combined-DH
input `44` repeated 64 times. Concatenating the derived forward key, reverse
key, forward nonce prefix, reverse nonce prefix, and confirmation key yields:

```text
d65f6c19c8decb3bb2e7432dbcc4c2f6fb92f7fd7e8c4a8f6bf039ce11befb3c
f2cfa3b7422a3a3de306bedee73a5d61fa1e0ecf95bacf664a1778302290924e
7e2909433214095d6f8df7db98bf65082206015cc6985e37ccf5bb9cf9ec73348
291bbfe864dcdd6
```

## Verification coverage

`peerless-onion-protocol` tests mutate every setup field class and every cell
header field, ciphertext, tag, and padding. They also cover relay-key
impersonation, wrong hop/key/direction/version/epoch, expiry, replay, duplicate,
out-of-window sequencing, three forward layers, three reverse layers, all six
terminal types, exact-size boundaries, parser fuzz corpora, fragment boundary
properties, reverse-order reassembly, and hostile fragment metadata.
