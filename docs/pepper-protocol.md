# Pepper Protocol

Pepper is an optional privacy overlay for `portal-tunnel`. This document
defines the production-safe protocol core that must remain stable across
implementations.

## Scope

This first implementation slice provides:

- fixed-size Pepper cells
- fail-closed configuration validation
- versioned suite definitions
- HKDF-based cryptographic domain separation
- end-to-end AEAD scaffolding
- Reed-Solomon erasure coding
- receiver-side replay cache
- paced batch emission

This slice does not yet wire Pepper into the SDK, relay ingress, or existing
proxy paths.

## Hard Invariants

1. Every Pepper cell is fixed-size.
2. The outer cell has no length field.
3. The outer cell exposes only hop-local routing metadata.
4. Bundle and shard metadata are not visible in the outer cell.
5. Replay protection is receiver-side.
6. Downgrade behavior must fail closed unless the caller explicitly opted out.

## Outer Wire Format

The default production suite is:

- version: `0x01`
- suite: `0x0001`
- cell size: `1200` bytes

Outer format:

```text
struct PepperCell {
    uint8   version;
    uint8   flags;
    uint16  suite_id;
    uint64  circuit_id;
    uint128 hop_tag;
    bytes   encrypted_payload[1172];
}
```

Notes:

- `circuit_id` is hop-local.
- `hop_tag` is opaque and unlinkable across hops.
- `encrypted_payload` consumes the remaining bytes in the fixed cell.
- No outer field carries `bundle_id`, `stream_id`, `shard_index`,
  `message_count`, `message_length`, or `unpadded_len`.

## Encapsulation Order

Pepper implementations must preserve this order:

1. collect application payloads by isolated stream
2. build a time-window bundle
3. pad the bundle to a bucket
4. end-to-end encrypt and authenticate the full bundle
5. split ciphertext into equal-size source blocks
6. apply `k-of-n` erasure coding
7. map exactly one coded block to exactly one cell payload
8. onion-encrypt the cell payload for its selected circuit
9. emit cells under paced multipath delivery

Pepper must not erasure-code plaintext bundles.

## Cryptographic Separation

Pepper uses HKDF-SHA256 with explicit labels:

- `pepper/v1/e2e-bundle`
- `pepper/v1/onion-hop`
- `pepper/v1/hop-mac`
- `pepper/v1/control`
- `pepper/v1/cover`
- `pepper/v1/replay`

The default suite uses:

- X25519 key agreement
- HKDF-SHA256
- ChaCha20-Poly1305 AEAD

No custom primitives are introduced.

## Erasure Coding

Pepper uses Reed-Solomon erasure coding for fixed-size blocks. A coded block is
one shard, and one shard maps to one cell payload.

This implementation adds exactly one narrow dependency:

- `github.com/klauspost/reedsolomon`

It is used only for Reed-Solomon coding and reconstruction.

## Replay Protection

Replay state is keyed by the authenticated end-to-end bundle identity, not by
outer routing metadata. The cache is bounded by epoch windows and drops expired
entries.

Default values:

- epoch duration: `1s`
- replay window: `120s`

## Pacing

Pepper cells are emitted in batches after a time window. Application writes do
not immediately cause one-cell network emissions. Jitter may be added within
configured bounds to avoid deterministic timing patterns.

## Non-goals

Pepper does not claim:

- complete anonymity against a global passive adversary
- endpoint compromise protection
- browser fingerprint protection
- perfect traffic volume hiding
- Tor compatibility
