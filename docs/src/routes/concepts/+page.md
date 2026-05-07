---
title: Concepts
description: Understand how Portal provides trustless, end-to-end encrypted tunnels.
---

# Concepts

Portal publishes local services on public HTTPS URLs through relay servers. Unlike most tunnel solutions, **the relay never sees your plaintext traffic**. This page explains how.

## What is Portal?

Portal is a reverse tunnel that exposes your local applications to the internet. It differs from alternatives like ngrok or Cloudflare Tunnel in one key way: **relays are trustless**. You don't need to trust the relay operator because they can't read your traffic.

This means you can:
- Use any public relay without security concerns
- Run your own relay for full control
- Switch between relays freely — your security model doesn't depend on the relay operator

## The Trustless Relay Model

In a traditional tunnel, the relay terminates TLS and has full access to your plaintext:

```text
Client → [TLS] → Relay (decrypts, re-encrypts) → [TLS] → Your App
                  ↑ Relay sees plaintext
```

Portal works differently. The relay only routes encrypted traffic:

```text
Client → [TLS] ────────────────────────────── → Your App
                    ↑ Relay forwards raw bytes
                    (cannot decrypt)
```

The relay reads only the TLS ClientHello (the initial unencrypted handshake message) to extract the SNI hostname for routing. After that, it bridges raw encrypted bytes between the client and your local TLS server.

## End-to-End TLS

Here's the detailed flow:

1. **SNI routing** — A client connects to the relay on port 443. The relay peeks at the TLS ClientHello to read the SNI hostname (e.g., `myapp.relay.example.com`).

2. **Reverse session claim** — The relay looks up which tunnel owns that hostname and claims one of its waiting reverse sessions.

3. **Local TLS termination** — Your Portal client receives the connection and performs the TLS handshake locally. Session keys are derived on your machine — the relay never receives them.

4. **Keyless signing** — For relay-hosted domains, Portal uses the relay's `/v1/sign` endpoint to get certificate signatures. The relay acts as a "keyless" signing oracle — it signs handshake digests but never receives the resulting session keys.

5. **Encrypted data flow** — After the handshake, all traffic flows as encrypted bytes through the relay. The relay continues forwarding without needing plaintext.

**Result:** TLS terminates on your side. The relay provides routing and certificate signing only.

## MITM Detection

How do you know the relay is actually forwarding encrypted bytes and not terminating TLS itself? Portal includes a built-in self-probe mechanism:

1. After a real connection is established, Portal opens a separate TLS connection to its own public URL
2. The probe exports TLS keying material on both the client side and the server side
3. If the exported values match, the connection was passed through without relay-side termination
4. A mismatch indicates the relay may be terminating TLS (suspected MITM)

By default, `portal expose` enables strict enforcement — if the probe detects TLS termination, the relay is banned. You can use `--ban-mitm=false` for warning-only mode.

> **Note:** The self-probe is a detect-only signal. It raises the cost of relay-side TLS termination but cannot prove passthrough for every user connection.

## Transport Models

Portal supports three transport modes:

### TLS Passthrough (default)

Standard HTTPS tunneling. Client connects to port 443, relay routes by SNI, your app terminates TLS locally.

```text
Client → Relay :443 (SNI routing) → Reverse Session → Your App (TLS termination)
```

### Raw TCP Port Routing

For non-TLS services like Minecraft servers or database connections. The relay allocates a dedicated TCP port and bridges raw TCP without any TLS wrapping.

```text
Client → Relay :40001 (dedicated TCP port) → Reverse Session → Your App (raw TCP)
```

Enable with `portal expose --tcp`. Requires the relay to have TCP port transport enabled.

### UDP via QUIC

For UDP services. The relay allocates a UDP port and uses an internal QUIC tunnel to carry datagrams between the client and your app.

```text
UDP Client → Relay :40002 (UDP) → QUIC Tunnel → Your App (raw UDP)
```

UDP and TCP port allocations are independent — the same numeric range can serve both.

## Identity and Authentication

Portal uses **SIWE (Sign-In with Ethereum)** for identity:

- On first run, Portal generates a secp256k1 key pair stored as `identity.json`
- Registration uses a challenge/response flow — you sign a message proving key ownership
- No accounts, no API keys, no email required
- Reuse the same `--identity-path` across runs to maintain your identity

The relay issues a lease-scoped JWT access token after registration, used for all subsequent operations (renew, connect, unregister).

## Relay Discovery

Portal maintains a public relay registry at:

```text
https://raw.githubusercontent.com/gosuda/portal-tunnel/main/config.toml
```

When you run `portal expose`, the CLI:
1. Loads the registry seed list
2. Adds any explicit `--relays` URLs
3. Optionally discovers additional relays through relay-to-relay synchronization

Use `--discovery=false` to limit connections to only explicitly specified relays.

## Next Steps

- **[CLI Reference](/cli-reference)** — Full command and flag documentation
- **[Architecture](/architecture)** — Deep dive into system design and protocol details
- **[Getting Started](/getting-started)** — Quick install and first tunnel setup
