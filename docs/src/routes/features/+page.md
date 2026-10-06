---
title: Feature Inventory
description: Canonical inventory of supported Portal product capabilities, interface support, trust boundaries, and reference guides.
---

# Feature Inventory

This is the canonical product capability inventory for Portal.

Each capability lists its supported interfaces (**CLI**, **Agent**, **SDK**, **Relay**), its trust boundaries and key constraints, and links directly to its authoritative guide or reference.

---

## Capability Matrix

| Area | Capability | Interfaces | Boundaries & Constraints | Canonical Guide |
| :--- | :--- | :--- | :--- | :--- |
| **Exposure** | Public HTTPS localhost tunnel | CLI, Agent, SDK, Relay | Uncached stream path terminates TLS locally; relay routes by SNI | [Getting Started](/getting-started) |
| **HTTP** | Multi-upstream routed HTTP | CLI, Agent, SDK | Managed locally in tunnel process; cannot mix with `--tcp` or `--udp` | [Concepts: Routed HTTP](/concepts#routed-http-mode) |
| **Static** | Local static serving | CLI, Agent, SDK | Serves local files/SPA fallback; path traversal (`..`) refused, but symlinks inside root pointing outside are followed | [CLI Reference: Static Site](/cli-reference#serve-a-static-site) |
| **Cache** | Opt-in relay static cache | CLI, SDK, Relay | Explicitly trusts selected relays with files and browser TLS; uncached on origin | [Security Model: Static Cache](/security-model#opt-in-static-cache) |
| **Transport** | Dedicated raw TCP | CLI, Agent, SDK, Relay | Requires relay port allocation; no TLS added by Portal | [TCP/UDP Tunneling](/tcp-udp-tunneling#dedicated-raw-tcp) |
| **Transport** | UDP relay | CLI, Agent, SDK, Relay | Carried over QUIC DATAGRAM backhaul; requires relay UDP support | [TCP/UDP Tunneling](/tcp-udp-tunneling#udp-relay) |
| **Relays** | Public relay discovery | CLI, Agent, SDK, Relay | Expands via registry & peer announcements; bounded by active limits | [Concepts: Relay Selection](/concepts#multi-relay-selection) |
| **Relays** | Explicit and self-hosted relays | CLI, Agent, SDK, Relay | Always maintained independently of discovery pool; no call-home | [Self-Hosting](/self-hosting) |
| **Reliability** | Multi-relay failover | CLI, Agent, SDK | Simultaneous reverse backhauls survive single-relay failure | [Concepts: Relay Selection](/concepts#multi-relay-selection) |
| **Overlay** | IVNP-backed overlay networking | CLI, Agent, SDK, Relay | Portal selects endpoints; IVNP owns the network path | [Concepts: Overlay Networking](/concepts#ivnp-backed-overlay-networking) |
| **TLS** | Endpoint tenant TLS | CLI, Agent, SDK | TLS terminates in tunnel process; relay never sees plaintext | [Security Model: Tenant TLS](/security-model#tenant-tls) |
| **TLS** | Keyless certificate signing | CLI, Agent, SDK, Relay | Relay signs transcripts via `/v1/sign`; no private keys shared | [Security Model: Keyless Signing](/security-model#keyless-signing) |
| **Security** | MITM self-probe | CLI, Agent, SDK | Compares exported TLS keying material; detects termination | [Security Model: MITM Probe](/security-model#mitm-self-probe) |
| **Identity** | Local secp256k1 identity | CLI, Agent, SDK | Persisted in `identity.json`; cryptographic lease proof without accounts | [Wallet & ENS: Identities](/wallet-and-ens#identity-surfaces) |
| **Auth** | SIWE application authentication | CLI, Agent | EIP-4361 wallet challenge; injects verified identity headers | [SIWE Authentication](/siwe-authentication#siwe-application-access) |
| **Payments** | x402 Sui payments | CLI, Agent | Gasless Sui USDC per-route pricing; in-browser wallet settlement | [Concepts: Payments](/concepts#in-flow-x402-payments) |
| **Payments** | x402 Casper payments | CLI, Agent | wCSPR CEP-18 token payments settled through Casper facilitators | [Configuration: x402 Networks](/configuration#x402-payment-networks) |
| **Operations** | Portal Agent | CLI, Agent | Multi-tunnel daemon from `config.toml`; service runner & TUI dashboard | [Portal Agent Guide](/portal-agent) |
| **Automation** | AI coding assistant plugins | Plugins | `portal-expose` and `portal-connect` skills for Codex, Claude, Cursor | [Agent Plugin Guide](https://github.com/gosuda/portal-tunnel/blob/main/plugins/portal-deploy/README.md) |
| **Naming** | Custom hostnames and ENS | CLI, Agent, Relay | Custom DNS prefixes, canonical identity names, and verified ENS records | [Wallet & ENS: ENS Import](/wallet-and-ens#ens-gasless-dns-import) |
