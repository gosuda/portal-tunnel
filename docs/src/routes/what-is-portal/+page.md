---
title: What is Portal?
description: An introduction to Portal, a permissionless localhost tunnel and public relay system.
---

# What is Portal?

Portal is an open-source tunnel system for publishing local services through
public relay servers. It is built around one clear architectural boundary:
**relays provide transport and routing, while your local tunnel process owns the endpoint behavior and security**.

Unlike traditional hosted reverse proxies:
- The relay routes incoming connections by SNI and forwards raw streams.
- Tenant TLS terminates inside the tunnel process on your local machine.
- The relay operator never receives tenant plaintext, session keys, or application credentials.

---

## Core Principles

- **Permissionless**: No cloud SaaS account, billing setup, or API keys required.
- **Trustless by default**: Tenant TLS terminates locally on your machine for default HTTPS stream exposures.
- **Local cryptographic identity**: Leases and reservations are signed by a local secp256k1 key pair (`identity.json`).
- **Flexible transport**: Expose web apps via HTTPS, mount multi-service microservices via routed HTTP, or allocate raw TCP and UDP ports.
- **Self-hostable & open source**: Run your own MIT-licensed relay server with zero telemetry, or attach to the public relay registry.
- **Overlay networking**: Bridge reverse backhauls over an independent IVNP overlay network when enhanced routing privacy is desired.
- **Native agentic payments**: Monetize endpoints directly using Sui or Casper x402 payment requirements.

---

## Common Use Cases

| Use case | Example |
| :--- | :--- |
| **Local dev & sharing** | Expose a Vite or Next.js dev server to show work to a teammate or client |
| **Webhook integration** | Receive live webhook deliveries from Stripe, GitHub, or Discord on localhost |
| **Multi-service backends** | Mount frontend (`/`) and API (`/api`) under a single public domain |
| **Game servers & custom protocols** | Forward raw TCP or UDP ports for Minecraft or custom protocols |
| **AI agent publishing** | Allow autonomous agents to publish interactive web services and paid APIs |
| **Edge & NAT traversal** | Securely reach edge devices and home lab servers behind strict NAT |

---

## Product Capabilities

For a complete breakdown of all 20+ supported capabilities across the CLI, Agent, SDK, and Relay—including interface support, trust boundaries, and canonical reference guides—see the **[Feature Inventory](/features)**.

---

## Next Steps

- **[Getting Started](/getting-started)**: Install the CLI and expose your first local app in seconds.
- **[Feature Inventory](/features)**: Explore the complete capability matrix across all surfaces.
- **[Concepts](/concepts)**: Understand Portal's transport model, relay responsibilities, and encryption flows.
- **[CLI Reference](/cli-reference)**: Comprehensive command and flag documentation.
