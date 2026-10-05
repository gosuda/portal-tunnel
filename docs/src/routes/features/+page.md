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
| **Exposure** | [Public HTTPS localhost tunnel](#public-https-localhost-tunnel) | CLI, Agent, SDK, Relay | Uncached stream path terminates TLS locally; relay routes by SNI | [Getting Started](/getting-started) |
| **HTTP** | [Multi-upstream routed HTTP](#multi-upstream-routed-http) | CLI, Agent, SDK | Managed locally in tunnel process; cannot mix with `--tcp` or `--udp` | [Concepts: Routed HTTP](/concepts#routed-http-mode) |
| **Static** | [Local static serving](#local-static-serving) | CLI, Agent, SDK | Serves local files/SPA fallback; path traversal (`..`) refused | [CLI Reference: Modes](/cli-reference#modes) |
| **Cache** | [Opt-in relay static cache](#opt-in-relay-static-cache) | CLI, Relay | Explicitly trusts selected relays with files and browser TLS; uncached on origin | [Security Model: Static Cache](/security-model#opt-in-static-cache) |
| **Transport** | [Dedicated raw TCP](#dedicated-raw-tcp) | CLI, SDK, Relay | Requires relay port allocation; no TLS added by Portal | [TCP/UDP Tunneling](/tcp-udp-tunneling#dedicated-raw-tcp) |
| **Transport** | [UDP relay](#udp-relay) | CLI, SDK, Relay | Carried over QUIC DATAGRAM backhaul; requires relay UDP support | [TCP/UDP Tunneling](/tcp-udp-tunneling#udp-relay) |
| **Relays** | [Public relay discovery](#public-relay-discovery) | CLI, Agent, SDK, Relay | Expands via registry & peer announcements; bounded by active limits | [Concepts: Relay Selection](/concepts#multi-relay-selection) |
| **Relays** | [Explicit and self-hosted relays](#explicit-and-self-hosted-relays) | CLI, Agent, SDK, Relay | Always maintained independently of discovery pool; no call-home | [Self-Hosting](/self-hosting) |
| **Reliability** | [Multi-relay failover](#multi-relay-failover) | CLI, Agent, SDK | Simultaneous reverse backhauls survive single-relay failure | [Concepts: Relay Selection](/concepts#multi-relay-selection) |
| **Overlay** | [IVNP-backed overlay networking](#ivnp-backed-overlay-networking) | CLI, Agent, SDK, Relay | Portal selects endpoints; IVNP owns the network path | [Concepts: Overlay Networking](/concepts#ivnp-backed-overlay-networking) |
| **TLS** | [Endpoint tenant TLS](#endpoint-tenant-tls) | CLI, Agent, SDK | TLS terminates in tunnel process; relay never sees plaintext | [Security Model: Tenant TLS](/security-model#tenant-tls-keyless-signing) |
| **TLS** | [Keyless certificate signing](#keyless-certificate-signing) | CLI, Agent, SDK, Relay | Relay signs transcripts via `/v1/sign`; no private keys shared | [Security Model: Keyless Signing](/security-model#tenant-tls-keyless-signing) |
| **Security** | [MITM self-probe](#mitm-self-probe) | CLI, SDK | Compares exported TLS keying material; detects termination | [Security Model: MITM Probe](/security-model#mitm-self-probe) |
| **Identity** | [Local secp256k1 identity](#local-secp256k1-identity) | CLI, Agent, SDK | Persisted in `identity.json`; cryptographic lease proof without accounts | [Wallet & ENS: Identities](/wallet-and-ens#tunnel-identities-and-wallets) |
| **Auth** | [SIWE application authentication](#siwe-application-authentication) | CLI, Agent, Relay | EIP-4361 wallet challenge; injects verified identity headers | [SIWE Authentication](/siwe-authentication) |
| **Payments** | [x402 Sui payments](#x402-sui-payments) | CLI, Agent, SDK | Gasless Sui USDC per-route pricing; in-browser wallet settlement | [Concepts: Payments](/concepts#routed-http-mode) |
| **Payments** | [x402 Casper payments](#x402-casper-payments) | CLI, Agent | wCSPR CEP-18 token payments settled through Casper facilitators | [API Reference: Payments](/api-reference#casper-wcpr-x402-support) |
| **Operations** | [Portal Agent](#portal-agent) | CLI, Agent | Multi-tunnel daemon from `config.toml`; service runner & TUI dashboard | [Portal Agent Guide](/portal-agent) |
| **Automation** | [AI coding assistant plugins](#ai-coding-assistant-plugins) | Plugins | `portal-expose` and `portal-connect` skills for Codex, Claude, Cursor | [Agent Plugin Guide](https://github.com/gosuda/portal-tunnel/blob/main/plugins/portal-deploy/README.md) |
| **Naming** | [Custom hostnames and ENS](#custom-hostnames-and-ens) | CLI, Agent, Relay | Custom DNS prefixes, canonical identity names, and verified ENS records | [Wallet & ENS: Naming](/wallet-and-ens#ens-and-custom-domains) |

---

## Detailed Capability Breakdown

### Exposure & Web Serving

#### Public HTTPS localhost tunnel
- **Interfaces**: CLI, Agent, SDK, Relay
- **Description**: Publish local HTTP applications to a public HTTPS URL through self-hosted or public relays without opening inbound firewall ports or configuring DNS.
- **Boundaries**: In the default stream path, tenant TLS terminates locally in the tunnel process. The relay acts strictly as an SNI router.
- **Reference**: [Getting Started](/getting-started), [Concepts: Default Stream Path](/concepts#default-stream-path)

#### Multi-upstream routed HTTP
- **Interfaces**: CLI, Agent, SDK
- **Description**: Mount multiple local HTTP upstreams (such as a frontend and backend API) behind a single public hostname using longest-prefix route matching.
- **Boundaries**: Route parsing and forwarding occur entirely within the local tunnel process. Cannot be combined with raw TCP or UDP flags.
- **Reference**: [Concepts: Routed HTTP Mode](/concepts#routed-http-mode), [CLI Reference: Modes](/cli-reference#modes)

#### Local static serving
- **Interfaces**: CLI, Agent, SDK
- **Description**: Host static directories or single-page apps (SPA/CSR entry points) directly from the filesystem without running a local web server.
- **Boundaries**: Paths escaping the directory are refused (`..` traversal check). The entry file must exist at startup.
- **Reference**: [CLI Reference: Static Site](/cli-reference#modes), [Portal Agent: Static Site](/portal-agent#static-site)

#### Opt-in relay static cache
- **Interfaces**: CLI, Relay
- **Description**: Offload static site files to selected relays to serve assets with relay-terminated TLS and edge caching.
- **Boundaries**: Explicit opt-in (`--cache`) that delegates browser TLS termination and asset trust to the selected relays. Applies strictly to the identity-bound canonical hostname; friendly aliases remain live-origin routes. Incompatible with `--ban-mitm`.
- **Reference**: [Security Model: Opt-In Static Cache](/security-model#opt-in-static-cache), [CLI Reference: Static Content Offload](/cli-reference#static-content-offload)

---

### Transport & Networking

#### Dedicated raw TCP
- **Interfaces**: CLI, SDK, Relay
- **Description**: Allocate a dedicated public TCP port on the relay to tunnel non-HTTP traffic, such as SSH, database connections, and Minecraft servers.
- **Boundaries**: Relays must enable TCP port allocations (`TCP_ENABLED=true`, `MIN_PORT`-`MAX_PORT`). Traffic is raw TCP without Portal-provided TLS.
- **Reference**: [TCP/UDP Tunneling: Dedicated Raw TCP](/tcp-udp-tunneling#dedicated-raw-tcp), [Concepts: Dedicated Raw TCP](/concepts#dedicated-raw-tcp)

#### UDP relay
- **Interfaces**: CLI, SDK, Relay
- **Description**: Forward UDP datagrams across the tunnel backhaul for game servers and real-time datagram protocols.
- **Boundaries**: Carried over a QUIC tunnel connection using QUIC DATAGRAM frames. Requires relay UDP support (`UDP_ENABLED=true`).
- **Reference**: [TCP/UDP Tunneling: UDP Relay](/tcp-udp-tunneling#udp-relay), [Concepts: UDP Relay](/concepts#udp-relay)

#### IVNP-backed overlay networking
- **Interfaces**: CLI, Agent, SDK, Relay
- **Description**: Bridge reverse tunnel backhaul through an independent IVNP overlay network between an overlay gateway and the public ingress.
- **Boundaries**: Portal selects and authorizes endpoints; IVNP owns the network path (routers, tunnels, and hop ordering). Direct reverse transport remains the default and fallback.
- **Reference**: [Concepts: IVNP-backed Overlay Networking](/concepts#ivnp-backed-overlay-networking), [Architecture: IVNP-backed Overlay Networking](/architecture#ivnp-backed-overlay-networking)

---

### Relays & Reliability

#### Public relay discovery
- **Interfaces**: CLI, Agent, SDK, Relay
- **Description**: Discover and connect to healthy public relays from the official registry and peer discovery announcements.
- **Boundaries**: Can be disabled via `--discovery=false`. Auto-selected relay pool size is capped by `--max-active-relays`.
- **Reference**: [Concepts: Multi-Relay Selection](/concepts#multi-relay-selection), [Configuration](/configuration)

#### Explicit and self-hosted relays
- **Interfaces**: CLI, Agent, SDK, Relay
- **Description**: Deploy fully open-source, MIT-licensed relays with zero telemetry or connect directly to chosen relay URLs.
- **Boundaries**: Explicitly specified relays are always connected and prioritized independently of auto-selected discovery pools.
- **Reference**: [Self-Hosting](/self-hosting), [Deployment](/deployment)

#### Multi-relay failover
- **Interfaces**: CLI, Agent, SDK
- **Description**: Maintain simultaneous reverse sessions across multiple relays so that incoming traffic fails over seamlessly if a relay goes offline.
- **Boundaries**: Handled automatically by the underlying `sdk.Exposure` multi-listener runtime.
- **Reference**: [Concepts: Multi-Relay Selection](/concepts#multi-relay-selection), [Portal Agent](/portal-agent)

---

### Security & Cryptography

#### Endpoint tenant TLS
- **Interfaces**: CLI, Agent, SDK
- **Description**: Terminate browser TLS inside the local tunnel process rather than at the relay, preserving client privacy.
- **Boundaries**: Standard for all uncached HTTPS stream and routed HTTP exposures. The relay sees only encrypted ciphertext.
- **Reference**: [Security Model: Tenant TLS](/security-model#tenant-tls-keyless-signing), [Concepts: Default Stream Path](/concepts#default-stream-path)

#### Keyless certificate signing
- **Interfaces**: CLI, Agent, SDK, Relay
- **Description**: Sign TLS handshake transcripts remotely through the relay's `/v1/sign` endpoint for relay-hosted wildcard domains.
- **Boundaries**: The relay acts as a keyless signing oracle for live connections; tenant private keys and session keys are never shared with the relay.
- **Reference**: [Security Model: Keyless Signing](/security-model#tenant-tls-keyless-signing), [Architecture: Keyless Signing](/architecture#tenant-tls-keyless-signing)

#### MITM self-probe
- **Interfaces**: CLI, SDK
- **Description**: Validate that the relay is not terminating TLS by establishing an active self-connection and comparing exported TLS keying material on both ends.
- **Boundaries**: Runs after real traffic begins. Enabled on tenant TLS exposures; passing `--ban-mitm` automatically bans a relay if keying material does not match.
- **Reference**: [Security Model: MITM Self-Probe](/security-model#mitm-self-probe), [Concepts: MITM Self-Probe](/concepts#mitm-self-probe)

---

### Identity, Auth & Naming

#### Local secp256k1 identity
- **Interfaces**: CLI, Agent, SDK
- **Description**: Prove lease ownership and establish authenticated tunnels using a local secp256k1 private key without accounts, passwords, or emails.
- **Boundaries**: Stored in `identity.json`. Reusing the identity preserves reservation of registered names.
- **Reference**: [Wallet & ENS: Tunnel Identities](/wallet-and-ens#tunnel-identities-and-wallets), [Concepts: Identity and Lease Authentication](/concepts#identity-and-lease-authentication)

#### SIWE application authentication
- **Interfaces**: CLI, Agent, Relay
- **Description**: Protect HTTP services with Sign-In with Ethereum (EIP-4361) wallet login and inject verified wallet identity headers upstream.
- **Boundaries**: Authentication occurs at the tunnel layer. Cannot be combined with `--cache`, `--tcp`, or `--udp`.
- **Reference**: [Application Authentication: SIWE](/siwe-authentication), [CLI Reference: Modes](/cli-reference#modes)

#### Custom hostnames and ENS
- **Interfaces**: CLI, Agent, Relay
- **Description**: Request custom subdomain prefixes, resolve canonical identity-bound hostnames, and attach verified Ethereum Name Service (ENS) records.
- **Boundaries**: Prefixes are subject to relay validation and availability. ENS requires public on-chain verification.
- **Reference**: [Wallet & ENS: ENS and Custom Domains](/wallet-and-ens#ens-and-custom-domains)

---

### Payments, Operations & Automation

#### x402 Sui payments
- **Interfaces**: CLI, Agent, SDK
- **Description**: Enforce gasless Sui USDC payments on specific routed HTTP paths before proxying traffic upstream.
- **Boundaries**: Requires `--x402-pay-to`. Includes `/x402/client.js` for seamless browser wallet integration and `/x402/prepare` for native clients.
- **Reference**: [Concepts: Routed HTTP Mode (Payments)](/concepts#routed-http-mode), [API Reference: Payments](/api-reference#payments)

#### x402 Casper payments
- **Interfaces**: CLI, Agent
- **Description**: Protect routed HTTP endpoints with Casper wCSPR token payments settled through Casper facilitators.
- **Boundaries**: Requires `--x402-network`, `--x402-asset`, and facilitator credentials (e.g. CSPR.cloud API key).
- **Reference**: [API Reference: Casper wCSPR Support](/api-reference#casper-wcpr-x402-support)

#### Portal Agent
- **Interfaces**: CLI, Agent
- **Description**: Run persistent multi-tunnel setups defined in a single TOML configuration file, manage system services, and inspect live relays with an interactive TUI dashboard.
- **Boundaries**: Designed for long-running endpoints and server environments outside interactive shell sessions.
- **Reference**: [Portal Agent Guide](/portal-agent), [Configuration Reference: Agent](/configuration#agent-configuration)

#### AI coding assistant plugins
- **Interfaces**: Plugins / Skills
- **Description**: Shared skills (`portal-expose` and `portal-connect`) enabling AI assistants (Codex, Claude Code, Cursor) to expose local apps, verify public URLs, and test paid routes.
- **Boundaries**: Requires an AI assistant runtime supporting skills (`gh skill` or `npx skills`).
- **Reference**: [Agent Plugin README](https://github.com/gosuda/portal-tunnel/blob/main/plugins/portal-deploy/README.md), [Getting Started: AI Assistant Plugin](/getting-started#ai-assistant-plugins)
