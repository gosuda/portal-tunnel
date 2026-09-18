---
title: Prerequisites
description: System requirements and prerequisites for running Portal tunnel.
---

# Prerequisites

Before installing Portal, make sure your environment meets the following
requirements.

## System Requirements

| Requirement | Minimum |
|-------------|---------|
| OS | Linux (amd64/arm64), macOS (amd64/arm64), Windows (amd64/arm64) |
| Network | Outbound TCP; UDP tunnels also require outbound UDP to the relay QUIC port |

## For Tunnel Users

- A local service running on a TCP port, for example a web server on
  `localhost:3000`
- Internet connectivity to reach a relay server

No accounts, API keys, billing setup, inbound firewall rules, or browser wallet
are required for normal tunnel use.

## For Relay Operators

If you plan to run your own relay server:

- A server with a public IP address
- A domain name; the default embedded DNS provider needs NS/glue delegation
  and inbound `53/tcp` plus `53/udp`
- TLS certificate material, either managed through ACME or manually provided
- Open inbound `443/tcp`
- Optional UDP and raw TCP transport port ranges

## Optional

- Long random admin token for relay admin access
- Ethereum wallet for optional local agent status access
- DNS provider API credentials if choosing an external provider; the default
  embedded provider manages ACME/ECH without a DNS vendor account

## Next Steps

- [Getting Started](/getting-started): install Portal and create your first tunnel
- [Wallet and ENS](/wallet-and-ens): understand admin tokens, wallet auth, and ENS gasless DNS
