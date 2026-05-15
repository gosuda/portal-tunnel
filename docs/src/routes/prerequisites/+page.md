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
| OS | Linux (amd64/arm64), macOS (amd64/arm64), Windows (amd64) |
| Network | Outbound TCP access for tunnel clients |
| Disk | About 10 MB for the binary |

## For Tunnel Users

- A local service running on a TCP port, for example a web server on
  `localhost:3000`
- Internet connectivity to reach a relay server

No accounts, API keys, billing setup, inbound firewall rules, or browser wallet
are required for normal tunnel use.

## For Relay Operators

If you plan to run your own relay server:

- A server with a public IP address
- A domain name with DNS pointing to the server
- TLS certificate material, either managed through ACME or manually provided
- Open inbound `443/tcp` and `4017/tcp`
- Optional UDP and raw TCP transport port ranges

## Optional

- Ethereum wallet for relay admin login or optional local agent status access
- DNS provider account for relay-managed ACME, ECH DNS records, and optional ENS
  gasless DNS import

## Next Steps

- [Getting Started](/getting-started): install Portal and create your first tunnel
- [Wallet and ENS](/wallet-and-ens): understand wallet auth and ENS gasless DNS
