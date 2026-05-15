---
title: SIWE Authentication
description: How Portal uses SIWE for tunnel registration and wallet sessions.
---

# SIWE Authentication

Portal uses Sign-In with Ethereum (SIWE) in two places:

- tunnel registration, signed automatically by the local tunnel identity
- browser wallet sessions for relay admin and optional local agent status access

For the full operational guide, see [Wallet and ENS](/wallet-and-ens).

## Tunnel Registration

`portal expose` and `portal agent` create or load a local secp256k1 identity
from `identity.json`. During registration, the relay returns a SIWE challenge
with statement `Register a portal lease`; the tunnel signs it with the local
identity private key and receives a lease access token.

This flow is automatic. It does not require a browser wallet.

```bash
portal expose 3000 --name myapp
```

There is no `--auth siwe` flag. SIWE is part of the normal registration
protocol.

## Wallet Sessions

The relay admin UI uses browser wallet login:

1. request `/admin/auth/challenge`
2. sign the returned SIWE message with the connected wallet
3. submit `/admin/auth/login`
4. use the resulting `portal_admin` session cookie

The relay identity address is allowed by default. Add more admin wallets with
`ADMIN_WALLETS`.

The local agent also exposes `/v1/agent/auth/*` wallet endpoints. Agent wallet
sessions can read `/v1/agent/status`; tunnel mutations still require the local
bearer token stored in the agent state directory.

## ENS

Portal does not use ENS names as tunnel names. Tunnel names are single DNS
labels such as `myapp`.

Relay operators can optionally enable ENS gasless DNS import. In that mode,
Portal manages DNSSEC and `ENS1 ...` TXT records for the relay domain and lease
hostnames so ENS-aware clients can resolve them to Portal identity addresses.

## Next Steps

- [Wallet and ENS](/wallet-and-ens): detailed wallet and ENS behavior
- [Security Model](/security-model): encryption and identity boundaries
- [Configuration](/configuration): full configuration reference
