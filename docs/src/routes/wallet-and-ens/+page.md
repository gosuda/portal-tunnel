---
title: Sui Wallet and ENS
description: How Portal uses Sui identities, Sui wallet login, zkLogin-compatible auth, and optional ENS DNS import.
---

# Sui Wallet and ENS

Portal uses Sui addresses for tunnel identity, relay identity, admin login, and
paid routes. ENS remains a small optional DNS import surface and still requires
an Ethereum address only for the `ENS1 ...` TXT record payload.

## Identity Surfaces

| Surface | Key material | Purpose |
|---------|--------------|---------|
| Tunnel identity | Local Sui Ed25519 key or BIP-39 mnemonic at `m/44'/784'/0'/0'/0'` | Signs Sui lease registration challenges |
| Relay identity | Relay Sui Ed25519 key | Signs relay descriptors and lease access tokens |
| Relay admin wallet | Sui wallet or zkLogin Sui address allowlist | Signs in to `/admin` and receives an admin bearer token |
| Agent wallet | Optional Sui address allowlist | Reads loopback agent status through `/agent/status` |
| ENS DNS import | DNSSEC plus `ENS1 ...` TXT records | Lets ENS-aware clients import configured hostnames |

## Sui Registration

Tunnel registration uses a Sui personal-message challenge internally:

1. The tunnel creates or loads a local Sui identity from `identity.json`.
2. The tunnel asks the relay for `/sdk/register/challenge`.
3. The relay returns a canonical Sui auth message.
4. The tunnel signs that message with the local Sui Ed25519 key.
5. The relay verifies the Sui signature and returns a lease-scoped token.

This does not require a browser wallet. It is accountless identity proof based
on the local tunnel key.

## Admin Login

The relay admin API accepts Sui wallet personal-message signatures and
zkLogin-compatible Sui signatures. Allowed admin addresses come from
`ADMIN_WALLETS`; the relay identity Sui address is always allowed.

```bash
ADMIN_WALLETS=0xabc...,0xdef...
```

Admin wallet flow:

1. `POST /api/admin/auth/challenge` with `{ "address": "0x...", "auth_method": "sui_wallet" }`.
2. Sign the returned `message` in the Sui wallet.
3. `POST /api/admin/auth/login` with the challenge id, address, message, and signature.
4. The relay returns an `access_token`.

Challenges expire after two minutes. Admin bearer tokens expire after 24 hours.

## ENS DNS Import

ENS gasless DNS import is optional relay-side DNS automation. It is separate
from Sui registration, Sui wallet login, and Sui payments.

When enabled, Portal publishes TXT values in this shape:

```text
ENS1 0x238A8F792dFA6033814B18618aD4100654aeef01 <ethereum-address>
```

Set the ENS import address explicitly with the ENS gasless configuration. Portal
does not reuse the relay Sui identity address as an ENS address.
