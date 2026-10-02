---
title: Application Access Authentication
description: Protect a tunnel with Portal credentials or SIWE wallet login.
---

# Application Access Authentication

Portal supports two application access providers: Portal-native credentials and
Sign-In with Ethereum (SIWE). SIWE is also used separately for:

- tunnel registration, signed automatically by the local tunnel identity
- optional tunnel-side access control for exposed HTTP applications
- optional browser wallet login for local agent status access

For the full operational guide, see [Wallet and ENS](/wallet-and-ens).

## Tunnel Registration

`portal expose` and `portal agent` create or load a local secp256k1 identity
from `identity.json`. During registration, the relay returns a SIWE challenge
with statement `Register a portal lease`; the tunnel signs it with the local
identity private key and receives a lease access token.

`identity.json` can store the signing key directly as `private_key`, or store a
BIP-39 `mnemonic` with `derivation_path` and let Portal derive the key at load
time.

This flow is automatic. It does not require a browser wallet.

```bash
portal expose 3000 --name myapp
```

## Portal Credentials

Use the `token` provider when visitors should not need an Ethereum wallet or
EIP-1193 browser extension:

```bash
portal expose 3000 --auth token
portal auth issue myapp.example.com --subject alice --expires 30d
```

The issue command loads the same existing `identity.json` used by the tunnel;
it never creates a new identity. It prints both the signed credential and an
HTTPS redeem URL. Send the URL to the intended user. The credential is carried
in the URL fragment, so it is not sent to the relay or web server as part of
the request URL. The tunnel-local login page submits it to the same-origin
redeem endpoint and stores the resulting `Secure`, `HttpOnly`, `SameSite=Lax`
session cookie.

Credentials contain a subject, tunnel identity, host, and expiry and are signed
with a key derived locally from the tunnel identity. A session never outlives
the credential it redeemed. The credential remains redeemable until expiry, so
operators should use a suitably short lifetime and deliver it as a bearer
secret.

## SIWE Application Access

Use `--auth siwe` to require a browser wallet login before Portal forwards an
HTTP request. Bare `--auth` remains an alias for `--auth siwe`:

```bash
portal expose 3000 --auth
portal expose 3000 --auth siwe --auth-allow 0x1234...
```

With no `--auth-allow`, any wallet that proves control of its address can sign
in. Repeat `--auth-allow` to restrict access to specific Ethereum addresses.
Portal keeps the two-minute, single-use challenge and the 24-hour signed
session local to the tunnel endpoint. The cookie is `Secure`, `HttpOnly`, and
`SameSite=Lax`. Portal removes that session cookie before forwarding the
request, while preserving application-owned cookies; relay-issued lease tokens
are not used for application access.

Inbound `X-Portal-User` and `X-Portal-Auth` headers are always removed. Add
`--auth-identity-headers` to inject the verified subject and provider (`siwe`
or `token`) after login. Upstreams must only trust these headers when they cannot be
reached except through this local Portal proxy.

Application auth covers proxied HTTP routes, static sites, and x402 endpoints.
It cannot be combined with raw TCP/UDP or relay static caching.

## Agent Wallet Status Access

Relay admin access uses `ADMIN_TOKEN`, not SIWE.

The local agent also exposes `/agent/auth/*` wallet endpoints. Agent wallet
sessions can read `/agent/status`; tunnel mutations still require the local
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
