---
title: Application Access Authentication
description: Let only chosen people open a tunnel, with Portal credential links, an Ethereum wallet, or OpenID Connect sign-in.
---

# Application Access Authentication

Without `--auth`, anyone who learns a tunnel's hostname can open the app. Portal
can ask visitors to sign in first. The check runs inside the `portal` process on
your machine, not at the relay, so it also protects static sites and every
routed path. Pick one method:

| You want | Use | Visitors need | You need |
|---|---|---|---|
| A few named people, nothing to set up | [`--auth credential`](#portal-credentials) | A link you create with `portal auth issue` | Nothing |
| People who own an Ethereum wallet | [`--auth siwe`](#siwe-application-access) | A browser wallet | Nothing |
| People who sign in with Google, Microsoft, Keycloak, GitLab or another OpenID Connect provider | [`--auth oidc`](#openid-connect-oidc) | An account at that provider | An OAuth client registered at the provider |

[Check that sign-in is on](#check-that-sign-in-is-on) once the tunnel runs. An AI
coding agent that follows the `portal-expose` skill reads the same steps in
[`application-auth.md`](https://github.com/gosuda/portal-tunnel/blob/main/plugins/portal-deploy/skills/portal-expose/references/application-auth.md).

SIWE is also used separately for:

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

Use the `credential` provider when visitors should not need an Ethereum wallet or
EIP-1193 browser extension:

```bash
portal expose 3000 --auth credential
portal auth issue myapp.example.com --subject alice --expires 720h
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
the credential it redeemed. The credential remains redeemable until expiry; operators can pass `--auth-allow <subject>`
(or `auth_allowed_wallets` in `config.toml`) to restrict allowed credential subjects
and revoke individual subjects immediately on both active sessions and bearer requests.

API clients can present the same credential on each request:

```bash
curl -H "X-Portal-Access-Credential: $PORTAL_CREDENTIAL" https://myapp.example.com/api
```

Portal validates and removes this header before forwarding the request.

## SIWE Application Access

Use `--auth siwe` to require a browser wallet login before Portal forwards an
HTTP request:

```bash
portal expose 3000 --auth siwe --auth-allow 0x1234...
```

With no `--auth-allow`, any wallet that proves control of its address can sign
in. Repeat `--auth-allow` to restrict access to specific Ethereum addresses.
Portal keeps the two-minute, single-use challenge and the 24-hour signed
session local to the tunnel endpoint. The cookie is `Secure`, `HttpOnly`, and
`SameSite=Lax`. Portal removes that session cookie before forwarding the
request, while preserving application-owned cookies; relay-issued lease tokens
are not used for application access.

Inbound `X-Portal-User`, `X-Portal-Auth`, and `X-Portal-Proof` headers are always removed. Add
`--auth-identity-headers` to inject the verified subject and provider (`siwe`,
`credential`, or `oidc`) after login. Upstreams must only trust these headers when they cannot be
reached except through this local Portal proxy.

### Verifying the identity headers

An upstream on loopback can be reached by any other process on the machine, and
such a process can connect to it directly and send `X-Portal-User` itself. To let
the application tell Portal from that process, give Portal a secret of at least 16
visible ASCII characters (no spaces) together with `--auth-identity-headers`.
Generate a random one once, into a file outside the repository that only you can
read, and pass it as `AUTH_IDENTITY_PROOF` to the one command that starts this
tunnel:

```bash
(umask 077 && mkdir -p ~/.config/portal && openssl rand -hex 32 > ~/.config/portal/myapp.proof)
AUTH_IDENTITY_PROOF="$(cat ~/.config/portal/myapp.proof)" portal expose 3000 --auth siwe --auth-identity-headers
```

`openssl rand -hex 32` writes 64 random hexadecimal characters, and `umask 077`
makes the file readable by you alone. The secret is never typed, so it stays out
of the shell history, and the variable is set for that `portal expose` only, not
for later tunnels started from the same shell. It is passed through the
environment rather than as `--auth-identity-proof` because process lists show
command-line arguments. The application reads the same file.

Portal then sends `X-Portal-Proof: <secret>` with the identity headers on every
authenticated request, and removes any `X-Portal-Proof` a visitor sends. The
application compares the header with the same secret in constant time (for
example `subtle.ConstantTimeCompare` in Go, `hmac.compare_digest` in Python or
`crypto.timingSafeEqual` in Node.js) and ignores `X-Portal-User` and
`X-Portal-Auth` when it differs or is missing. The proof is optional and off by
default. It is sent to every upstream of the tunnel and in cleartext over a
plain `http` upstream, so use one secret per tunnel and keep it to upstreams you
trust with it. Anyone who sees one request can reuse the value, so do not log
`X-Portal-Proof` in the application (access logs, header-dumping middleware).

Application auth covers proxied HTTP routes, static sites, and x402 endpoints.
It cannot be combined with raw TCP/UDP or relay static caching.

## OpenID Connect (OIDC)

Use `--auth oidc` to authenticate visitors against any standard OpenID Connect provider (Google, Microsoft, GitLab, Authentik, Keycloak, Pocket ID) using the Authorization Code flow with PKCE (`S256`):

```bash
export AUTH_OIDC_CLIENT_SECRET=...   # read from the environment so it stays out of the process list
portal expose 3000 \
  --name myapp \
  --auth oidc \
  --auth-oidc-issuer https://accounts.google.com \
  --auth-oidc-client-id "$OIDC_CLIENT_ID" \
  --auth-allow alice@example.com
```

Configure the identity provider's redirect URI as `https://<tunnel-host>/_portal/auth/callback`. Portal verifies the ID token against the provider's `.well-known/openid-configuration` and `jwks_uri` and enforces `--auth-allow` on login and on every subsequent session request. A session is bound to the issuer and client ID that created it, so changing `--auth-oidc-issuer` or `--auth-oidc-client-id` signs every visitor out; rotating the client secret does not.

`--auth-allow` is required with `--auth oidc`: an identity provider authenticates accounts it does not restrict to your application, so without an allowlist every one of them would pass, and Portal refuses to start. It accepts an email address, an `@example.com` domain (that exact domain only, not its subdomains), or a `sub:<subject>` entry for the provider's opaque `sub` claim. Email and domain entries match only when the ID token carries `email_verified: true`; a provider that omits the claim, or one whose `sub` is not an email, can be allowed by `sub:` only. A `sub` claim value can never satisfy an email or domain entry, so an email-shaped `sub` cannot impersonate a verified-email allowlist entry.

Email and domain entries are compared in lowercase and must be ASCII, so write an internationalized domain in punycode. A `sub:` entry is compared exactly, including case, because the provider's `sub` is a case-sensitive identifier: `sub:Alice` does not allow the subject `alice`.

An OIDC session lasts as long as the ID token, but never less than 15 minutes, so a short-lived token does not send the visitor through the provider again at once, and never more than 24 hours. Revoking a principal takes effect on the next request whatever the session lifetime, because `--auth-allow` is checked every time.

Pass the client secret as `AUTH_OIDC_CLIENT_SECRET`, as above, so it stays out of the process list and the shell history. `AUTH_OIDC_ISSUER` and `AUTH_OIDC_CLIENT_ID` can replace the two flags, and all three are used only with `--auth oidc`. At start Portal fetches the provider's discovery document and keys once and logs `application auth provider is not usable` if that fails; the tunnel keeps running and visitors can sign in once the provider is reachable.

## Check that sign-in is on

An unauthenticated `GET` or `HEAD` request is sent to the login page, and any
other method is refused:

```bash
curl -sI https://myapp.example.com/            # 303, Location: /_portal/auth/login?next=%2F
curl -s -X POST https://myapp.example.com/     # 401 {"error":"authentication required"}
```

A `200` means the gate is not on: check that `--auth` is on the command you ran.
With OIDC, use `GET` for `/_portal/auth/login`, which answers `303` to the
provider; a `HEAD` request is refused with `405`.

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
