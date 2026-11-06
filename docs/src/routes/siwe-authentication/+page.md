---
title: Application Access Authentication
description: Let only chosen people open a tunnel, with Portal credential links, an Ethereum wallet, OpenID Connect, SAML 2.0, or email link sign-in.
---

# Application Access Authentication

> **Maintainer note**: the method table, allowlist forms, session lifetime, secret handling, and verification steps on this page are mirrored in the agent skill reference at `plugins/portal-deploy/skills/portal-expose/references/application-auth.md`. When sign-in behavior changes, update both files. This page is the human-facing source; the reference is the agent-facing copy.

Without `--auth`, anyone who learns a tunnel's hostname can open the app. Portal
can ask visitors to sign in first. The check runs inside the `portal` process on
your machine, not at the relay, so it also protects static sites and every
routed path. Pick one method:

| You want | Use | Visitors need | You need |
|---|---|---|---|
| A few named people, nothing to set up | [`--auth credential`](#portal-credentials) | A link you create with `portal auth issue` | Nothing |
| People who own an Ethereum wallet | [`--auth siwe`](#siwe-application-access) | A browser wallet | Nothing |
| People who sign in with Google, Microsoft, Keycloak, GitLab or another OpenID Connect provider | [`--auth oidc`](#openid-connect-oidc) | An account at that provider | An OAuth client registered at the provider |
| People who sign in at a SAML identity provider such as Okta, Entra ID, ADFS, Keycloak or Shibboleth | [`--auth saml`](#saml-20) | An account at that provider | A SAML application registered at the provider |
| People you know by email address | [`--auth email`](#email-links) | A mailbox | An SMTP account, such as a mailbox app password or a transactional mail service |

Two keys hold the list of who may sign in. `--auth-allow`
(`auth_allowed_wallets` in `config.toml`) is the list for `siwe` and
`credential`. `--auth-email-list` (`auth_email_list`) is the list for `oidc`,
`saml`, and `email`: a tunnel runs one provider, so the one list serves all
three. `oidc` and `saml` still read `--auth-allow` / `auth_allowed_wallets`, so
existing configs keep working. Setting both keys is refused. `email` takes only
`--auth-email-list`.

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
HTTPS redeem URL. Send the URL to the intended user. A credential works only on
the host it was issued for, so issue it for the host of the URL you share: the
short URL when the relay granted it, otherwise the identity-bound one. The
credential is carried in the URL fragment, so it is not sent to the relay or web server as part of
the request URL. The tunnel-local login page submits it to the same-origin
redeem endpoint and stores the resulting `Secure`, `HttpOnly`, `SameSite=Lax`
session cookie.

Credentials contain a subject, tunnel identity, host, and expiry and are signed
with a key derived locally from the tunnel identity. A session never outlives
the credential it redeemed. The credential remains redeemable until expiry; operators can pass `--auth-allow <subject>`
(or `auth_allowed_wallets` in `config.toml`) to restrict allowed credential subjects
and revoke individual subjects immediately on both active sessions and bearer requests. Keep that list non-empty: with no `--auth-allow`, every unexpired credential is accepted, so removing the last subject reopens access instead of ending it.

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
in. Repeat `--auth-allow` to restrict access to specific Ethereum addresses; removing the last one empties the list and lets any wallet in again.
Portal keeps the two-minute, single-use challenge and the 24-hour signed
session local to the tunnel endpoint. The cookie is `Secure`, `HttpOnly`, and
`SameSite=Lax`. Portal removes that session cookie before forwarding the
request, while preserving application-owned cookies; relay-issued lease tokens
are not used for application access.

Inbound `X-Portal-User`, `X-Portal-Auth`, and `X-Portal-Proof` headers are always removed. Add
`--auth-identity-headers` to inject the verified subject and provider (`siwe`,
`credential`, `oidc`, `saml`, or `email`) after login. Upstreams must only trust these headers when they cannot be
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
# AUTH_OIDC_CLIENT_SECRET is set in this shell first; see the prompt below
portal expose 3000 \
  --name myapp \
  --auth oidc \
  --auth-oidc-issuer https://accounts.google.com \
  --auth-oidc-client-id "$OIDC_CLIENT_ID" \
  --auth-email-list alice@example.com
```

Configure the identity provider's redirect URI as `https://<tunnel-host>/_portal/auth/callback`. Portal builds it from the host the visitor opened, so register it for every host visitors use: the short `<name>.<relay-domain>` URL and the identity-bound one, on every relay the tunnel is published on. Pinning one relay with `--relays <url> --discovery=false` keeps that list short. Portal verifies the ID token against the provider's `.well-known/openid-configuration` and `jwks_uri` and enforces `--auth-email-list` on login and on every subsequent session request. A session is bound to the issuer and client ID that created it, so changing `--auth-oidc-issuer` or `--auth-oidc-client-id` signs every visitor out; rotating the client secret does not. On the not-allowed screen, Sign in again asks the provider for its account chooser, so a browser still signed in to the refused account can pick another one.

`--auth-email-list` is required with `--auth oidc`: an identity provider authenticates accounts it does not restrict to your application, so without an allowlist every one of them would pass, and Portal refuses to start. It accepts an email address, an `@example.com` domain (that exact domain only, not its subdomains), or a `sub:<subject>` entry for the provider's opaque `sub` claim. Email and domain entries match only when the ID token carries `email_verified: true`; a provider that omits the claim, or one whose `sub` is not an email, can be allowed by `sub:` only. A `sub` claim value can never satisfy an email or domain entry, so an email-shaped `sub` cannot impersonate a verified-email allowlist entry.

Email and domain entries are compared in lowercase and must be ASCII, so write an internationalized domain in punycode. A `sub:` entry is compared exactly, including case, because the provider's `sub` is a case-sensitive identifier: `sub:Alice` does not allow the subject `alice`.

An OIDC session lasts as long as the ID token, but never less than 15 minutes, so a short-lived token does not send the visitor through the provider again at once, and never more than 24 hours. Revoking a principal takes effect on the next request whatever the session lifetime, because `--auth-email-list` is checked every time.

Pass the client secret as `AUTH_OIDC_CLIENT_SECRET`, as above, so it stays out of the process list. Typing the secret after `export` saves it in the shell history; reading it at a prompt avoids that. Run these lines in the same shell session that then starts `portal expose`. If you press Ctrl-C at the Linux and macOS prompt, run `stty echo` to see what you type again.

Linux and macOS (bash, zsh):

```bash
printf 'OIDC client secret: '; stty -echo; read -r AUTH_OIDC_CLIENT_SECRET; stty echo; echo; export AUTH_OIDC_CLIENT_SECRET
```

Windows PowerShell:

```powershell
$secret = Read-Host 'OIDC client secret' -AsSecureString; $env:AUTH_OIDC_CLIENT_SECRET = [System.Net.NetworkCredential]::new('', $secret).Password
```

At start Portal fetches the provider's discovery document and keys once and logs `application auth provider is not usable` if that fails; the tunnel keeps running and visitors can sign in once the provider is reachable.

## SAML 2.0

Use `--auth saml` to sign visitors in at a SAML 2.0 identity provider (IdP),
such as Keycloak, Okta, Microsoft Entra ID, ADFS or Shibboleth. Use it when the
provider issues no OpenID Connect client. Portal reads the IdP metadata and
verifies each signed response on your machine. The relay never sees the
assertion.

```bash
portal expose 3000 \
  --name myapp \
  --auth saml \
  --auth-saml-metadata-url https://idp.example.com/realms/main/protocol/saml/descriptor \
  --auth-email-list @example.com
```

### Set up the identity provider

Portal is the service provider (SP), the application that the IdP signs
visitors in to. Portal serves two addresses on every host a visitor opens:

| Address | Use |
|---|---|
| `https://<tunnel-host>/_portal/auth/saml/metadata` | The SP metadata to import at the IdP |
| `https://<tunnel-host>/_portal/auth/saml/acs` | The assertion consumer service (ACS), with the HTTP-POST binding |

1. Start the tunnel once and note each host that Portal prints after `service ready at`.
2. At the IdP, add a SAML application. Import the SP metadata from the metadata address, or enter the ACS address and the entity ID by hand.
3. Set the IdP to sign the response, the assertion, or both.
4. Set the IdP to send unencrypted assertions. Portal sends unsigned requests, so the IdP must not require a signed `AuthnRequest`.
5. Choose the subject: a NameID format, or an attribute that you name with `--auth-saml-subject-attribute`. The next section explains the choice.
6. Copy the IdP metadata address into `--auth-saml-metadata-url`.

In Keycloak, create a client with the client type SAML. The client ID is the
entity ID, and the realm metadata is at
`https://<keycloak-host>/realms/<realm>/protocol/saml/descriptor`. Keep Sign
documents on, and turn Client signature required and Encrypt assertions off.

The SP entity ID is the metadata address of the host the visitor opened,
unless you set `--auth-saml-entity-id`. The ACS address also follows that
host, as the OIDC redirect URI does. A tunnel has a short
`<name>.<relay-domain>` URL and an identity-bound URL on every relay that
publishes it. If visitors use more than one host, set one
`--auth-saml-entity-id`, so that the IdP sees one application, and register the
ACS address of every host with it. To keep that list short, pin one relay with
`--relays <url> --discovery=false`.

If the IdP publishes no metadata URL, save its metadata XML to a file and use
`--auth-saml-metadata-file <path>` instead. Set one of the two sources. Portal
reads the metadata again every 15 minutes, so a new signing key in the metadata
takes effect without a restart. Portal refuses metadata in which every signing
certificate has expired, because no signature by such a certificate is
accepted. If the IdP keeps signing with an expired certificate, renew it at the
IdP. At start, Portal reads the metadata once and logs `application auth
provider is not usable` if that fails. The tunnel keeps running.

### Who may sign in with SAML

`--auth-email-list` is required with `--auth saml`, for the same reason as with
OIDC. The subject is the `NameID` of the assertion, or the single value of the
attribute that `--auth-saml-subject-attribute` names, for example `email`. The
allowlist entries take the OIDC forms:

- An email address, or an `@example.com` domain, matches a subject that is an email address. A domain entry matches that exact domain only, not its subdomains.
- A `sub:<subject>` entry matches the subject exactly, including case, whatever the subject holds.

SAML has no `email_verified` claim, so Portal treats an email that the IdP signs
as verified. Set the IdP to release only an address that its users cannot
change. If the IdP cannot guarantee this, allow a stable NameID with `sub:`
entries, for example one in the persistent format. A transient NameID changes
at every login, so it never matches a `sub:` entry.

### What Portal checks

Portal checks the XML signature with the maintained `gosaml2` and `goxmldsig`
libraries. Portal accepts a response only when all of these conditions are
true:

- The response is signed, or every assertion in it is signed, with a certificate from the IdP metadata. A response that mixes signed and unsigned assertions is refused.
- The response carries exactly one assertion.
- The issuer is the entity ID in the IdP metadata, and the status is success.
- The destination and the recipient are the ACS address of this host, and the audience is the SP entity ID.
- The response and the assertion answer the `AuthnRequest` of this browser (`InResponseTo`). Portal keeps the request ID in a signed cookie for 10 minutes.
- The assertion is inside its `NotBefore` and `NotOnOrAfter` window, with one minute of clock skew.
- Portal did not accept the assertion ID before. Portal remembers each accepted ID until the login state that it answered expires.

Portal accepts a signed response with an unsigned assertion inside, as well as
signed assertions in an unsigned response. It never accepts a response in which
neither is signed. For this reason, the SP metadata does not set
`WantAssertionsSigned`.

Portal keeps the accepted assertion IDs in memory, so a restart of the tunnel
forgets them. An assertion that Portal accepted just before a restart can then
be presented once more until its 10-minute login state expires. Only someone
who holds both the response and the visitor's state cookie can do that.

IdP-initiated sign-in, which starts at the IdP's application list, is refused,
because such a response answers no request of this tunnel. Visitors start at
the tunnel address instead. Portal does not support single logout.

A SAML session follows the `SessionNotOnOrAfter` of the assertion when the IdP
sends one, but never lasts less than 15 minutes or more than 24 hours. Without
it, the session lasts 24 hours. The `NotOnOrAfter` of the assertion only limits
when Portal accepts the assertion. Portal checks `--auth-email-list` on every
request, so a removed entry ends its sessions at once. A session is also bound
to the metadata source, the entity ID and the subject attribute: a change to one
of them signs every visitor out. With `--auth-identity-headers`,
`X-Portal-User` carries the email or the `sub:` subject, and `X-Portal-Auth`
carries `saml`.

## Email links

Use `--auth email` to sign visitors in with a one-time link that Portal sends
by email. A visitor enters an email address on the sign-in page. If the address
is on the allowlist, Portal sends a link to it through your own SMTP account.
The link creates a 24-hour session. You need no identity provider, only an SMTP
account, for example a mailbox with an app password or a transactional mail
service. The SMTP settings and the password stay on your machine. The relay
never sees them.

```bash
# AUTH_SMTP_PASSWORD is set in this shell first; see the prompt below
portal expose 3000 \
  --name myapp \
  --auth email \
  --auth-smtp-addr smtp.gmail.com:587 \
  --auth-smtp-username you@gmail.com \
  --auth-smtp-from you@gmail.com \
  --auth-email-list alice@example.com \
  --auth-email-list @example.com
```

### Set up the SMTP account

1. Find the submission server of your mail provider as `host:port`, for example `smtp.gmail.com:587`. Set it with `--auth-smtp-addr`.
2. Create an app password or an SMTP credential at the provider. Set the username with `--auth-smtp-username` and the password with `AUTH_SMTP_PASSWORD`. Leave both empty only for a server that needs no login.
3. Set the sender with `--auth-smtp-from`. Use an address that your SMTP account can send from. You can add a display name, for example `"Portal <login@example.com>"`.

Every link comes from this one sender. No visitor input can change the sender,
the subject or the text of the mail. The mail has no `To` header, by design: the
recipient is named only in the SMTP envelope. Delivery, spam placement, SPF, DKIM
and DMARC belong to your SMTP account.

Portal picks the transport from the port. Port 465 uses TLS from the start. On
any other port, the server must offer STARTTLS, and Portal refuses to send the
password without it. Only a server at `localhost`, `127.0.0.1` or `::1`, such
as a local mail relay on `127.0.0.1:25`, can receive plaintext. These are the
names to which Go's SMTP client sends a password without TLS.

Portal signs in with AUTH PLAIN only. A server that offers only AUTH LOGIN fails
at the startup check.

Pass the password as `AUTH_SMTP_PASSWORD`, as with the OIDC client
secret, so that it stays out of the process list. Read it at a prompt to keep it
out of the shell history. Run these lines in the same shell session that then
starts `portal expose`.

Linux and macOS (bash, zsh):

```bash
printf 'SMTP password: '; stty -echo; read -r AUTH_SMTP_PASSWORD; stty echo; echo; export AUTH_SMTP_PASSWORD
```

Windows PowerShell:

```powershell
$secret = Read-Host 'SMTP password' -AsSecureString; $env:AUTH_SMTP_PASSWORD = [System.Net.NetworkCredential]::new('', $secret).Password
```

When the tunnel starts, Portal checks the SMTP server once and sends no mail.
The check proves the server, TLS, and the login. It sends no `MAIL FROM`, so it
does not prove the sender. With no username it signs in to nothing, so it proves
only that the server answers, with TLS where TLS is required. If the check fails,
Portal logs `application auth provider is not usable`, and the agent shows the
error as the provider check. The tunnel keeps running.

### Who may sign in with email

`--auth-email-list` is required with `--auth email`. Without a list, anyone
could make the tunnel send mail to any address, so Portal refuses to start. An
entry is an email address, or an `@example.com` domain that matches that exact
domain only, not its subdomains. A mailbox has no other account ID, so Portal
refuses `sub:` entries. Entries are compared in lowercase and must be ASCII, as
with OIDC. An address entry that no visitor could sign in with, for example one
that contains a space, `%` or `!`, stops the tunnel at startup.

Portal refuses a visitor's address that contains `%` or `!` with `400`. A mail
server can route on those characters, so the allowlist could not vouch for where
the mail ends up.

The sign-in page gives the same answer for every other well-formed address: an
allowed address, an address that is not allowed, and an address over a limit.
Portal sends the mail after it answers, so the time of the answer shows nothing
either. For the same reason, a visitor never sees an SMTP error.

A failed send shows only in the tunnel log, as `email login link not sent`, and
the error on that line says why. For the recipient and data steps the error holds
only the SMTP reply code, never the recipient. The error
`every email send slot is in use` means that four sends were running, so Portal
dropped this one. A refusal by a limit or by the allowlist logs nothing, so a
quiet log can mean a refusal. A wrong server, TLS setup or login shows in the
startup check.

One address gets at most one link per minute and five links per hour. For an
address that you list exactly, this limit bounds the mail to its mailbox. An
`@domain` entry is different: `alice+1@example.com` and `alice+2@example.com` are
two addresses that can reach one mailbox, so only the budget below limits that
mailbox.

The addresses that only an `@domain` entry allows get at most 50 links per hour
together, because their number has no bound. All `@domain` entries share this one
budget, not one budget per domain. It protects the quota of your SMTP account. An
address that you list exactly is outside this budget.

Portal cannot tell visitors apart, because the relay does not pass on their IP
addresses. So one visitor can use up the budget with made-up addresses in any
allowed domain. Then the real addresses of every `@domain` entry get no link
while the flood lasts and for up to an hour after it, because the window rolls.
Their visitors see no error. The same requests also make your SMTP account send
up to 50 mails per hour to addresses that may not exist. If this matters, list
the addresses exactly instead of `@domain`.

### The link

The link opens the sign-in page with the token after `#`:
`https://<tunnel-host>/_portal/auth/login#email_token=...`. A browser does not
send the part after `#` to a server. The page removes the token from the address
when it loads and shows a Continue button. It posts the token to Portal only on
that click. So a mail scanner or a link preview that only fetches the URL, or
that opens the page and runs its script without clicking, does not use up the
link.

The token holds 256 random bits. Portal keeps only its SHA-256 hash in memory,
with the address and the host. A link works once, for 10 minutes, and only on
the host that it was sent for. A restart of the tunnel cancels every link that
was not used. The visitor then asks for a new link.

Portal sends a link only for a host where the tunnel is published now: the
identity-bound URL of a relay, or the short URL while that relay holds the
name. Portal refuses a request for any other host with `403`. This keeps a
forged `Host` header from putting another host into the link.

The link is not bound to the browser that asked for it. A visitor can ask on a
computer and open the mail on a phone. Anyone who can read the mail can use the
link once, so the link is as safe as the mailbox.

Portal checks `--auth-email-list` again when the link is used and on every
request, so a removed entry ends its sessions at once. A session is also bound to the
SMTP server, the SMTP username and the sender. If you change one of them, for
example after the mail account was compromised, every email session ends. A
new password alone does not end the sessions. With `--auth-identity-headers`,
`X-Portal-User` carries the email address, and `X-Portal-Auth` carries `email`.

## Check That Sign-In Is On

An unauthenticated `GET` or `HEAD` request is sent to the login page, and any
other method is refused:

```bash
curl -sI https://myapp.example.com/            # 303, Location: /_portal/auth/login?next=%2F
curl -s -X POST https://myapp.example.com/     # 401 {"error":"authentication required"}
```

A `200` means the gate is not on: check that `--auth` is on the command you ran.
With OIDC or SAML, use `GET` for `/_portal/auth/login`, which answers `303` to
the provider; a `HEAD` request is refused with `405`.

With email, ask for a link for an address that is on no allowlist. The answer is
`202`, and no mail goes out:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Origin: https://myapp.example.com' -H 'Content-Type: application/json' \
  -d '{"email":"nobody@example.invalid"}' \
  https://myapp.example.com/_portal/auth/email/request     # 202
```

A `403` means that the tunnel is not published at that host now.

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
