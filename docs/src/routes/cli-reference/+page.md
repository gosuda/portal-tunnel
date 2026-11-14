---
title: CLI Reference
description: Complete reference for Portal CLI commands, flags, and usage examples.
---

# CLI Reference

The `portal` CLI exposes local services through Portal relay servers. The relay
provides transport and routing. The tunnel process decides whether a connection
is handled as the default HTTPS stream, routed HTTP, raw TCP, or UDP.

## Install

### macOS / Linux

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
```

### Windows PowerShell

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
```

### From A Relay

If your relay publishes its own installer:

```bash
curl -sSL https://portal.example.com/api/install.sh | bash
```

The installer downloads the `portal` binary and adds it to your `PATH`. It does
not create a config file.

## Command Overview

| Command | Purpose |
|---------|---------|
| `portal expose` | Expose one local service or one routed HTTP bundle |
| `portal auth issue` | Issue a Portal-native application access credential |
| `portal list` | Print relay URLs resolved for this invocation |
| `portal agent` | Run a durable local multi-tunnel agent |
| `portal update` | Replace the CLI with the latest release |
| `portal version` | Print the current version |

## `portal expose`

Common workflows:

```bash
portal expose 3000
portal expose 3000 --auth siwe
portal expose --serve ./dist
portal expose localhost:25565 --tcp
```

Expose a local service with optional flags:

```bash
portal expose [flags] <target>
```

Or run routed HTTP mode:

```bash
portal expose [flags] --http-route "PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT]" [...]
```

The payment suffix is optional; omit it for free routes.

### Target Formats

| Format | Example | Resolves to |
|--------|---------|-------------|
| Bare port | `3000` | `127.0.0.1:3000` |
| Host and port | `localhost:8080` | `localhost:8080` |
| URL host | `http://127.0.0.1:3000` | `127.0.0.1:3000` |

URL inputs are accepted for address parsing. Paths, queries, and fragments are
not supported.

### Mode Selection

| Mode | Example | Notes |
|------|---------|-------|
| Default HTTPS stream | `portal expose 3000` | Relay routes by SNI; tunnel process terminates tenant TLS |
| Static site | `portal expose --serve ./dist` | Serves a directory or an HTML file with SPA fallback |
| Routed HTTP | `portal expose --http-route /api=3001 --http-route /=5173` | Tunnel process runs the HTTP reverse proxy |
| Dedicated raw TCP | `portal expose localhost:25565 --tcp` | Relay allocates a public TCP port |
| UDP relay | `portal expose 8080 --udp --udp-addr 19132` | Relay allocates a public UDP port |

### Flags

`portal expose --help` (or `portal help expose`) lists common flags first, then
advanced flags for metadata, provider settings, and operations. Both groups are
accepted in the same command; advanced flags do not require a configuration file.

#### Common Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--name` | string | | Select this service under the signing identity and request its friendly alias; one normalized DNS label, at most 63 ASCII characters. Overrides a legacy saved name without rewriting the identity file |
| `--relays` | string | registry | Additional relay API URLs, comma-separated |
| `--discovery` | bool | `true` | Include registry relays and relay discovery expansion |
| `--overlay` | bool | `false` | Prefer an [IVNP overlay path](/concepts#ivnp-backed-overlay-networking) when available; retains direct fallback |
| `--http-route` | string | | HTTP route mapping in `PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT]` form; repeatable; route amounts require `--x402-pay-to` |
| `--serve` | string | | Serve a local directory or HTML file; unknown paths fall back to the entry HTML |
| `--tcp` | bool | `false` | Request a dedicated raw TCP port on the relay |
| `--udp` | bool | `false` | Enable public UDP relay in addition to the default stream path |
| `--auth` | string | | Protect HTTP application access with `siwe`, `credential`, `oidc`, `saml`, or `email`; cannot be combined with `--cache` |
| `--auth-allow` | string | | Principal allowed to sign in with `siwe` (Ethereum wallet) or `credential` (subject); repeat for multiple principals (empty allows any valid principal); `oidc` and `saml` also read it, as `--auth-email-list`; requires `--auth` |
| `--auth-email-list` | string | | Who may sign in with `oidc` or `saml` (verified email, `@example.com` domain, or `sub:<subject>`) or `email` (email or `@example.com` domain); repeat for multiple entries (at least one entry is required); requires `--auth` |
| `--auth-oidc-issuer` | string | | OIDC issuer URL for `--auth oidc` (env: `AUTH_OIDC_ISSUER`) |
| `--auth-oidc-client-id` | string | | OIDC client ID for `--auth oidc` (env: `AUTH_OIDC_CLIENT_ID`) |
| `--auth-oidc-client-secret` | string | | Optional OIDC client secret for `--auth oidc` (env: `AUTH_OIDC_CLIENT_SECRET`) |
| `--auth-saml-metadata-url` | string | | SAML identity provider metadata URL for `--auth saml` (env: `AUTH_SAML_METADATA_URL`) |
| `--auth-saml-metadata-file` | string | | SAML identity provider metadata file, instead of the URL, for `--auth saml` (env: `AUTH_SAML_METADATA_FILE`) |
| `--auth-saml-entity-id` | string | `https://<host>/_portal/auth/saml/metadata` | SAML service provider entity ID for `--auth saml` (env: `AUTH_SAML_ENTITY_ID`) |
| `--auth-saml-subject-attribute` | string | NameID | SAML attribute that names the visitor for `--auth saml`, such as `email` (env: `AUTH_SAML_SUBJECT_ATTRIBUTE`) |
| `--auth-smtp-addr` | string | | SMTP server `host:port` that sends the login links for `--auth email`; port 465 uses TLS from the start, any other port must offer STARTTLS, and only `localhost`, `127.0.0.1` or `::1` may use plaintext (env: `AUTH_SMTP_ADDR`) |
| `--auth-smtp-username` | string | | SMTP username for `--auth email`; set it together with the password, or leave both empty for a server that needs no login (env: `AUTH_SMTP_USERNAME`) |
| `--auth-smtp-password` | string | | SMTP password for `--auth email`, with spaces around it dropped; pass it by environment variable, because process lists show arguments (env: `AUTH_SMTP_PASSWORD`) |
| `--auth-smtp-from` | string | | The one sender address of every login link for `--auth email`, with an optional display name (env: `AUTH_SMTP_FROM`) |
| `--x402-pay-to` | string | | Payment recipient address for this tunnel |
| `--ban-mitm` | bool | `false` | Ban relay when the MITM self-probe detects TLS termination |
| `--identity-path` | string | `identity.json` | Identity JSON file path; created automatically when missing |

#### Advanced Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tls-auto` | bool | `false` | Obtain and renew exact canonical certificates through an approved relay; enables the Local TLS service namespace |
| `--tls-state-dir` | path | identity path plus `.tls` | Persistent automatic certificate/key storage; requires `--tls-auto`; must be explicit with `--identity-json` |
| `--tls-require-local` | bool | `false` | Require namespace support; in automatic mode also require usable canonical readiness. Requires automatic or manual Local TLS; manual mode already rejects legacy-only relays |
| `--tls-cert` | path | | Manual certificate chain PEM; requires `--tls-key`; only the exact service canonical DNS SAN is allowed |
| `--tls-key` | path | | Matching manual private key PEM; requires `--tls-cert` |
| `--tls-monitor-state-dir` | path | disabled | Opt into evaluation-only, warning-only [certificate monitoring](/keyless-tls#certificate-monitoring); persist evidence and send hostname queries to independent DNS and CertSpotter |
| `--tls-monitor-baseline` | path | unconfigured | Operator-managed CAA/SPKI baseline JSON; requires `--tls-monitor-state-dir` |
| `--tls-monitor-dns-resolver` | IP:port | `1.1.1.1:53` when enabled | Resolver for monitoring; requires `--tls-monitor-state-dir`; bracket IPv6 addresses |
| `--max-active-relays` | int | `3` | Maximum auto-selected relays to keep connected; explicit relays are always included |
| `--identity-json` | string | | In-memory identity JSON; takes precedence over `--identity-path` without reading or writing that file |
| `--description` | string | | Service description metadata |
| `--tags` | string | | Service tags metadata, comma-separated |
| `--thumbnail` | string | | Service thumbnail URL metadata |
| `--owner` | string | | Service owner metadata |
| `--hide` | bool | `false` | Hide service from relay listing screens |
| `--auth-identity-headers` | bool | `false` | Send authenticated `X-Portal-User` and `X-Portal-Auth` headers to HTTP upstreams; requires `--auth` |
| `--auth-identity-proof` | string | | Secret sent as `X-Portal-Proof` with the identity headers so the upstream can verify they came from Portal; at least 16 visible ASCII characters; requires `--auth-identity-headers`; pass it by environment variable, not on the command line, because process lists show arguments (env: `AUTH_IDENTITY_PROOF`) |
| `--x402-testnet` | bool | `false` | Use Sui testnet when `--x402-network` is omitted |
| `--x402-network` | string | | Optional Sui, Casper, or Nano CAIP-2 network |
| `--x402-asset` | string | | wCSPR CEP-18 contract hash required by Casper |
| `--x402-endpoint` | string | | Optional Sui RPC, Casper facilitator, or Nano RPC endpoint; repeatable |
| `--x402-facilitator-token` | string | `CSPR_CLOUD_API_KEY` | Casper facilitator authorization token; prefer the environment variable so the secret is not exposed in the process arguments |
| `--strip-request-header` | string | | Client request header removed before routed HTTP forwards it upstream; repeatable; case-insensitive; applies to HTTP and WebSocket upgrades; Portal-owned headers (`Host`, `X-Forwarded-*`) are always rewritten after stripping; requires `--http-route` or `--auth` |
| `--cache` | bool | `false` | Opt in to relay storage and browser TLS termination for `--serve` |
| `--cache-ttl` | duration | `0` | Requested offline cache lifetime; `0` uses relay policy; requires `--cache` |
| `--log-format` | string | `text` | Log output format; `json` sends application log records as one structured JSON record per line on stdout for machine integration; top-level command errors stay on stderr (see [Machine-Readable Relay Lifecycle](#machine-readable-relay-lifecycle)) |
| `--exit-on-stdin-eof` | bool | `false` | Bind the tunnel lifetime to a caller-owned stdin pipe or socket; closing its last writer requests normal shutdown |
| `--udp-addr` | string | | Local UDP target; defaults to the primary target when `--udp` is enabled |
| `--metrics-addr` | string | | Optional `host:port` for Prometheus `/metrics` |

### IVNP-backed overlay networking

```bash
portal expose 3000 --overlay
```

This asks the relay to prefer an available overlay gateway for reverse streams.
Portal selects and authorizes the endpoints; IVNP owns the gateway-to-ingress
path. Direct reverse transport remains the default and fallback. See
[the overlay networking concepts](/concepts#ivnp-backed-overlay-networking) for
why endpoint policy and network routing are separate, and
[the architecture](/architecture#ivnp-backed-overlay-networking) for the protocol.

### Identity Names

The identity file supplies the reusable signing key. An explicit `--name`
selects a service without rewriting that file, including when the file already
exists or the key comes from `--identity-json`. New identity files store no
service name. When the option is omitted, a legacy file's saved name remains
the compatibility default; otherwise the service is unnamed. Use distinct
explicit names to serve independent targets under one signing key.

For example, repeat `--name blog` when restarting a service with a newly created
identity file:

```bash
portal expose 3000 --identity-path ./identity.json --name blog
# On later runs, keep --name blog to select the same service.
portal expose 3000 --identity-path ./identity.json --name blog
```

Omitting `--name` on the later run selects the unnamed service because the new
file stores only the key identity. This changes the URL even though the signing
key is unchanged.

| Endpoint | Hostname | TLS and cache policy |
|---|---|---|
| Friendly alias, if available | `<name>.<relay-root>` | Keyless, HTTP/1.1, live origin only |
| Negotiated Local TLS canonical | `<service>.<40-lowercase-hex-address>.<relay-root>` | Tunnel-owned exact certificate, HTTP/1.1 and HTTP/2, never relay cached |
| Legacy canonical | `<address>.<relay-root>`, `<name>-<address>.<relay-root>`, or `<name-hash>--<address>.<relay-root>` | Existing Keyless and eligible opt-in cache behavior |

Local TLS uses `default` for an unnamed service; an explicitly named `default`
is rejected only in that namespace. Its service label can use all 63 octets.
Legacy names longer than 22 characters use a 21-character name hash to fit the
address into one label. Canonical-shaped service labels are rejected in both
modes. Depth is relative to the configured relay root, which may contain
multiple labels. A friendly alias collision does not prevent canonical service
registration.

### Tunnel-owned Local TLS

```bash
portal expose 3000 --name blog --identity-path identity.json \
  --tls-auto --tls-require-local
```

Automatic issuance needs a relay with tenant issuance enabled and, for public
CA orders, explicit approval for this service plus shared durable issuance
budget state. See [relay configuration](/configuration#public-tenant-issuance-admission).
Without `--tls-require-local`, an older relay may still provide legacy URLs, and
a compatible relay's legacy URL can become ready while canonical issuance is
pending. The new canonical hostname itself never falls back to Keyless.

Certificate/key bundles persist per hostname in `--tls-state-dir`, defaulting
to the identity file path plus `.tls`. With `--identity-json`, supply this
directory explicitly. Renewals reuse the stored leaf key. Issuance failure
keeps a still-valid certificate; expiry withdraws canonical readiness and
rejects new canonical TLS handshakes. Friendly and legacy endpoints stay separate.

For manual material, replace `--tls-auto` with `--tls-cert chain.pem --tls-key
key.pem`. Files must form a currently valid pair with exactly the assigned
canonical hostname as the only DNS SAN, without wildcard or sibling identities.
Pin the intended relay with `--relays <url> --discovery=false`. Files reload
during lease certificate checks, at most hourly after a successful check;
restart for immediate reload. Invalid replacements retain the previous usable
pair. Manual mode does not obtain or automatically renew certificates.

Moving to a new canonical is an explicit origin migration: update links,
callbacks, allowed origins, cookies, and browser storage as appropriate.
There is no automatic redirect. The separate legacy URLs remain supported
with no removal date currently specified. Local key ownership does not remove
the relay's DNS issuance authority or give ordinary browser JavaScript native
exporter verification; see the [security model](/security-model#local-tls-service-namespace).

### Constraints

- Automatic and manual Local TLS cannot be combined, and neither can be used
  with raw TCP, UDP, or relay static cache in the CLI/agent HTTP path.
- `--tls-state-dir` requires `--tls-auto`. `--tls-require-local` requires
  `--tls-auto` or a complete manual certificate/key pair; manual mode already
  rejects legacy-only relays.
- Certificate monitoring requires `--tls-monitor-state-dir`; its baseline and
  resolver options alone are invalid. Monitoring cannot be used with raw TCP,
  relay static cache, or browser/WASM exposures.
- Choose one of `<target>`, `--serve`, or `--http-route`.
- `--serve` cannot be combined with `--tcp` or `--udp`.
- `--cache` requires `--serve` and cannot be combined with `--ban-mitm`.
- `--cache-ttl` requires `--cache`; a nonzero value must be between `1s` and
  `8760h` and is clamped by the relay.
- `--http-route` cannot be combined with `--tcp` or `--udp`.
- `--strip-request-header` requires `--http-route` or `--auth`; it applies to
  every routed HTTP upstream, including WebSocket upgrades, and Portal-owned
  headers (`Host`, `X-Forwarded-*`) cannot be removed by it.
- `--tcp` and `--udp` require matching transport support on the relay.
- Route payment amounts are part of `--http-route` and require a tunnel-owned
  `--x402-pay-to`.
- Tunnel paid routes use Sui mainnet by default. Casper requires an explicit
  `--x402-network casper:...` and `--x402-asset`; it uses the hosted facilitator
  by default or the first `--x402-endpoint` override. The default CSPR.cloud
  facilitator also requires `CSPR_CLOUD_API_KEY`. Nano requires
  `--x402-network nano:mainnet` and a `nano_` pay-to address; repeat
  `--x402-endpoint` for at least two RPC nodes or omit it for the public
  defaults.

### Application-Owned Tunnel Lifetime

Applications launching Portal as a subprocess can own its lifetime through a
stdin pipe:

```bash
portal expose --http-route /=7317 --identity-path ./portal-identity.json \
  --exit-on-stdin-eof --log-format json
```

Create the child with piped stdin and keep its writer open while the tunnel is
desired. Pipes and Unix sockets are accepted, including the socketpair that
Node.js `child_process` uses for `stdio: 'pipe'`. Portal drains and ignores bytes; stdin is not a command protocol. A
terminal, regular file, or null device is rejected when this flag is enabled.
Without the flag, stdin does not control the tunnel's lifetime.

Closing the last writer requests the same cancellation and cleanup as a normal
shutdown signal, including best-effort relay unregister and listener closure.
This applies during startup, after readiness, and while reconnecting or failed.
Cancellation during startup exits successfully. An unexpected stdin read error
also requests shutdown and logs a warning. Existing shutdown timeouts apply;
unregister has a five-second timeout per relay, not a five-second process deadline.
Shutdown errors remain visible as a nonzero exit status. For example, if the relay
is offline, unregister may fail even though EOF successfully stops the tunnel.

Normal application exit or a forced kill closes its pipe handles. This stops
Portal only if no other process retains a writer: prevent writer inheritance
and close unused copies. This is pipe ownership, not universal parent-death
detection. Continue draining stdout and stderr and observing subprocess exit.
Use the existing JSON relay lifecycle records below for readiness, and retract
advertised URLs when the subprocess exits.

The application owns restart policy, authorization, and identity persistence
through the existing identity options. Its access checks and header filtering
remain its responsibility. Cleanup of older unmanaged processes may still be
needed during migration.

Use [`portal agent`](/portal-agent) for durable tunnels whose lifetime Portal
and the OS service manager own. Use this option when the calling application
owns the tunnel's lifetime; it adds no daemon or control API.

### Machine-Readable Relay Lifecycle

Integrations that launch `portal expose` as a subprocess can track relay
readiness without parsing human-facing messages:

```bash
portal expose 3000 --log-format json
```

| Guarantee | Behavior |
|-----------|----------|
| Records | One structured JSON log record per line on **stdout**; filter by `"event":"relay_status"` |
| Human output | Unchanged by default; `--log-format text` (default) keeps the human-readable console |
| State ownership | Records are emitted from the same authoritative SDK status paths the human logs derive from |
| Transitions | Records report readiness, readiness loss (`ready` → `connecting`), the relay refusing the lease, failures, and deselection; repeated unchanged statuses are omitted |

One ready record:

```json
{"level":"info","event":"relay_status","relay_url":"https://relay.example.com","state":"ready","public_url":"https://myapp-<identity>.relay.example.com","alias_url":"https://myapp.relay.example.com","deselected":false,"time":"2026-01-01T00:00:00Z","message":"service ready at https://myapp-<identity>.relay.example.com (short URL: https://myapp.relay.example.com)"}
```

Fields on `event=relay_status` records:

| Field | Meaning |
|-------|---------|
| `event` | Always `relay_status` |
| `relay_url` | Relay API URL this status describes |
| `state` | `connecting`, `ready`, or `failed` |
| `failure` | Present when `state` is `failed`: `runtime` (recoverable), `terminal`, or `mitm` (TLS termination detected; requires `--ban-mitm`) |
| `approval` | Present while the relay refuses this lease: `pending` (not approved yet) or `refused` (denied or banned). `state` is `connecting` and `public_url` is empty. Its absence does not mean approved |
| `public_url` | Identity-bound canonical URL; usable only when nonempty and `state` is `ready`. Local TLS keeps it empty before usable material exists and withdraws it on expiry |
| `legacy_url` | Separate one-label canonical compatibility URL for a Local TLS lease; use only while `state` is `ready` and not deselected |
| `alias_url` | Short `<name>.<relay-domain>` URL without an Ethereum address; prefer this for sharing when present. Present **only while `state` is `ready` and granted**: a failed, deselected, or address-only relay never reports one |
| `deselected` | `true` on the removal notification for a relay that left the membership set; a previously advertised relay URL must be retracted |

Records never carry access tokens, private identities, or other secrets;
other log levels and messages on the same stream are not part of this
contract. A consumer needing an authoritative complete membership
snapshot should use the SDK's `Relays()`, not the lossy event stream.

A `connecting` record retracts readiness until a subsequent `ready`
record, and never reports an `alias_url`.
For Local TLS, a `ready` record may have an empty `public_url` and a usable
`legacy_url` or `alias_url`. Retract a previously advertised canonical when a
later record empties `public_url`, even if `state` remains `ready` for the
separate compatibility endpoint.

On a `manual` relay, a waiting tunnel logs `waiting for relay approval` once,
not on every retry, and needs no restart after approval:

```json
{"level":"warn","event":"relay_status","relay_url":"https://relay.example.com","state":"connecting","public_url":"","deselected":false,"approval":"pending","address":"0x...","time":"2026-01-01T00:00:00Z","message":"waiting for relay approval"}
```

Raw TCP and UDP tunnels log `raw transport endpoints allocated` once a reverse
stream opens, so the line also means that the relay accepts the lease.

### Examples

Expose a local web app:

```bash
portal expose 3000
```

Protect the app with tunnel-local SIWE login:

```bash
portal expose 3000 --auth siwe
# Restrict login and pass the verified identity to the upstream.
portal expose 3000 --auth siwe --auth-allow 0x1234... --auth-identity-headers
```

Protect it without requiring a browser wallet, then issue a host-scoped
credential from the tunnel identity:

```bash
portal expose 3000 --auth credential
portal auth issue myapp.example.com --subject alice --expires 720h
```

Protect it with a standard OpenID Connect provider (see
[OpenID Connect](/siwe-authentication#openid-connect-oidc)):

```bash
portal expose 3000 --auth oidc \
  --auth-oidc-issuer https://accounts.google.com \
  --auth-oidc-client-id <client-id> \
  --auth-email-list alice@example.com
```

`--auth-email-list` is required with `--auth oidc`. The `AUTH_OIDC_*` variables
are read only with `--auth oidc`, so exporting them for one service does not affect
another `portal expose`. An `--auth-oidc-*` flag given on the command line
without `--auth oidc` is rejected.

Protect it with a SAML 2.0 identity provider (see
[SAML 2.0](/siwe-authentication#saml-20)):

```bash
portal expose 3000 --auth saml \
  --auth-saml-metadata-url https://idp.example.com/realms/main/protocol/saml/descriptor \
  --auth-email-list @example.com
```

`--auth-email-list` is required with `--auth saml`. The `AUTH_SAML_*` variables
follow the `AUTH_OIDC_*` rule: Portal reads them only with `--auth saml`, and
it rejects an `--auth-saml-*` flag on the command line without `--auth saml`.

Protect it with one-time sign-in links that Portal sends through your own SMTP
account (see [Email links](/siwe-authentication#email-links)):

```bash
# AUTH_SMTP_PASSWORD is set in this shell first, at a prompt
portal expose 3000 --auth email \
  --auth-smtp-addr smtp.gmail.com:587 \
  --auth-smtp-username you@gmail.com \
  --auth-smtp-from you@gmail.com \
  --auth-email-list alice@example.com
```

`--auth-email-list` is required with `--auth email`. The `AUTH_SMTP_*` variables
follow the `AUTH_OIDC_*` rule: Portal reads them only with `--auth email`, and
it rejects an `--auth-smtp-*` flag on the command line without `--auth email`.

`--auth-allow` is the list for `siwe` and `credential`. `--auth-email-list` is
the list for `oidc`, `saml`, and `email`: a tunnel runs one provider, so the one
list serves all three. `oidc` and `saml` still read `--auth-allow`, so existing
configs keep working. Setting both is refused. `email` takes only
`--auth-email-list`.

Portal protects the complete HTTP gateway, including routed, static, and x402
paths. It always strips inbound Portal identity headers. The auth gate cannot be
combined with relay cache mode or raw TCP/UDP exposure.

Use a custom name and relay:

```bash
portal expose localhost:8080 \
  --name myapp \
  --relays https://portal.example.com \
  --discovery=false
```

Run routed HTTP mode:

```bash
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

Route matching is longest-prefix-first. `/api` matches `/api/*` and strips the
`/api` prefix before proxying to the upstream.

Expose a Minecraft server:

```bash
portal expose localhost:25565 --name minecraft --tcp
```

Enable UDP alongside the default stream target:

```bash
portal expose localhost:8080 --udp --udp-addr localhost:19132 --name game
```

Ban relays on MITM probe detection:

```bash
portal expose 3000 --ban-mitm
```

Publish a paid HTTP route:

```bash
portal expose --name paid-app \
  --http-route "/paid=http://127.0.0.1:3001 GET:0.01" \
  --http-route /=http://127.0.0.1:5173 \
  --x402-pay-to 0x...
```

The optional method list limits which methods require payment; without it, every
method on that route prefix is paid.

The routed HTTP handler also serves `/x402/client.js` and `/x402/prepare` on the
public tunnel origin. Frontends served by one of the routes can use the shared
browser-only Sui wallet client for an in-page payment flow:

```js
import { getSuiWallets, x402Fetch } from '/x402/client.js';

const [wallet] = getSuiWallets();
if (!wallet) {
  throw new Error('Install a Sui wallet');
}

const [account] = await wallet.accounts();
if (!account) {
  throw new Error('Connect a Sui account');
}

const response = await x402Fetch('/paid/photo', { method: 'GET' }, {
  wallet,
  account,
  onEvent: (event) => console.log(event.type, event.message),
});
```

`x402Fetch()` is a convenience wrapper: it asks `/x402/prepare` for the payment
transaction, asks the wallet to sign it, then retries the protected request with
an `X-PAYMENT` header. `onEvent` receives structured progress events; the older
`onStatus(message)` callback is still accepted for simple UIs. Routed HTTP
payments use Sui mainnet by default; pass `--x402-testnet` when exposing the
tunnel and use `network: 'sui:testnet'` in wallet clients that need an explicit
network. For mainnet, omit `network` or pass `sui:mainnet`.

Native clients should not load `/x402/client.js`. Call `POST /x402/prepare` with
`{ "sender": "...", "method": "GET", "path": "/paid/photo" }`, execute
`prepareTransaction.transaction` first when present, sign
`paymentTransaction.transaction`, and send the resulting x402 payload as the
`X-PAYMENT` header on the protected request:

```js
const payload = {
  x402Version: prepared.x402Version,
  payload: {
    signature,
    transaction: prepared.paymentTransaction.transaction,
  },
  accepted: prepared.paymentRequirements,
  resource: prepared.resource,
};
const header = base64(JSON.stringify(payload));
```

The frontend integration is optional. Requests without a valid `X-PAYMENT`
header still receive x402 payment-required responses from the tunnel.

### Serve A Static Site

```bash
portal expose --serve ./dist
# An HTML file serves its containing folder with that file as the SPA entry.
portal expose --serve ./site/index.html
```

Unknown paths fall back to the entry HTML file. Keep private files outside the
served directory. Path traversal (`..`) is refused, and a symlink whose target is
outside the folder answers `404`; a symlink inside the folder is followed. Static serving
is available in both `expose` and agent TOML; the agent format supports `serve` but
not relay cache options (`cache` or `cache_ttl`).

To opt in to storage and TLS termination at one selected relay:

```bash
portal expose --serve ./dist --cache --cache-ttl 1h \
  --relays https://gosunuts.xyz --discovery=false
```

The selected relay must advertise cache support and admit the snapshot.
Otherwise the live origin tunnel remains in use. A cached connection trusts
the relay with the files and HTTP traffic, even if it falls back to the live
origin. Only the identity-bound canonical hostname is cached; the friendly
hostname continues to require a live origin. The requested TTL is an upper request subject to relay policy, not a
hosting guarantee; cached files may be evicted or lost on relay restart.
See [cache configuration](/configuration#static-relay-cache) and
[the TLS boundary](/security-model#opt-in-static-cache).

## `portal auth issue`

Issue a host-scoped credential using an existing tunnel identity:

```bash
portal auth issue [flags] <host>
portal auth issue myapp.example.com --subject alice --expires 720h
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--subject` | string | required | Subject placed in the credential and optional upstream identity header |
| `--expires` | duration | `720h` | Credential lifetime |
| `--identity-path` | string | `identity.json` | Existing tunnel identity; no identity is created by this command |
| `--identity-json` | string | | In-memory existing tunnel identity; `IDENTITY_JSON` environment variable; takes precedence over the path |

The command prints a bearer credential and an HTTPS redeem URL. `<host>` is the
published hostname, or an `https://` URL of it; the default port `:443` is
ignored, and a relay on another port must include it (`myapp.example.com:8443`).
Use it with a tunnel started via `portal expose ... --auth credential`. API
clients can send the credential in `X-Portal-Access-Credential`; Portal
validates and removes that header before forwarding the request upstream.

## `portal list`

Print relay URLs resolved for the current invocation:

```bash
portal list [flags]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--relays` | string | registry | Additional relay URLs |
| `--default-relays` | bool | `true` | Include public registry relays |

`portal list` does not run the runtime relay discovery expansion loop. It only
resolves the registry seed list plus explicit relay URLs.

## `portal agent`

Run a durable local agent that owns multiple tunnels from one config file:

```bash
portal agent run
portal agent dashboard
portal agent stop
portal agent restart
```

| Command | Description |
|---------|-------------|
| `portal agent run` | Install or update and start the managed agent service |
| `portal agent run --config config.toml --foreground` | Run the agent in the current terminal |
| `portal agent dashboard` | Open the local TUI for tunnels, relays, and settings |
| `portal agent stop` | Gracefully stop the agent and disable or stop the OS service |
| `portal agent restart` | Stop the current agent if present, install or update the service, and start it again |

The local control API binds only to loopback and uses a token in the agent state
directory. See [Portal Agent](/portal-agent) for the workflow and
[Configuration Reference](/configuration#configtoml) for the `config.toml`
format.

Agent flags:

| Command | Flag | Default | Description |
|---------|------|---------|-------------|
| `portal agent run` | `--config` | platform default | Agent TOML config path |
| `portal agent run` | `--foreground` | `false` | Run in the current process without installing the OS service |
| `portal agent run` | `--service` | `false` | Internal service entrypoint used by the installed OS service |
| `portal agent run` | `--theme` | `amber` | Dashboard color theme with `--foreground`: `amber` or `green` (env: `PORTAL_TUI_THEME`) |
| `portal agent dashboard` | `--config` | platform default | Config path used for display and state-dir discovery |
| `portal agent dashboard` | `--state-dir` | config/default | Agent state directory to attach to |
| `portal agent dashboard` | `--theme` | `amber` | Color theme: `amber` or `green` (env: `PORTAL_TUI_THEME`) |
| `portal agent stop` | `--config` | platform default | Config path used to resolve state dir and service name |
| `portal agent stop` | `--state-dir` | config/default | Agent state directory to stop |
| `portal agent restart` | `--config` | platform default | Config path used to reinstall and restart the service |

## `portal update`

Update the CLI binary:

```bash
portal update
```

The updater resolves the latest GitHub release, compares it with the installed
version, downloads the matching asset, verifies its SHA256 checksum, and
replaces the current executable.

## `portal version`

```bash
portal version
```

Prints the installed version string and exits.

## Behavior Notes

- `portal expose` and `portal list` check the latest published GitHub Release in
  the background. A `main` merge or branch artifact is not offered to installed
  clients until the release is created with matching binary and checksum assets.
- `portal expose` loads or creates a signing identity at `identity.json` or
  `--identity-path`.
- Multiple relay URLs are registered independently. A failed relay does not stop
  healthy relays from serving.
- With discovery enabled, the tunnel consumes relay `/discovery` results and
  reconciles its relay pool.
- MITM self-probing logs suspected termination by default; relay banning requires `--ban-mitm`.
- When the local stream target is unreachable, the tunnel returns an HTTP 503
  page to browser-style clients.
- Routed HTTP mode is HTTP-only and runs inside the tunnel process.
- Routed HTTP mode keeps the browser's `Host` for every upstream and sends
  `X-Forwarded-Proto: https`; a local dev server that checks `Host` (such as
  Vite's `server.allowedHosts`) must allow the public hostname.
- `--tcp` requires relay TCP port transport, a valid `MIN_PORT`/`MAX_PORT`
  range, and TCP port transport enabled in the admin panel.
- `--udp` requires relay UDP transport, a valid `MIN_PORT`/`MAX_PORT` range, UDP
  enabled in the admin panel, and the public `PORTAL_URL` port reachable over
  UDP for the QUIC backhaul.
- Bare `portal [flags]` is not accepted; use `portal expose` explicitly.
- Runtime `APP_*`, `RELAYS`, and `DEFAULT_RELAYS` environment variable fallbacks
  are not used.

## Next Steps

- [Getting Started](/getting-started): run your first tunnel
- [Portal Agent](/portal-agent): run durable multi-tunnel services
- [Wallet and ENS](/wallet-and-ens): understand admin tokens, wallet auth, and ENS gasless DNS
- [Concepts](/concepts): understand the relay and transport model
- [TCP and UDP Tunneling](/tcp-udp-tunneling): raw TCP and UDP setup
- [Deployment](/deployment): run your own relay server
