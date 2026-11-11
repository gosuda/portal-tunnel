# Portal CLI (`portal`)

`cmd/portal-tunnel` implements the `portal` command-line executable. It exposes local applications, static directories, and raw network ports through Portal relays.

For full architectural concepts, security models, and end-to-end tutorials, visit the [Portal Documentation Site](https://gosuda.github.io/portal-tunnel) and the [Canonical Feature Inventory](https://gosuda.github.io/portal-tunnel/features).

---

## Installation & Packaging

### Automated Installation Scripts

**macOS / Linux:**
```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
```

**Windows (PowerShell):**
```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
```

### Docker Compose

Run the multi-architecture container image (`linux/amd64` and `linux/arm64`) using the bundled `compose.yaml`:

```bash
cd cmd/portal-tunnel
mkdir -p identity
# Linux only: ensure UID 65532 (distroless nonroot user) owns the identity volume
if [ "$(uname)" = Linux ]; then sudo chown -R 65532:65532 identity; fi

PORTAL_TUNNEL_TARGET=host.docker.internal:3000 \
PORTAL_TUNNEL_NAME=my-app \
docker compose up -d
```

The container runs as nonroot user (`UID:GID 65532:65532`) and persists its cryptographic identity to `./identity/identity.json`.

### Building from Source

```bash
go build -trimpath -ldflags "-s -w" -o portal ./cmd/portal-tunnel
```

---

## Command Surface

```text
portal expose [flags] <target>
portal expose [flags] --http-route "PATH=UPSTREAM [METHOD[,METHOD...]:AMOUNT]" [...]
portal expose [flags] --serve <directory|html-file>
portal list [flags]
portal agent run [flags]
portal agent dashboard [flags]
portal agent stop [flags]
portal agent restart [flags]
portal version
portal update
```

### Common Workflows

```bash
portal expose 3000
portal expose 3000 --auth siwe
portal expose --serve ./dist
portal expose localhost:25565 --tcp
```

`portal expose --help` and `portal help expose` show common flags first, followed by advanced flags. Both groups work in the same command.

### Common Flags

- `--name`: Request a short URL such as `https://myapp.<relay-domain>/`, without the Ethereum address (normalized DNS label, maximum 63 ASCII characters). When granted, it appears as `short URL` in readiness messages and `alias_url` in JSON logs. A new identity without a name, or a name already owned by another identity, uses the identity-bound canonical URL. Existing identities retain their saved name; use a new `--identity-path` to choose another.
- `--relays`, `--discovery`, `--overlay`: Select relays and prefer an available overlay path.
- `--http-route`, `--serve`, `--tcp`, `--udp`: Choose routed HTTP, a static site, raw TCP, or UDP exposure.
- `--auth siwe`, `--auth credential`, `--auth oidc`, `--auth saml`, or `--auth email`: Protect HTTP application access. `--auth-allow` restricts access for `siwe` (Ethereum wallets) and `credential` (credential subjects); repeatable. `--auth-email-list` is the list for `oidc` and `saml` (verified emails, `@example.com` domains, or `sub:` subjects) and `email` (emails and `@example.com` domains); these three require at least one entry; repeatable. `oidc` and `saml` also read `--auth-allow`. `--auth email` sends a one-time sign-in link through the SMTP server set by `--auth-smtp-addr`, from the sender set by `--auth-smtp-from`.
- `--x402-pay-to`: Payment recipient for paid HTTP routes.
- `--ban-mitm`: Ban relays when the MITM self-probe detects relay-side TLS termination.
- `--identity-path`: Identity file path; defaults to `identity.json` in the working directory and is created when missing.

### Advanced Flags

The advanced section retains metadata (`--description`, `--tags`, `--owner`, `--thumbnail`, `--hide`), inline identity (`--identity-json`), upstream headers (`--auth-identity-headers`, `--auth-identity-proof`, `--strip-request-header`), x402 provider settings, static caching, `--udp-addr`, `--max-active-relays`, and `--metrics-addr`.

These flags remain available directly on `portal expose`; no configuration file is required. See the [CLI Reference](https://gosuda.github.io/portal-tunnel/cli-reference#flags) for the full flag reference, defaults, and detailed examples.

---

## Flag Validation & Constraints

The CLI enforces the following contractual invariants at startup:

1. **Target Exclusivity**:
   - A positional `<target>` argument cannot be combined with `--http-route` or `--serve`.
   - `--serve` cannot be combined with `--http-route`, `--tcp`, or `--udp`. The entry file must exist. Path traversal (`..`) is refused, but symlinks inside the served folder pointing outside it are followed (serve trusted folders only).
2. **Static Offload**:
   - `--cache` and `--cache-ttl` require `--serve`.
   - `--cache` cannot be combined with `--ban-mitm` (caching intentionally trusts the relay with browser TLS).
3. **Transport Exclusivity**:
   - `--http-route` cannot be combined with `--tcp` or `--udp`.
   - `--auth` cannot be combined with `--cache`, `--tcp`, or `--udp`.
4. **Header Manipulation**:
   - `--strip-request-header` requires `--http-route` or `--auth`.
   - Portal-reserved headers (`Host`, `X-Forwarded-*`) cannot be removed by `--strip-request-header`.
5. **x402 Requirements**:
   - Route payment amounts defined in `--http-route` require `--x402-pay-to`.
   - Casper payments require `--x402-network casper:...` and `--x402-asset`.

---

## Tunnel-owned TLS certificate files

For a hostname you already have a certificate for, use:

```sh
portal expose 3000 --relays https://relay.example.com --discovery=false \
  --identity-path identity.json --tls-cert tenant-chain.pem --tls-key tenant-key.pem
```

The PEM chain and matching private key must be supplied together. The certificate
must cover only the exact `<service>.<address>.<relay-root>` canonical hostname,
not friendly aliases, wildcards, or sibling service SANs. Choose an explicit relay
and disable discovery when the certificate covers only that relay's canonical
hostname. Public browsers require a publicly trusted certificate chain.

Canonical tenant handshakes use Go's ordinary `crypto/tls` with the local private
key. Friendly and legacy endpoints keep their independent Keyless TLS path.
Tenant certificate verification is separate from control API trust. Manual local
TLS requires namespace support and cannot be combined with `--cache` or raw TCP.
For a persistent agent, set both paths in the tunnel's existing configuration:

```toml
[[tunnels]]
id = "web"
target = "3000"
relays = ["https://relay.example.com"]
discovery = false
tls_cert = "certs/tenant-chain.pem"
tls_key = "certs/tenant-key.pem"
```

Relative agent paths resolve from the config file's directory. Protect the
private key file with permissions appropriate to the account running Portal.
Portal reads these files on startup and checks for replacements during ordinary
lease renewal, at most hourly after a successful check. Replace the files with a
matching pair; a temporarily mismatched or invalid replacement leaves the
previous usable pair installed. Newly accepted handshakes use the replacement;
in-flight handshakes and established connections keep their original material.
Restart to load a replacement immediately.

Configured local files are required: missing, corrupt, expired, or mismatched
material does not silently restore relay-backed signing, including after a
restart. An unsuccessful refresh keeps the previous material, but does not make
an expired certificate valid. Renew the files before expiry. This file-backed
path does not obtain or automatically renew certificates through ACME; issuance,
key persistence, and timely renewal are the operator's responsibility.

Local key possession removes the signing round trip and dependency. It is not
independent visitor authentication or complete MITM prevention: the relay still
provides routing and availability, authoritative DNS control can permit competing
certificate issuance, and a relay wildcard certificate covers friendly and legacy names, not the new
two-label service namespace.

## Automatic tunnel certificates and service namespaces

Opt in to tunnel-owned TLS with `portal expose 3000 --name blog --tls-auto
--identity-path identity.json`. The new canonical URL is
`blog.<40-lowercase-hex-address>.<relay-root>`. The address has no `0x` prefix.
The relay root can contain several labels. An unnamed service uses the reserved
`default` label; an explicitly named `default` cannot enter the new namespace.

Hostname policy never changes in place:

- `<name>.<root>` remains a first-come friendly alias with Keyless TLS and HTTP/1.1.
- `<service>.<address>.<root>` uses only tunnel-owned Local TLS. It is advertised
  only after both peers negotiate support and an exact-hostname certificate is
  usable. Issuance failure, expiry, or lost state cannot downgrade it to Keyless.
- Existing `<name>-<address>.<root>`, `<hash>--<address>.<root>`, and
  `<address>.<root>` URLs remain legacy compatibility endpoints. Old peers do
  not silently acquire the new namespace. `--tls-require-local` requires a relay
  supporting the new namespace instead of accepting a legacy-only relay.

There is no automatic redirect or origin migration. Applications must explicitly
update links, callback URLs, allowed origins, cookies, and browser storage when
moving to the new URL. Keep existing URLs during the compatibility period; no
removal date is currently specified.

The tunnel retains its leaf private key and sends only a CSR to the authenticated
relay API. The relay must enable `--tenant-certificates`. Issuance is lease-scoped:
only that service's exact canonical hostname is permitted, never wildcard,
friendly alias, sibling hostname, or a shared SAN certificate. Relay-side budgets
and retry backoff protect the operator's shared CA quota.

State defaults to the identity path plus `.tls`. `--tls-state-dir` overrides it;
`--identity-json` requires an explicit state directory. Agent relative paths are
resolved from its configuration directory. Store and back up this state privately.
Per-hostname keys and certificate bundles are retained across restarts and reused
for renewal; sibling services sharing one signing identity have independent leaf
material. A still-valid certificate survives renewal failure, but expired material
cannot serve new canonical handshakes.

```toml
[[tunnels]]
id = "blog"
name = "blog"
target = "3000"
identity_path = "identity.json"
tls_auto = true

[[tunnels]]
id = "api"
name = "api"
target = "4000"
identity_path = "identity.json"
tls_auto = true
```

Set each service's `name` explicitly when sharing an identity file. An explicit
name selects a service without rewriting the key file. New key files do not store
the service name; old files remain readable and their stored name is used only
when no explicit name is supplied. The pair of service name and signing address
identifies the lease; sharing a key does not merge targets or leases.

The CLI HTTP handler path supports HTTP/2 on Local TLS canonical connections and
proxies requests to ordinary HTTP/1.1 backends. HTTP/1.1 stays supported. Raw SDK
byte-stream proxy users must not advertise h2 unless their HTTP consumer handles
it; changing ALPN alone does not translate protocols. Friendly/legacy Keyless
connections retain HTTP/1.1. Relay control-plane and cache ALPN are unchanged.

New canonical URLs never use relay static cache, retained offline responses,
snapshot publication, or cache fallback. Their SNI always selects ciphertext
passthrough to the tunnel, even when the tunnel or certificate is unavailable.
Existing opt-in cache behavior remains on eligible legacy URLs only. Browser HTTP
caching and separately configured external CDNs are independent features.
Automatic/manual local TLS modes cannot be combined with raw TCP or relay cache.

Two hostname labels prevent reuse of the relay's existing `*.<root>` certificate.
They do not remove its DNS/ACME authority: a malicious relay may obtain a new
competing certificate. CT/CAA monitoring is warning-only, not prevention. Native
identity-bound channel binding authenticates the entire hostname, nonce, and
current TLS Exporter on live tunnel-terminated sessions. Ordinary browser
JavaScript cannot obtain that exporter and has no equivalent proof. Relay-cached
legacy sessions have a different TLS trust boundary and no such guarantee.
## Certificate monitoring

Monitoring is disabled by default. For a best-effort evaluation pilot, opt in
with `--tls-monitor-state-dir` alongside either Keyless, automatic, or manual
local-certificate mode:

```sh
portal expose 3000 --tls-auto --identity-path identity.json \
  --tls-monitor-state-dir evidence --tls-monitor-baseline baseline.json
```

This monitors each canonical hostname, not short aliases. Only an enabled runtime
sends hostname queries to the independent DNS resolver (default `1.1.1.1:53`,
override with `--tls-monitor-dns-resolver IP:port`) and to CertSpotter over HTTPS.
No monitoring is activated merely by installing or updating Portal. Runtime
findings and source outages only warn; they do not change DNS, issue or replace
certificates, block traffic, or switch relays. Invalid initial configuration can
still reject startup. Raw TCP, relay cache, and browser/WASM are unsupported.

Persistent agents use `tls_monitor_state_dir`, `tls_monitor_baseline`, and
`tls_monitor_dns_resolver` in their `[[tunnels]]` entry. Relative state and baseline
paths resolve from the agent config directory. Baseline and resolver options
require the state-directory opt-in. The Go SDK exposes
`sdk.WithCertificateMonitoring(stateDir, baselineFile, dnsResolver)`.

The baseline is operator-managed and never accepted from the first DNS answer.
Without one, CAA is `UNCONFIGURED`. CertSpotter's unauthenticated API is for
personal/evaluation use, not a production monitoring SLA. Its unexpired,
coalesced precertificate/final-certificate results are not exhaustive CT history,
and hourly polling plus publication/aggregation delays cannot guarantee
pre-attack detection. See the
[monitoring guide](https://gosuda.github.io/portal-tunnel/keyless-tls#certificate-monitoring)
for the baseline schema, evidence format, and security limits.

## Canonical Documentation Links

- **[Feature Inventory](https://gosuda.github.io/portal-tunnel/features)**: Complete matrix of Portal capabilities, surfaces, and constraints.
- **[CLI Reference](https://gosuda.github.io/portal-tunnel/cli-reference)**: In-depth usage examples, exit codes, and flag references.
- **[Concepts](https://gosuda.github.io/portal-tunnel/concepts)**: Architecture, relay ownership, and transport mechanics.
- **[Security Model](https://gosuda.github.io/portal-tunnel/security-model)**: Tenant TLS, keyless signing, and the static cache trust boundary.
- **[Portal Agent Guide](https://gosuda.github.io/portal-tunnel/portal-agent)**: Running long-running multi-tunnel setups with `config.toml`.
- **[Self-Hosting Guide](https://gosuda.github.io/portal-tunnel/self-hosting)**: Running your own private or public relay server.
