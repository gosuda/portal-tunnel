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
must be valid for the identity's canonical hostname on each selected relay.
Include any short alias hostname visitors use in the certificate SANs too;
a certificate for only the alias does not cover the canonical hostname.
Use alias certificates only where the operator controls their continuing
authority: releasing or reassigning an alias does not revoke an already issued
certificate or remove the former owner's private key.
Choose explicit relays and disable discovery unless the certificate covers all
additional relay hostnames. Public browsers still require a publicly trusted
certificate chain.

Tenant handshakes use the same TLS engine as Keyless TLS, but sign in process
with the local key instead of calling the relay's `/v1/sign` endpoint. The
exporter self-probe verifies tenant certificates separately from the relay
control API's TLS trust. This option cannot be combined with `--cache` or
raw `--tcp`.

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
certificate issuance, and a relay wildcard certificate can also cover tenant
names.

## Automatic tunnel certificates

Automatic issuance is opt-in while operators measure issuance latency, renewal
reliability, and shared CA quota use:

```sh
portal expose 3000 --tls-auto --identity-path identity.json
```

The tunnel generates and retains its private key locally. It sends only a CSR to
the authenticated relay API; the relay uses its existing ACME account and DNS
provider to obtain the hostname certificate. Automatic mode publishes only the
stable identity-derived canonical URL; it neither reserves nor advertises a
short alias. The identity's name is retained. The CSR endpoint accepts only the
current lease's exact canonical hostname and rejects short aliases, wildcard,
apex, and sibling requests. An automatic certificate therefore grants no
short-alias authority that could outlive reassignment.

The relay must support this issuance endpoint and enable `--tenant-certificates`.
Relay-side issuance is off by default to protect the operator's shared CA quota.
An older or disabled relay leaves bootstrap-allowed clients on Keyless TLS;
a `--tls-require-local` client stays unready until a local certificate is available.

By default, an automatic tunnel with no usable persisted certificate can begin
with Keyless TLS while issuance runs in the background. Valid local material is
installed for new handshakes and reused after restart. Existing connections are
not upgraded retroactively. Renewal failure preserves a still-valid local
certificate; an expired certificate cannot serve new handshakes. Once local
material has been issued, renewal failure or expiry does not restore Keyless
signing. Corrupt saved material fails closed. If all saved state is deleted,
a bootstrap-allowed restart can bootstrap again; use --tls-require-local
to prohibit that downgrade even after state loss.

To prohibit Keyless bootstrap, add `--tls-require-local`. The tunnel must obtain
or load usable local material before accepting traffic. This setting remains in
the persistent agent configuration across restarts; lost, corrupt, or expired
state does not remove it. Local-key ownership is not independent visitor
authentication.

Automatic state defaults to the identity file path plus `.tls`, for example
`identity.json.tls`. Use `--tls-state-dir` to choose another directory.
An in-memory identity supplied by `--identity-json` requires an explicit state
directory, even when `--identity-path` also has a value. Keep this state on
durable private storage and back it up securely. Certificate material follows
stable hostnames, rather than individual leases; multiple relay hostnames have
separate material. The key is saved before the first CSR and reused during
renewal; the matching certificate and key are stored as one atomic private
bundle. An operating-system lock serializes concurrent issuers for that hostname.
Issuance retries back off from one minute to one hour; successful state is checked
hourly, or earlier when renewal is due.

For a persistent agent:

```toml
[[tunnels]]
id = "web"
target = "3000"
identity_path = "identity.json"
tls_auto = true
tls_state_dir = "certificates"
tls_require_local = true
```

Explicit relative paths resolve from the agent config directory. If
`tls_state_dir` is omitted, its default follows the resolved identity path.
The state directory alone does not enable automatic issuance. Automatic mode
cannot be combined with manually supplied `tls_cert`/`tls_key`, relay cache,
or raw TCP. Manual certificate files already prohibit relay-signing fallback.

CSR issuance leaves CA account authority with the relay operator. The relay's
existing wildcard and control of authoritative DNS can still permit competing
certificates. The gains are client-only possession of the legitimate tunnel key
and removal of the online `/v1/sign` dependency after activation. CAA and
CT/precertificate monitoring remain complementary follow-up work; this mode
does not claim prevention of malicious-relay impersonation.

## Canonical Documentation Links

- **[Feature Inventory](https://gosuda.github.io/portal-tunnel/features)**: Complete matrix of Portal capabilities, surfaces, and constraints.
- **[CLI Reference](https://gosuda.github.io/portal-tunnel/cli-reference)**: In-depth usage examples, exit codes, and flag references.
- **[Concepts](https://gosuda.github.io/portal-tunnel/concepts)**: Architecture, relay ownership, and transport mechanics.
- **[Security Model](https://gosuda.github.io/portal-tunnel/security-model)**: Tenant TLS, keyless signing, and the static cache trust boundary.
- **[Portal Agent Guide](https://gosuda.github.io/portal-tunnel/portal-agent)**: Running long-running multi-tunnel setups with `config.toml`.
- **[Self-Hosting Guide](https://gosuda.github.io/portal-tunnel/self-hosting)**: Running your own private or public relay server.
