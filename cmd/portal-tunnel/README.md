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

- `--name`: Optional hostname prefix (normalized DNS label, maximum 22 ASCII characters). A new identity without a name uses an address-only canonical hostname.
- `--relays`, `--discovery`, `--overlay`: Select relays and prefer an available overlay path.
- `--http-route`, `--serve`, `--tcp`, `--udp`: Choose routed HTTP, a static site, raw TCP, or UDP exposure.
- `--auth siwe` or `--auth credential`: Protect HTTP application access. `--auth-allow` restricts SIWE login to the supplied wallets (repeatable).
- `--x402-pay-to`: Payment recipient for paid HTTP routes.
- `--ban-mitm`: Ban relays when the MITM self-probe detects relay-side TLS termination.
- `--identity-path`: Identity file path; defaults to `identity.json` in the working directory and is created when missing.

### Advanced Flags

The advanced section retains metadata (`--description`, `--tags`, `--owner`, `--thumbnail`, `--hide`), inline identity (`--identity-json`), upstream headers (`--auth-identity-headers`, `--strip-request-header`), x402 provider settings, static caching, `--udp-addr`, `--max-active-relays`, and `--metrics-addr`.

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

## Canonical Documentation Links

- **[Feature Inventory](https://gosuda.github.io/portal-tunnel/features)**: Complete matrix of Portal capabilities, surfaces, and constraints.
- **[CLI Reference](https://gosuda.github.io/portal-tunnel/cli-reference)**: In-depth usage examples, exit codes, and flag references.
- **[Concepts](https://gosuda.github.io/portal-tunnel/concepts)**: Architecture, relay ownership, and transport mechanics.
- **[Security Model](https://gosuda.github.io/portal-tunnel/security-model)**: Tenant TLS, keyless signing, and the static cache trust boundary.
- **[Portal Agent Guide](https://gosuda.github.io/portal-tunnel/portal-agent)**: Running long-running multi-tunnel setups with `config.toml`.
- **[Self-Hosting Guide](https://gosuda.github.io/portal-tunnel/self-hosting)**: Running your own private or public relay server.
