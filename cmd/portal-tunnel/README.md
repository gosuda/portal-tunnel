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

### Common Flags

#### Core & Discovery
- `--name`: Public hostname prefix (normalized DNS label, maximum 22 ASCII characters); auto-generated when omitted.
- `--relays`: Comma-separated list of explicit relay server URLs.
- `--discovery`: Enable public registry lookups and peer discovery gossip (default `true`).
- `--max-active-relays`: Maximum number of auto-selected relays to maintain in active pool (default `3`).
- `--identity-path`: Path to `identity.json` (auto-created if missing; defaults to user config directory).
- `--identity-json`: Inline JSON identity payload in memory (takes precedence over `--identity-path`).

#### Web & Routing Modes
- `--http-route`: Multi-upstream routing definition (`PATH=UPSTREAM [METHOD:PRICE]`). Repeatable.
- `--serve`: Serve a local static folder (`index.html`) or single-page app file without an external server.
- `--cache`: Allow selected relays to cache static assets and terminate browser TLS. Requires `--serve`.
- `--cache-ttl`: Requested offline cache lifetime (clamped by relay policy).
- `--strip-request-header`: Header removed before forwarding upstream. Repeatable; requires `--http-route` or `--auth`.

#### Transport & Overlay
- `--overlay`: Prefer an IVNP overlay network gateway path; direct reverse transport remains default and fallback.
- `--tcp`: Request a dedicated public raw TCP port on the relay.
- `--udp`: Enable public UDP relay.
- `--udp-addr`: Local target address for incoming UDP datagrams.

#### Security & Access Control
- `--ban-mitm`: Automatically ban relays if the MITM self-probe detects relay-side TLS termination.
- `--auth`: Application-level authentication (`siwe` or `credential`).
- `--auth-allow`: Whitelisted Ethereum wallet address for SIWE (repeatable).
- `--auth-identity-headers`: Inject verified `X-Portal-User` and `X-Portal-Auth` headers upstream.

#### x402 Micropayments
- `--x402-pay-to`: Payment recipient address for monetized routes.
- `--x402-testnet`: Use Sui testnet instead of mainnet.
- `--x402-network`: Optional CAIP-2 network identifier for Sui or Casper.
- `--x402-asset`: CEP-18 wCSPR contract hash required for Casper routes.
- `--x402-endpoint`: Custom RPC endpoint or facilitator URL (repeatable).
- `--x402-facilitator-token`: Casper facilitator authorization token (defaults to `CSPR_CLOUD_API_KEY`).

---

## Flag Validation & Constraints

The CLI enforces the following contractual invariants at startup:

1. **Target Exclusivity**:
   - A positional `<target>` argument cannot be combined with `--http-route` or `--serve`.
   - `--serve` cannot be combined with `--http-route`, `--tcp`, or `--udp`.
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
