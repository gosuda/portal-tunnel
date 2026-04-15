# Portal CLI

`cmd/portal-tunnel` builds the `portal` tunnel CLI. It connects a local service to one or more Portal relays.

## Usage

Install directly from the official GitHub release assets:

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
portal expose 3000
portal list
```

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
portal expose 3000
portal list
```

If your relay publishes its own installer, you can use that instead:

```bash
curl -sSL https://portal.example.com/install.sh | bash
portal expose 3000
portal list
```

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://portal.example.com/install.ps1 | iex
portal expose 3000
portal list
```

Custom relay and metadata example:

```text
portal expose localhost:8080 \
  --name myapp \
  --identity-path ~/.config/portal/myapp.identity.json \
  --relays https://portal.example.com \
  --description "Service description" \
  --tags tag1,tag2 \
  --thumbnail https://example.com/thumb.png \
  --owner "Portal Operator"
```

TCP port routing example (e.g., Minecraft server):

```text
portal expose localhost:25565 --name minecraft --tcp
```

Multi-port HTTP aggregation example:

```text
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

## Commands

### `portal expose [flags] <target>`

- `<target>` accepts a bare port like `3000`, a `host:port`, or an `http(s)://host:port` URL.
- Bare ports resolve to `127.0.0.1:<port>`.
- Instead of `<target>`, you can repeat `--http-route PATH=UPSTREAM` to aggregate multiple local HTTP services behind one public URL.
- Route matching is longest-prefix-first. `/api=http://127.0.0.1:3001` matches `/api/*` and strips the `/api` prefix before proxying to the upstream.
- Routed HTTP mode automatically forwards `X-Forwarded-*`, rewrites upstream `Location` redirects back to the public route path, and strips loopback cookie domains while remapping cookie paths to the mounted route prefix.
- `--name` is optional. When omitted, the CLI generates a name for that run.
- `--relays` adds explicit relay API URLs for that run. Explicit relays are always kept connected and are not counted against `--max-active-relays`.
- `--discovery=false` disables the public registry seed list and the runtime relay discovery expansion loop for that run. With `--discovery=false`, only the explicit `--relays` values are used.
- `--ban-mitm` enables strict rejection when the TLS self-probe detects termination in the path.
- `--tcp` requests a dedicated TCP port on the relay for raw TCP services that do not use TLS (e.g., Minecraft, game servers).
- `--udp` requests a public UDP port on the relay and forwards datagrams to `--udp-addr` or the primary target.

Flags:

```text
--relays          Portal relay API URLs (comma-separated, https only)
--discovery       Include public registry relays and discover additional relay bootstraps
--max-active-relays  Maximum number of auto-selected relays; explicit --relays are always included
--ban-mitm        Ban relay when the MITM self-probe detects TLS termination
--identity-path   Identity JSON file path; created automatically when missing
--identity-json   Identity JSON payload; overrides --identity-path contents and is persisted there when both are set
--name            Public hostname prefix (single DNS label); auto-generated when omitted
--description     Service description metadata
--tags            Service tags metadata (comma-separated)
--thumbnail       Service thumbnail URL metadata
--owner           Service owner metadata
--hide            Hide service from relay listing screens
--tcp        Request a dedicated TCP port on the relay for raw TCP services (no TLS)
--udp        Enable public UDP relay in addition to the default stream path
--udp-addr   Local UDP target address; defaults to the primary target when --udp is enabled
--http-route      HTTP route mapping in PATH=UPSTREAM form; repeat for multiple routes
```

### `portal list [flags]`

- Prints the relay URLs that the CLI will use for the current invocation.
- `--relays` adds explicit relay URLs, and `--default-relays=false` disables the public registry list for the current listing run.
- Unlike `portal expose`, `portal list` does not run the relay discovery expansion loop. It only resolves the registry seed list plus explicit `--relays` values.

Legacy execution compatibility has been removed:

- Use `portal expose ...` explicitly; bare `portal [flags]` is no longer accepted.
- Runtime `APP_*`, `RELAYS`, and `DEFAULT_RELAYS` environment variable fallbacks are no longer used.
- Pass either the local target as the positional `<target>` argument or repeat `--http-route` for routed HTTP mode.

## Install Behavior

- `install.sh` installs the downloaded binary as `portal`.
- `install.ps1` installs `portal.exe` for the current Windows user and updates the user `PATH`.
- The installer does not write a config file.
- `portal expose 3000` still works after install because discovery is enabled by default.
- To target only a specific relay, use `--relays https://portal.example.com --discovery=false`.

## Notes

- `portal expose` loads or creates the signing identity at `identity.json` by default. Reusing the same `--identity-path` keeps the same address across runs.
- Use different `--identity-path` values when you want separate local identities.
- Multiple relay URLs are registered independently. Each relay gets its own lease registration and public URLs.
- Relay publishes each service at `<name>.<portal root host>`.
- The tunnel consumes one aggregate SDK listener, so the CLI no longer manages per-relay listener loops itself.
- Relay startup and reconnect failures are retried independently in the background. A relay that is down does not stop healthy relays from continuing to serve traffic.
- The tunnel starts once relay URLs pass local validation. Remote compatibility checks, lease registration, and reconnects continue in the background until each relay becomes ready.
- With discovery enabled, the tunnel uses the public registry as discovery seed input and can expand through relay discovery. Explicit `--relays` values are always included separately from the auto-selected relay pool. With `--discovery=false`, only the explicit relay URLs are used. Published public URLs appear only for relays that have registered successfully.
- Explicit `--relays` listeners retry indefinitely with `RetryCount=0`. Auto-selected discovery relays are created with `RetryCount=10` and are dropped from the active set after that budget is exhausted.
- Retry count limits retries when positive. `RetryCount=0` retries indefinitely.
- Tenant TLS is provisioned automatically through the relay keyless signer. The SDK fetches the relay certificate chain and uses `/v1/sign` for remote signing.
- `portal expose` enables MITM strict enforcement by default. Use `--ban-mitm=false` to keep warning-only behavior when the TLS self-probe suspects relay termination.
- When the local service is unreachable, the tunnel returns an HTTP 503 page.
- `--tcp` allocates a dedicated TCP port within the relay's configured `MIN_PORT-MAX_PORT` range. The relay bridges raw TCP connections to the local target without TLS. Requires `TCP_ENABLED=true`, a valid `MIN_PORT/MAX_PORT` range, and TCP port enabled in the admin panel.
- `--http-route` mode is HTTP-only and cannot be combined with `--udp`.
