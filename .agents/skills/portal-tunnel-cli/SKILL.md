---
name: portal-tunnel-cli
description: How the portal-tunnel client CLI (cmd/portal-tunnel) is structured and invoked — expose/agent/list/update subcommands, flags, validation rules, and x402/routing options. Use when changing or testing client-side tunnel behavior.
---

# portal-tunnel client CLI

Entrypoint `cmd/portal-tunnel/main.go`. Subcommands are dispatched by the repo's own `utils.RunCommands` (std `flag` package, NOT cobra/urfave). Commands: `expose`, `agent {run,dashboard,stop,restart}`, `list`, `update`, `version`, `help`. Flags are defined in code (`main.go`, `agent.go`); current `main` help prints usage + examples but does not enumerate flags. PR #352 proposes adding the registered flag list (`FlagSet.PrintDefaults`) and a loopback help example; until it merges, read the source for the authoritative list.

## expose (main.go ~85-110)
Publishes a local service. Key flags (many have env fallbacks, shown in `ENV`):
- Target: positional `<target>` (e.g. `3000`, `localhost:8080`) OR `--http-route "PATH=UPSTREAM[ METHOD,...:AMOUNT]"` (repeatable) OR `--serve <dir|file>` for static.
- Relays: `--relays` (extra API URLs), `--discovery` (default true), `--max-active-relays` (default 3, `MAX_ACTIVE_RELAYS`).
- Multi-hop: `--multi-hop` (explicit ordered URLs, `MULTI_HOP`) OR `--multi-hop-depth` (default 0, `MULTI_HOP_DEPTH`) — mutually exclusive.
- Identity: `--identity-path` (default `identity.json`, `IDENTITY_PATH`), `--identity-json` (`IDENTITY_JSON`).
- MITM: `--ban-mitm` (`BAN_MITM`).
- Transport: `--udp`/`--udp-addr` (`UDP_ENABLED`/`UDP_ADDR`), `--tcp` (`TCP_ENABLED`).
- Metadata: `--name --description --tags --owner --thumbnail --hide`.
- x402: `--x402-pay-to`, `--x402-network` (Sui/Casper CAIP-2), `--x402-asset`, `--x402-testnet`, `--x402-endpoint` (repeatable), `--x402-facilitator-token` (`CSPR_CLOUD_API_KEY`).
- `--metrics-addr`. Parsed values flow into `sdk.ExposeConfig` (main.go ~224-281).

### Validation rules (must hold; see main.go ~125-148)
- positional target cannot combine with `--http-route`.
- `--serve` cannot combine with target/`--http-route`/`--udp`/`--tcp`.
- `--http-route` payment amounts require `--x402-pay-to`.
- Casper networks require `--x402-asset`.
- `--multi-hop` cannot combine with `--multi-hop-depth`.

### Examples
```
portal expose 3000
portal expose localhost:8080 --name my-app
portal expose --serve ./site --name my-app
portal expose --http-route /api=http://127.0.0.1:3001 --http-route /=http://127.0.0.1:5173
portal expose 3000 --udp --udp-addr 127.0.0.1:5353
portal expose 3000 --relays https://portal.example.com --discovery=false
portal expose 127.0.0.1:8080 --identity-path /home/user/.config/portal/identity.json --relays https://127.0.0.1:<api-port> --discovery=false  # loopback relay from the same checkout/release
portal expose 3000 --multi-hop-depth 3
```

## Other commands
- `agent run` (`--config` default `service.DefaultConfigPath()`, `--service`, `--foreground`); `agent dashboard`/`stop` (`--config`, `--state-dir`); `agent restart` (`--config`). See `cmd/portal-tunnel/agent.go`.
- `list` (`--relays`, `--default-relays` default true).
- `update` (`--version`, empty = latest).

## Defaults source
Default public relays come from embedded `registry.json` → `types.BootstrapRelays`; version/protocol from `config.toml` → `types.ReleaseVersion`/`SDKVersion`/`DiscoveryVersion` (embedded via `manifest.go`).
