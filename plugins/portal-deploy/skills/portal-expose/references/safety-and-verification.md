# Exposure safety and verification

## Public-exposure check

Before creating a tunnel, identify the exact target and confirm that it belongs to the requested app. Treat these as high-risk targets that require explicit user direction:

- Databases and caches such as PostgreSQL, MySQL, Redis, or MongoDB.
- Docker/container sockets and daemon APIs.
- Debuggers, profilers, development consoles, internal dashboards, and admin panels.
- Services without authentication that can read files, execute code, change configuration, or mutate production data.
- Local development servers that expose source trees, environment-derived data, directory listings, or unrestricted filesystem paths.

End-to-end transport encryption does not make an unauthenticated service private. The public hostname can still be reached by anyone who learns it. Unless `--hide` / `hide = true` is set, every participating relay lists the lease in `GET /api/state`, so anyone can enumerate it. The relay's landing-page directory shows that same list only when the operator opts in (`LANDING_PAGE_ENABLED`, default `false`, changeable later from the admin dashboard). Listed services can also receive public up/down reputation votes (`POST /api/reputation/vote`) on relays running the current release.

## Secret handling

- `portal expose` defaults `--identity-path` to `./identity.json` and writes `private_key`, `mnemonic`, and `token_secret` there. Always override it with an absolute path outside the repository. For `portal agent`, omit `identity_path` so identity stays under the agent state directory.
- Never print or commit Portal identity JSON, private keys, access tokens, agent endpoint tokens, wallet material, payment facilitator tokens, or installer credentials.
- Keep persistent identity and agent state outside the repository. If the user intentionally keeps state under the project, verify that its directory is ignored before creating files.
- Pass secrets through the environment or an existing secret manager. Do not place them directly in commands, logs, skill output, or TOML unless the upstream workflow has no secret reference mechanism and the user explicitly accepts the storage risk.
- Avoid environment dumps, `ps eww`, or other diagnostics that reveal process environments.
- `IDENTITY_PATH`, `TCP_ENABLED`, and `UDP_ENABLED` are read by both `portal expose` and `relay-server` with different meanings (an identity file versus a state directory; a per-tunnel port request versus relay-wide transport); on a host that runs both, an environment variable set for the relay silently reconfigures `portal expose`. Prefer explicit flags.

## Verification matrix

For HTTP services:

1. Request a local readiness path with a short timeout.
2. Start Portal and wait for `service ready at <https-url>`.
3. Request the public URL with a short timeout and normal certificate verification.
4. Accept `2xx` or expected redirects as healthy. Treat an intentional `401` or `403` as reachable-but-protected and say so. Investigate unexpected `4xx`, any `5xx`, TLS errors, or Portal error pages.
5. If public validation fails, repeat the local request to separate app failure from tunnel or relay failure.

For UI apps, use a browser-capable tool when available to check the primary page for a blank screen, obvious runtime error, failed asset loading, or redirect loop. Avoid login and state-changing interactions unless requested.

For raw TCP or UDP, wait for `raw transport endpoints allocated` and protocol-probe the logged `tcp_addr`/`udp_addr`. A successful local port open alone may not prove application readiness. Do not require an HTTPS URL.

## Lifecycle handoff

The final response must distinguish:

- App process started by this workflow versus an existing process.
- Temporary foreground `portal expose` versus `portal agent --foreground` versus a managed OS service.
- Whether `portal agent stop`/`restart` would also take down other tunnels on that service.
- Verified public URLs or raw endpoints versus values merely printed in logs.
- Listed versus `--hide` visibility, and detect-only MITM versus `--ban-mitm`.
- Whether `--cache` was used: cached responses are served by the relay with relay-terminated browser TLS and can remain available on the relay after the tunnel stops, bounded by `--cache-ttl` and the relay's `CACHE_MAX_TTL` (default `24h`).
- Stop command for the tunnel and whether stopping the tunnel also stops the app.

Do not promise availability after the local machine sleeps, disconnects from the network, shuts down, or stops the application; with `--cache`, say instead that the relay may keep serving the cached static files until its bounded deadline and that cache misses still need the local server. Do not run `portal agent dashboard` yourself; it is an interactive TUI.
