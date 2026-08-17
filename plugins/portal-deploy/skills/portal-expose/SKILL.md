---
name: portal-expose
description: Expose, preview, or keep a local web app, static site, HTTP route set, or explicitly requested TCP/UDP service reachable through Portal, then verify the public endpoint and report its lifecycle. Use when the user asks to deploy, publish, share, tunnel, expose, or create a public preview of a local app with Portal. Do not use for deploying a Portal relay, generic cloud hosting, or publishing this plugin.
license: MIT
---

# Expose an App with Portal

Portal publishes a service that is already running on the user's machine. It does not build the app or move it to a cloud host. Treat a successful tunnel as dependent on both the local app and the Portal process or agent remaining available.

Read `references/portal-cli.md` when choosing commands or persistent-agent configuration. Read `references/safety-and-verification.md` before exposing a nontrivial project, a service with authentication, or any non-HTTP port.

## Choose the Mode

Use the smallest mode that satisfies the request:

- Temporary web preview: `portal expose <target>`.
- Trusted static directory or HTML entry: `portal expose --serve <path>`.
- Multiple local HTTP services under one URL: repeat `--http-route`.
- Durable tunnel that should survive terminal or login restarts: an explicit `portal agent` config and managed service.
- Session-owned durable tunnel without an OS service: `portal agent run --foreground`.
- Raw TCP or UDP: only when the user explicitly requests that transport and names the target.

Default to a temporary preview when the user says only "share", "preview", or "deploy locally". Do not install an OS service unless the user asks for a persistent, managed, or restart-surviving tunnel and accepts that `portal agent run` without `--foreground` installs a per-user launchd or systemd unit.

## Workflow

### 1. Inspect the Project

- Read the applicable repository instructions before running or changing anything.
- Determine the app directory, start command, expected protocol, loopback target, and a meaningful health path.
- Prefer declared scripts and documented ports over guessing from process lists.
- Do not expose a port merely because it is listening. Tie it to the requested app.
- If the project is already running, preserve its process. If it is not running and deployment was requested, start it with the project's normal command and retain the terminal/session handle.

Ask one concise question only when the target, desired lifetime, or transport cannot be discovered safely. An explicit request to deploy, publish, expose, tunnel, or share authorizes creating the public tunnel for the named app; it does not authorize exposing adjacent services.

### 2. Verify the Local Service

- Wait for the app's real readiness signal, not only for the process to exist.
- Make a bounded local request to the selected target. For HTTP, record the URL and status. For TCP/UDP, use a protocol-appropriate check that does not mutate application data.
- Stop before opening a tunnel if the local health check fails.
- Warn and require explicit direction before exposing databases, container daemons, debug consoles, unauthenticated admin panels, or services containing sensitive data.
- Before opening the tunnel, say that the public hostname is listed on participating relays and visible via `portal list` unless the user asked for `--hide`.

### 3. Check Portal

- Run `portal version` when `portal` is available.
- If Portal is missing, present the official install method and request approval before running it because installation writes outside the project. Never execute an installer from an unknown relay or third-party URL.
- Do not assume a hard-coded latest release or stale flags. Use the installed version and the checked-in Portal reference as the compatibility baseline.

### 4. Build the Command or Agent Config

- Use loopback targets such as `127.0.0.1:<port>` unless the project explicitly needs another address.
- Use the user's requested name. Otherwise omit `--name` for a temporary preview or derive a stable DNS-label-safe name for a persistent tunnel.
- For `portal expose`, always pass an absolute `--identity-path` outside the repository. The CLI default is `identity.json` in the process working directory and that file contains private key material. For `portal agent`, omit `identity_path` so the agent stores identity under its state directory; if you set the field, use an absolute path outside the repository.
- Never print or commit identity JSON, control tokens, facilitator tokens, or wallet secrets.
- With a user-selected relay on `portal expose`, pass `--relays <https-url> --discovery=false`. In persistent mode those flags are not accepted on `portal agent run`; put `relays = ["https://..."]` and `discovery = false` on the `[[tunnels]]` entry instead.
- The MITM self-probe always runs. Without `--ban-mitm` / `ban_mitm = true`, a suspected TLS termination is only logged and the tunnel keeps serving. Do not claim the default path blocks a relay. Add `--ban-mitm` only when the user wants fail-closed handling. There is no flag that disables the probe.
- Never add TCP, UDP, multi-hop, payment, or public metadata flags that the user did not request. `--hide` is the exception for listing: mention the default public listing, then add `--hide` or `hide = true` only when the user wants the tunnel unlisted.

Before executing, show the exact public target and any important exposure consequence when it is not already obvious from the user's request.

### 5. Start and Observe the Tunnel

- Run a temporary `portal expose` in a foreground PTY or managed long-running command session. Do not hide it behind an untracked `nohup` process.
- For persistent mode, inspect any existing agent config and running service first. `run`, `restart`, and `stop` are service-wide: they affect every `[[tunnels]]` entry that the selected service owns. Reuse and merge the existing config when the same agent should keep other tunnels. An isolated second agent needs its own config, `service_name`, `state_dir`, and loopback `control_addr`. Changing only `service_name` still shares the default state directory and `127.0.0.1:4018`. Do not stop or replace an agent that already owns unrelated tunnels.
- Create or update only the selected agent config, then start it with `portal agent run --config <path>` after the user accepts OS-service installation, or `portal agent run --foreground --config <path>` when the current session should own the process. `--foreground` opens the interactive dashboard when stdin and stdout are TTYs. Run that command in a non-TTY managed session so logs stay capturable and the TUI does not start.
- Do not run `portal agent dashboard`. It is an interactive TUI. Give the user that command in the handoff.
- Capture bounded output. Redact tokens, identity material, signed payloads, and credentials.
- HTTP tunnels are ready when a public URL is emitted. Raw TCP/UDP tunnels log `raw transport endpoints allocated` with `tcp_addr` and/or `udp_addr` instead of `service ready at <URL>`. Do not wait for an HTTPS URL on a raw transport.

### 6. Verify the Public Endpoint

- For HTTP, make a bounded HTTPS request to every public URL being handed off. A deliberately authenticated app may return `401` or `403`; explain that as reachable but protected. Treat unexpected `5xx`, TLS errors, or a Portal error page as a failed deployment.
- For raw TCP or UDP, protocol-probe the allocated `tcp_addr`/`udp_addr` without mutating application data. A successful local port open is not enough.
- When a browser-capable tool is available and the app has UI, load the primary page and check for an obvious render or runtime failure. Do not log in or submit data unless the user requested it.
- Re-check the local health endpoint if the public request fails so the handoff distinguishes app failure from tunnel or relay failure.

### 7. Hand Off the Result

Report:

- Deployment mode and exact local target.
- Public URL or allocated raw endpoint, and the verified status.
- Whether the tunnel is listed on public relays or hidden with `--hide`.
- Whether MITM handling is detect-only or `--ban-mitm`.
- The identity path and that it must stay out of version control.
- The app and Portal process/session or OS-service ownership.
- The exact stop or restart command, and whether that command affects other tunnels on the same agent.
- Anything that remains temporary, unavailable, or unverified.

Do not call the result permanent when the local machine, app process, or foreground tunnel must remain running.

## Failure Rules

- Local app unhealthy: stop before exposing it and report the failing check.
- Portal absent and installation not approved: provide the official command without executing it.
- No ready public URL or allocated raw endpoint: keep the bounded diagnostic output and report the relay/tunnel failure.
- MITM self-probe warning without `--ban-mitm`: report the warning and offer `--ban-mitm`; do not claim the relay was blocked.
- Requested name unavailable: offer an auto-generated or alternative name; do not silently hijack another identity.
- Existing agent owns other tunnels: do not stop or replace it to publish this app.
- Cancellation: stop only processes started by this workflow, unless the user explicitly asks to stop an existing app or agent.
