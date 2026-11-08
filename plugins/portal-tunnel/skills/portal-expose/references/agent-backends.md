# AI agent web UIs and backends

Use this reference when the service to expose controls coding agents or a shell: a herdr web client such as Ovis (formerly "herdr web UI"), another agent dashboard, a terminal in the browser, or an agent's HTTP or WebSocket API. The human-facing copy is the docs page `docs/src/routes/agent-backends/+page.md`; when either changes, update both.

These services give whoever reaches them a shell as the user, so treat every one as the high-risk case in `safety-and-verification.md`: expose it only when the user asks, name the risk, and get approval for the exact command.

## Rules for every agent backend

- **The app keeps its own gate.** Portal's `--auth` sign-in (see `application-auth.md`) can stand in front, but it does not replace the app's token or pairing. Check that the app refuses an unauthenticated request through the public URL before handing the URL off.
- **Bind to loopback.** The app listens on `127.0.0.1` only; Portal connects to it there. Never change the app to `0.0.0.0` to make Portal work.
- **Routed HTTP, not the plain target.** Use `--http-route /=<port>`. It sets `X-Forwarded-For` and `X-Forwarded-Proto: https`, which these apps use to tell a remote visitor from the local user and to accept their own same-origin requests; it carries WebSocket upgrades.
- **Strip trust headers the app believes.** When the app trusts a header from a local proxy (a Tailscale login, a forwarded user), add `--strip-request-header <name>` so a visitor cannot send their own copy.
- **Keep the address private and stable.**
  - Use `--hide` so the lease stays off the relay's public listing.
  - Use a hard-to-guess `--name` and one absolute `--identity-path` outside the repository, reused on every run. Cookies, installed web apps, and push alerts are tied to the address.
  - Pin one relay with `--relays <url> --discovery=false`, and only a relay the user trusts: the relay holds the certificate for its domain.
  - Hand off the identity-bound URL (`service ready at`), not only the short `<name>.<relay-host>` URL, which another identity can claim while this tunnel is stopped.
- **Secrets stay in the environment.** The app's token, OIDC client secrets, and `AUTH_IDENTITY_PROOF` never go on the command line or into chat, files, or logs. Generate a token on the user's machine, for example `openssl rand -hex 32`, and let the user put it where the app reads its settings.
- **Prefer the app's own path when it has one.** If the app starts Portal itself (for example a Portal panel in its settings), use that, so the app records the address and its own identity file.

## Ovis (herdr web client)

[Ovis](https://github.com/devswha/ovis), formerly "herdr web UI", is a browser and phone client for [herdr](https://github.com/herdrdev/herdr) panes running Claude Code, Codex, OpenCode, and other agents. Facts below follow the Ovis user guide's "Behind a reverse proxy" section; check the installed version's guide when they disagree.

- **Defaults:** `HOST=127.0.0.1`, `PORT=7317` (a plugin install may pick 17317, 27317, 37317, or 47317 and print it). Settings go in the plugin's `env` file (`herdr plugin config-dir devswha.ovis`) or the server's environment.
- **Requirements:** Portal v2.6.1 or later on the client and the relay (for `--http-route` with `--strip-request-header`), and `OVIS_TOKEN` set before exposing. With a public address and no token, anyone who reaches it gets in until the first device pairs. Plain `portal expose 7317` sends no `X-Forwarded-Proto`, and the app refuses its own requests with `invalid_origin`.
- **Never** set `OVIS_TAILSCALE_SERVE_ONLY=1` while Portal reaches the port.
- **Command:**

  ```sh
  portal expose --http-route /=7317 \
    --strip-request-header Tailscale-User-Login \
    --name herdr-$(openssl rand -hex 8) \
    --identity-path /absolute/path/outside/repo/herdr.json \
    --relays <relay> --discovery=false --hide
  ```

- **Built-in path:** Ovis's **Settings → Phone & devices → Portal** runs the same command with its own identity file, and can put Portal's sign-in (credential link, wallet, or OIDC) in front. It requires `OVIS_TOKEN` and Portal v2.7.0 or later for the sign-in. Suggest it before running Portal by hand.
- **Verify:** from outside, `curl -sS --max-time 10 -o /dev/null -w '%{http_code}\n' https://<identity-bound host>/api/session` must return `401`. A `200` without a token means the app is open: stop the tunnel and report it.
- **Hand off:** the identity-bound URL, that the user signs in with the token or pairs the phone from **Settings → Phone & devices**, and the stop command.

## Other agent UIs and APIs

The same rules apply to other agent dashboards, browser terminals, and agent HTTP APIs. Before exposing one, read its documentation for:

1. its own authentication, and set it up first;
2. which forwarding headers it needs and which headers it trusts;
3. whether it needs WebSocket or Server-Sent Events.

If the app has no authentication of its own, do not expose it with only Portal's sign-in in front unless the user accepts that every person who passes the sign-in gets a shell; say so in the approval request.
