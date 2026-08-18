---
name: omp-collab
description: Share a running Oh My Pi (OMP) session with a phone or remote browser through OMP collab, either via the hosted my.omp.sh relay or a self-hosted collab relay exposed behind a Portal tunnel. Use when the user asks to access, watch, or steer their machine's OMP session from a phone or another browser, to remote-control OMP away from home, or to self-host the collab relay through Portal. Do not use for exposing a generic web app (portal-expose covers that), sharing saved session snapshots (/share), or joining a session as a guest (omp join).
license: MIT
---

# Share a Running OMP Session with Portal

OMP collab shares a live OMP session with guests: browser or TUI clients see the streaming transcript, tool cards, and footer state, and full-control guests can prompt, interrupt, and steer subagents through Agent Hub. Payloads are sealed with AES-256-GCM before they reach the relay; the relay sees only room ids, connection counts, and ciphertext frames. Possession of the collab link is the trust boundary.

Two hard rules before anything else:

- Only the host human can mint a collab link: `/collab` is an interactive TUI command of the running OMP session. Never claim to have started sharing, never fabricate a link, and never try to drive the TUI yourself. Your job is to prepare and verify the infrastructure, then hand the user the exact one-line command.
- Treat every collab link the user shows you as a secret. Never echo full links into logs, files, or final responses.

Read `references/omp-collab-details.md` for link formats, OMP settings, the guest permission model, and the self-hosted relay constraints.

## Choose the Path

Use the hosted path unless the user explicitly wants to avoid third-party relays:

- **Hosted relay (default)**: zero infrastructure. The user runs `/collab` in the OMP TUI; guests open the printed `my.omp.sh/#<link>` URL or scan the QR. Portal is not involved.
- **Self-hosted relay behind Portal**: when the user wants the session traffic to terminate on their own machine. Requires an OMP source checkout and `bun` on this machine, because the production collab relay is not currently distributed and the only runnable relay is the WebSocket-only stand-in from `packages/collab-web`. Portal carries `wss://` traffic to it.

Ask one concise question only when the user has not expressed a preference about routing session traffic through the hosted `my.omp.sh` relay.

## Workflow

### 1. Check OMP

- Run `omp --version`. Collab with browser links and QR codes needs a current OMP (17.x era); if OMP is missing, tell the user to install it and stop.
- Confirm the target is the session the user cares about. Collab shares the session of the TUI that runs `/collab`; a second OMP process would share an empty session.

### 2. Hosted Path

1. Verify the hosted relay is reachable: `https://my.omp.sh/` should return the web client and `https://my.omp.sh/healthz` should return success. Stop and report if either fails.
2. Tell the user to run, in their OMP TUI:
   - `/collab` for full control (prompt, interrupt, Agent Hub), or
   - `/collab view` for a read-only link.
3. The TUI prints a terminal join link, a `my.omp.sh/#<roomId>.<key>` browser deep link, and QR codes. The user opens the browser link or scans the QR on the phone. No OMP install is needed on the phone.
4. Hand off: the link is the credential; `/collab status` lists participants; `/collab stop` revokes immediately.

### 3. Self-Hosted Path (relay behind Portal)

Prerequisites, checked before touching anything:

- `bun --version` works, and an OMP source checkout containing `packages/collab-web` exists. If either is missing, report the gap and offer the hosted path instead of cloning or installing toolchains unprompted.
- `portal version` works and the installed Portal release is known. Portal has been verified to pass WebSocket upgrades through its HTTPS tunnels; do not re-litigate that, just verify the final handshake.

Steps:

1. Start the stand-in relay from `packages/collab-web` with `bun run relay`. It listens on `ws://localhost:7466` and implements `/r/<roomId>` only — it serves no web client and no share endpoints. Run it as a managed long-running process with capturable logs, not an untracked background job.
2. Verify the local relay: a WebSocket handshake against `ws://127.0.0.1:7466/` (any path) must complete or be rejected by the relay itself, not by a connection failure.
3. Expose it with Portal following the portal-expose rules: `portal expose 127.0.0.1:7466 --name <dns-label-safe-name>` with an absolute `--identity-path` outside any repository. Mention that the hostname is publicly listed on participating relays unless `--hide` is requested.
4. Verify the public endpoint: open a WebSocket to `wss://<public-host>/` and require a completed handshake. Treat TLS errors or Portal error pages as failures; re-check the local relay to distinguish relay failure from tunnel failure.
5. Configure OMP once, in the user's OMP settings (see `references/omp-collab-details.md` for the settings file):
   - `collab.relayUrl: wss://<public-host>`
   - `collab.webUrl: https://my.omp.sh` — required in this path because the stand-in relay serves no web client. `collab.webUrl` must be `https://` (or `http://localhost`); the browser client needs a secure origin for WebCrypto.
6. Tell the user to run `/collab` in their OMP TUI (it now uses the configured relay) or `/collab wss://<public-host>` for a one-off. The printed browser link points at the `collab.webUrl` origin with the relay link in the fragment, so the phone still opens a normal `https://` page while the WebSocket goes through Portal to this machine.

### 4. Verify and Hand Off

- Hosted path: confirm the user reports a successful phone join (transcript visible). You cannot observe the room yourself.
- Self-hosted path: after the user starts sharing, confirm the relay process log shows the host connection arriving through the tunnel.
- Hand off with: the path used, the exact `/collab` command to run, what guests can and cannot do (full-control vs view-only vs host-only commands), and the stop sequence — `/collab stop` first, then stopping the Portal tunnel and the relay process for the self-hosted path.
- State clearly that the shared session stays alive only while the host OMP process runs, and for the self-hosted path, while the relay and tunnel processes run.

## Failure Rules

- OMP missing or too old: provide the install/upgrade path and stop.
- `my.omp.sh` unreachable: report it; do not silently switch the user to the self-hosted path.
- No `bun` or no OMP source checkout: report the gap and offer the hosted path; never install toolchains or clone repositories without approval.
- Local relay handshake fails: fix before exposing; a tunnel cannot repair a dead local service.
- Public `wss://` handshake fails while the local one works: check the service name availability and relay health, capture bounded diagnostics, and report.
- Never log, persist, or repeat a full collab link or its key portion. Reference links as `my.omp.sh/#<redacted>`.
