# OMP Collab Reference

Facts an agent needs when sharing or self-hosting OMP collab. Verified against OMP 17.3.7 (`omp://collab.md` in the OMP distribution) and Portal v2.3.6 (WebSocket upgrade through a live Portal tunnel verified end to end).

## Commands (host TUI)

| Command           | Effect                                              |
| ----------------- | --------------------------------------------------- |
| `/collab`         | Start sharing full-control, or re-print link + QR   |
| `/collab <relay>` | Start sharing through a specific relay              |
| `/collab view`    | Start sharing read-only                             |
| `/collab status`  | Show link + participants                            |
| `/collab stop`    | Stop sharing and revoke the link                    |
| `/join <link>`    | Join as a guest (also `omp join "<link>"`)          |
| `/leave`          | Leave (guest) or stop sharing (host)                |

There is no CLI host command: `omp join` is guest-side and `omp share` is a different feature (encrypted snapshot of a saved session, not live sharing). Host start is TUI-only by design.

## Link formats

`<roomId>.<key>` — the trailing part is the room secret, base64url:

- **Full link** — 48 bytes: 32-byte AES-256-GCM room key + 16-byte write token. Grants prompting, interrupting, and subagent control.
- **View-only link** — bare 32-byte key, no write token. Live read access only.

Accepted forms include `host/r/<roomId>.<key>` (wss inferred), explicit `wss://`/`https://` relay URLs, and browser wrappers: `https://web-host/#<relay-link>` opens the web UI at `web-host` while connecting the WebSocket to the embedded relay link. Legacy `#`-joined forms still parse.

The link is the credential. Share it like a password.

## Settings

| Setting              | Default             | Meaning                                             |
| -------------------- | ------------------- | --------------------------------------------------- |
| `collab.relayUrl`    | `wss://my.omp.sh`   | Relay used by `/collab` when no relay is passed      |
| `collab.webUrl`      | empty               | Browser UI origin; empty derives from `relayUrl`     |
| `collab.displayName` | OS username         | Name shown to other participants                     |

`collab.webUrl` must be `https://` (only `http://localhost` is allowed as plain http — WebCrypto needs a secure origin). When set, the generated browser link is `<webUrl>/#<relay-link>`, which is what makes the self-hosted relay path work with the hosted web client.

## Guest permission model

Full-control guests can read the whole transcript, prompt, interrupt (Esc equivalent), use Agent Hub against the host's subagents (table, chat, kill/revive, transcripts), and answer host select/editor requests.

View-only guests read everything live but cannot mutate.

Host-only, always: `/model`, `/compact`, `/resume`, `/branch`, `!bash`, `$python`, skills, and anything that mutates the host session or machine.

## Encryption and relay visibility

Every session payload (entries, events, state, prompts) is sealed with AES-256-GCM before hitting the socket. The relay observes only room ids, connection counts, opaque ciphertext frames and sizes, and a 4-byte routing prefix. Hosting the relay yourself removes even that visibility from a third party; it does not change the crypto.

## Self-hosted relay constraints

- The production collab relay (Go, serves `/` web client, `/r/<roomId>`, `/s` share blobs, `/healthz`) is **not currently distributed** — no published source or binaries.
- The runnable stand-in is `packages/collab-web/scripts/local-relay.ts` from an OMP source checkout: `bun run relay` inside `packages/collab-web` listens on `ws://localhost:7466`. It implements `/r/<roomId>` only — no web client, no `/share`, no `/healthz`.
- Because the stand-in serves no web client, a self-hosted deployment must set `collab.webUrl` to an HTTPS origin that serves the collab-web client. `https://my.omp.sh` works as a pure static-client origin; the session WebSocket still goes to your relay.
- Portal tunnels pass WebSocket upgrades: `wss://<portal-host>` to a `ws://127.0.0.1:7466` target verified working (handshake + echo round trip through a live relay).
