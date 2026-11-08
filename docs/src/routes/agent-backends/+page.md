---
title: AI Agent Web UIs
description: Reach a herdr web client such as Ovis, or another coding-agent dashboard, through Portal without opening it to everyone.
---

# AI Agent Web UIs

> **Maintainer note**: the rules and commands on this page are mirrored in the agent skill reference at `plugins/portal-tunnel/skills/portal-expose/references/agent-backends.md`. When either changes, update both files. This page is the human-facing source; the reference is the agent-facing copy.

Agent web UIs let you drive Claude Code, Codex, and other coding agents from a browser or phone. Whoever reaches one can type into your terminals, so it needs more care than a normal preview.

## Rules

- **Keep the app's own login on.** Set the app's token or pairing before you expose it. Portal's [application authentication](/siwe-authentication) can add a sign-in in front, but it does not replace the app's own gate.
- **Keep the app on loopback.** It listens on `127.0.0.1`; Portal connects to it there.
- **Use routed HTTP.** `--http-route /=<port>` sends `X-Forwarded-For` and `X-Forwarded-Proto: https` and carries WebSocket upgrades, which these apps need.
- **Hide and pin the address.** Use `--hide`, a hard-to-guess `--name`, one identity file outside your repository, and one relay you trust with `--relays <relay> --discovery=false`.
- **Use the address-bound URL** that `service ready at` prints. The short `<name>.<relay>` URL can be claimed by another identity while your tunnel is stopped.
- **Keep secrets out of the command line.** Tokens and client secrets go in the app's environment.

## Ovis (herdr web client)

[Ovis](https://github.com/devswha/ovis), formerly "herdr web UI", is a browser and phone client for [herdr](https://github.com/herdrdev/herdr). It listens on `127.0.0.1:7317` by default.

1. Set `OVIS_TOKEN` to a long random value (for example `openssl rand -hex 32`) where Ovis reads its settings, and restart it.
2. Use Portal v2.6.1 or later, on a relay that runs v2.6.1 or later.
3. Start Portal:

   ```sh
   portal expose --http-route /=7317 \
     --strip-request-header Tailscale-User-Login \
     --name herdr-$(openssl rand -hex 8) \
     --identity-path ~/.config/portal/herdr.json \
     --relays <relay> --discovery=false --hide
   ```

4. From another device, `https://<address-bound host>/api/session` must answer `401` without a token.
5. Open the address and sign in with the token, or pair the device from **Settings → Phone & devices**.

The plain `portal expose 7317` sends no `X-Forwarded-Proto`, so Ovis refuses its own requests (`invalid_origin`). Do not set `OVIS_TAILSCALE_SERVE_ONLY=1` while Portal runs. Ovis can also start Portal for you from **Settings → Phone & devices → Portal**, with an optional Portal sign-in in front (Portal v2.7.0 or later). See the Ovis guide's [Behind a reverse proxy](https://github.com/devswha/ovis/blob/main/docs/guide.md#behind-a-reverse-proxy) section for details.

## Other agent UIs

For any other agent dashboard, browser terminal, or agent API, check its documentation for its own authentication, the forwarding headers it needs or trusts, and whether it uses WebSocket or Server-Sent Events. If it has no login of its own, everyone who passes Portal's sign-in gets a shell on your machine.
