---
title: Webhook and Discord Endpoints
description: Expose a local webhook, Discord Interactions endpoint, or Discord Activity through Portal with a stable public URL.
---

# Webhook and Discord Endpoints

> **Maintainer note**: the steps and checks on this page are mirrored in the agent skill reference at `plugins/portal-tunnel/skills/portal-expose/references/webhook-endpoints.md`. When either changes, update both files. This page is the human-facing source; the reference is the agent-facing copy.

Services such as Discord, Stripe, GitHub, and Slack call a URL that you register once. Portal can give a locally running app that URL with the existing `portal expose` command. Portal only carries the requests; signature checks and response deadlines are handled by your app.

## Keep the URL stable

Use the same name, identity file, and relay every time, so the registered URL does not change:

```sh
portal expose 3000 --name discord-bot \
  --identity-path /absolute/path/outside/repo/discord-bot.json \
  --relays https://portal.example.com --discovery=false
```

- The identity file holds a private key. Keep it outside the repository and reuse it; a new file gets a new address.
- `--name` applies only when the identity file is created. An existing file keeps its saved name.
- Register the short URL that the CLI prints (`https://discord-bot.portal.example.com`) plus the path your app serves.
- For an endpoint that must stay up, run the tunnel as a [Portal Agent](/portal-agent) service instead of a terminal session.

## Check before you register

Start the tunnel first. Many services test the URL when you save it.

```sh
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/json' --data '{}' \
  https://discord-bot.portal.example.com/interactions
```

An app that checks signatures answers this unsigned request with `401`. A `405` on `GET` is also normal for a `POST`-only route. A `200` means the app accepts unsigned requests, which is a security problem in the app.

## Discord Interactions endpoint

1. Run your app locally, for example on port `3000` with the route `/interactions`.
2. Expose it with the command above and run the check.
3. In the [Discord Developer Portal](https://discord.com/developers/applications), open your application, then **General Information**, and set **Interactions Endpoint URL** to `https://discord-bot.portal.example.com/interactions`.
4. Save. Discord sends a `PING` and a request with an invalid signature. The URL is accepted only when your app handles both. Discord also sends invalid signatures later as routine checks and removes the URL if your app accepts one.

Your app must:

- Verify `X-Signature-Ed25519` and `X-Signature-Timestamp` with your application's public key on every request, and answer `401` when the check fails.
- Answer `PING` (`type: 1`) with `200` and `{"type": 1}`.
- Send the first response to an interaction within 3 seconds. For longer work, send a deferred response and follow up later; the interaction token is valid for 15 minutes.

See Discord's [Interactions overview](https://discord.com/developers/docs/interactions/overview) for details. A bot that uses only the Gateway needs no public URL.

## Discord Activity

An Activity is a web app that Discord loads through its proxy. Expose the Activity's web server with its own name and identity, then set the Activity's URL mapping for `/` to the public hostname without `https://`, for example `discord-activity.portal.example.com`. See Discord's [local development guide](https://discord.com/developers/docs/activities/development-guides/local-development).

## Other webhooks

The same steps apply to Stripe, GitHub, Slack, and OAuth redirect URIs: keep the name and identity stable, check the endpoint, then register the URL. Keep signing secrets in your app's environment, never in the command line or the repository.
