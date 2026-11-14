# Webhook and callback endpoints

Use this reference when the public URL will be registered with another service that calls it: a Discord Interactions endpoint, a Stripe, GitHub, or Slack webhook, an OAuth redirect URI, or a Discord Activity URL mapping. The human-facing copy is the docs page `docs/src/routes/webhook-endpoints/+page.md`; when either changes, update both.

Portal only carries the requests. Signature checks, challenge replies, and response deadlines belong to the app.

## Keep the URL stable

The other service stores the URL, so it must not change between runs.

- Pass the same explicit `--name` and an absolute `--identity-path` outside the repository, and reuse that identity file every time. A new identity file gets a new address. An explicit name selects a service without rewriting the existing key file; omitting it uses a legacy saved name or an unnamed service.
- Register the granted short URL (`alias_url`, `https://<name>.<relay-host>/...`) with the exact path the app serves, for example `/interactions`.
- Pin the relay with `--relays <url> --discovery=false`, because the hostname belongs to one relay.
- When the endpoint must stay reachable after the terminal closes, use the persistent `portal agent` mode in `portal-cli.md`. A temporary preview is fine for one test session.

## Order of steps

1. Start the local app and check its health locally (workflow step 2).
2. Expose it and wait for `service ready at`.
3. Check the public endpoint (below).
4. Only then give the user the URL to register. Many services send a test request when the URL is saved and reject the URL if that request fails.

## Verify without credentials

A plain `GET` often does not prove a webhook works, and some answers that look like errors are correct:

- `405 Method Not Allowed` for `GET` on a `POST`-only route: reachable.
- `401` for a request without a valid signature: reachable, and the signature check works. This is the expected answer to an unsigned test.
- `404`: the path is wrong, or the app does not serve it.
- TLS failure, `5xx`, or a Portal error page: report as failed, as `SKILL.md` describes.

Make one unsigned `POST` with an empty JSON body (`curl -sS --max-time 10 -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' --data '{}' https://<alias>/<path>`). Expect `401` from an app that checks signatures. A `200` means the app accepts unsigned requests: report it as a security problem in the app, not as success.

## Credentials

Never ask for a bot token, client secret, signing secret, or webhook secret in chat, and never put one on the command line or in the repository. The app reads them from its own environment. The agent does not sign in to the other service's console; give the user the URL and the exact field to paste it into.

## Discord Interactions endpoint

For slash commands and other interactions over HTTP (not the Gateway):

- **Developer Portal:** application > **General Information** > **Interactions Endpoint URL**, for example `https://discord-bot.<relay-host>/interactions`. When it is saved, Discord sends a `PING` and also checks that the app rejects a bad signature, so the endpoint must be live first. Discord also sends invalid signatures later as routine checks and removes the URL when the app accepts one, so keep the signature check on.
- **App requirements:**
  - Verify `X-Signature-Ed25519` and `X-Signature-Timestamp` against the application's public key on every request, and answer `401` when the check fails.
  - Answer a `PING` (`type: 1`) with `200` and `{"type": 1}` with a JSON `Content-Type`.
  - Send the first response to each interaction within 3 seconds. For longer work, reply with a deferred response (`type: 5`) and send the result as a follow-up; the interaction token stays valid for 15 minutes.
- **Example:**

  ```sh
  portal expose 3000 --name discord-bot \
    --identity-path /absolute/path/outside/repo/discord-bot.json \
    --relays https://portal.example.com --discovery=false
  ```

A bot that uses only the Gateway (a WebSocket the bot opens to Discord) needs no public URL and no Portal tunnel.

## Discord Activity

An Activity is a web app that Discord loads through its own proxy. Expose the Activity's web server as above, then in the Developer Portal set the Activity's URL mapping for `/` to the public hostname without the scheme (`discord-activity.<relay-host>`). Keep the same identity so the mapping stays valid.
