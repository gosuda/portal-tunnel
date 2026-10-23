# Protect an app with visitor sign-in

Use this when only chosen people should open the public URL ("only me", "my team", "private", "add a login", "restrict access"). The check runs inside the `portal` process on the user's machine, not at the relay, and covers the whole HTTP gateway: the proxied target, `--serve` files, every `--http-route`, and paid routes. Without it, anyone who learns the hostname can open the app. Add sign-in only when the user asks for it; do not enable it on your own (the workflow in `SKILL.md` says when to offer it).

> **Sync notice**: the method table, allowlist forms, session lifetime, secret handling, and verification steps in this file mirror `docs/src/routes/siwe-authentication/+page.md`. When sign-in behavior changes, update both files together. The docs page is the human-facing source; this reference is the agent-facing copy.

## Choose a method

| The user wants | Method | Visitors need | The operator needs |
|---|---|---|---|
| A few named people, nothing external to set up | `credential` | A link from `portal auth issue` | Nothing |
| People who own an Ethereum wallet | `siwe` | A browser wallet | Nothing |
| People who already sign in at Google, Microsoft, Keycloak or another OpenID Connect provider | `oidc` | An account at that provider | An OAuth client registered at the provider |

When the user does not say which, use `credential`: it needs no external setup. A credential link is a bearer token, not a password; whoever holds the link gets in until it expires.

## credential

```sh
portal expose 3000 --name my-app --identity-path /absolute/path/to/identity.json --auth credential
portal auth issue my-app.<relay-host> --subject alice --expires 720h --identity-path /absolute/path/to/identity.json
```

- `portal auth issue` prints `Credential: ...` and `Redeem URL: ...`; opening the redeem URL signs the person in. The credential travels in the URL fragment, which a browser never sends in a request, so the relay does not see it. Both lines are the same bearer secret: whoever holds either gets in until it expires.
- **Handing a link over.** The one authorized delivery is the redeem URL, once, to the user who asked for it, in your final answer, for them to pass to the invitee; do not send it to anyone else or through another channel. Everywhere else it is a secret: do not write it to a file, a commit, an issue or pull request, a log or a note you keep, do not print it a second time, and leave the `Credential:` line out (the redeem URL is enough).
- **Captured output.** Capture the command's output, take the `Redeem URL:` line from it, and show only that line. Do not paste the raw output. If a tool has already recorded it, say so instead of repeating it; if the link may have leaked, issue a new one under a different subject (for example `alice-2`), list that subject, take the old subject out of `--auth-allow` and restart. A credential has no ID of its own, so the tunnel cannot tell two links for the same subject apart: with no allowlist, or with the old subject still listed, the leaked link keeps working until it expires or the tunnel is stopped.
- **What the final answer says about a link:** the subject name, when it expires, the redeem URL once, that it is a bearer link that works for anyone who holds it until then and only for this host, and how to end its access, which ends per subject, not per link (take the subject out of the allowlist, keeping it non-empty, and restart, or stop the tunnel).
- Use the same identity file for `expose` and `auth issue`: the tunnel's identity signs the credential, and the credential is valid only for that tunnel and that exact public hostname. The default lifetime is 30 days.
- A script or API client sends the credential in the `X-Portal-Access-Credential` header.
- With no `--auth-allow`, every unexpired credential signs in and only expiry ends it. To make a credential revocable before it expires, list its subject with `--auth-allow alice` (repeatable); the tunnel then rejects any subject that is not listed, and taking a subject out of the list and restarting the tunnel ends its access. Keep the list non-empty: removing the last subject leaves it empty, and an empty list lets every unexpired credential in again. To end access for the last person, stop the tunnel (or list a name no credential was issued for).

## siwe

```sh
portal expose 3000 --name my-app --auth siwe --auth-allow 0xAbc...
```

- `--auth-allow` takes Ethereum addresses and is repeatable. Without it, any wallet can sign in, which proves only that the visitor controls some address. Confirm with the user before leaving it empty. Removing the last address later leaves the list empty and lets any wallet in; stop the tunnel instead.
- The visitor signs a one-time message in their browser wallet. No transaction and no gas.

## oidc

Do these in order. Stop and ask the user for the missing value instead of guessing it.

1. Decide the exact public hostname first. Pass `--name` so it is known before the tunnel starts: `https://<name>.<relay-host>`.
2. At the provider, create an OAuth client of the web-application type and register the redirect URI `https://<name>.<relay-host>/_portal/auth/callback`. Note the client ID, and the client secret if the provider issues one.
3. Find the issuer URL. Google's is `https://accounts.google.com`. Any provider that publishes `<issuer>/.well-known/openid-configuration` works. The issuer must be `https`.
4. Decide who may sign in. `--auth-allow` is required with `oidc`; without at least one entry Portal refuses to start, because the provider authenticates accounts that have nothing to do with the app.
   - `alice@example.com`: that email, only when the provider reports it as verified.
   - `@example.com`: any verified email on exactly that domain, not its subdomains.
   - `sub:<id>`: the provider's own subject identifier, for providers that do not verify email. Compared exactly, including case.
   - Email and domain matching ignores case but needs ASCII; write an internationalized domain in punycode.
5. Pass the client secret through the environment, never on the command line, where `ps` would show it. The user sets `AUTH_OIDC_CLIENT_SECRET` in their own shell; do not type it into a shell for them, print it, or write it to a file in the repository. A secret typed into an interactive shell lands in shell history, so tell the user to read it at a prompt instead (the prompt lines are in the OpenID Connect section of the Application Authentication docs page, `docs/src/routes/siwe-authentication/+page.md`), then start the tunnel from that shell:

```sh
# AUTH_OIDC_CLIENT_SECRET is already set in this shell by the user
portal expose 3000 --name my-app --identity-path /absolute/path/to/identity.json \
  --auth oidc --auth-oidc-issuer https://accounts.google.com --auth-oidc-client-id <client-id> \
  --auth-allow alice@example.com --auth-allow @example.com
```

- `AUTH_OIDC_ISSUER`, `AUTH_OIDC_CLIENT_ID` and `AUTH_OIDC_CLIENT_SECRET` stand in for the three flags, and are used only together with `--auth oidc`; exporting them for one app does not change other `portal expose` runs. An `--auth-oidc-*` flag without `--auth oidc` is refused.
- At start Portal fetches the provider's discovery document and keys once and logs `application auth provider is not usable` when that fails. The tunnel keeps running; visitors cannot sign in until the provider is reachable.
- A session follows the provider's token lifetime, between 15 minutes and 24 hours. Sessions are re-checked against `--auth-allow` on every request. Changing the list takes effect when the tunnel restarts.

## Common options

- `--auth-identity-headers` passes the verified identity to the app as `X-Portal-User` (wallet address, credential subject, or `alice@example.com` / `sub:<id>` for OIDC) and `X-Portal-Auth` (`siwe`, `credential`, `oidc`). Portal strips any client-supplied copies. Tell the user the app may trust these headers only if it is reachable solely through Portal: bind it to loopback.
- Sign-in cannot be combined with `--tcp`, `--udp` or `--cache`; the tunnel refuses to start. Portal serves its own pages under `/_portal/auth/`, so the app must not use that prefix.
- Sessions use a `Secure`, `HttpOnly` cookie that Portal removes before forwarding the request to the app.

## Persistent agent

The same settings are fields of a `[[tunnels]]` entry. The agent does not read the `AUTH_OIDC_*` variables and has no way to refer to a secret, so a client secret can only be stored in the TOML file as plain text. Do not put it there on your own: tell the user so, and write it only after they explicitly accept that risk (the rule is in `references/safety-and-verification.md`). If they do not, run the tunnel with `portal expose` and `AUTH_OIDC_CLIENT_SECRET` in the environment instead. When they accept, keep the file outside the repository (or in an ignored path), owned by the user with mode `0600` in a directory only they can read, never print the secret or paste it into logs or the final answer, and say in the handoff that the file holds a secret. Leave `auth_oidc_client_secret` empty only when the provider registered the client without a secret. A tunnel with neither `identity_path` nor `identity_json` keeps its identity in `<state_dir>/identity.json`, or `<state_dir>/<id>/identity.json` when the config has more than one tunnel: pass that file as `--identity-path` to `portal auth issue`; a relative `identity_path` is resolved against the config file's folder, not the shell's.

```toml
[[tunnels]]
id = "web"
name = "my-app"
target = "127.0.0.1:3000"
auth = "oidc"
auth_oidc_issuer = "https://accounts.google.com"
auth_oidc_client_id = "<client-id>"
auth_allowed_wallets = ["alice@example.com"]
auth_identity_headers = true
```

`auth_allowed_wallets` holds the allowlist for every method, not only wallets.

## Verify

Without signing in as the user:

1. `curl -sI https://<host>/` returns `303` with `Location: /_portal/auth/login?next=%2F`. A `200` means the gate is not on; stop and report it.
2. `curl -s -X POST https://<host>/` returns `401` with `{"error":"authentication required"}`.
3. `credential`: `curl -s -H "X-Portal-Access-Credential: $C" https://<host>/` returns the app's real response. Use a credential the user issued; do not paste it into the final answer.
4. `oidc`: `curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' https://<host>/_portal/auth/login` prints `303` and the provider's authorization endpoint. Use GET: a login starts only on GET, and HEAD answers `405`. Do not complete a provider login on the user's behalf.

## When it fails

| Message | Cause and fix |
|---|---|
| `oidc requires at least one --auth-allow entry` | Add an allowlist entry. |
| `oidc issuer url is required` / `must use https` | Pass an `https` issuer. |
| `oidc client id is required` | Pass `--auth-oidc-client-id`. |
| `oidc settings require the oidc application auth provider` | An `--auth-oidc-*` flag was given together with `--auth siwe` or `--auth credential`. |
| `unsupported application auth provider ""` | `--auth-allow`, `--auth-identity-headers` or an `--auth-oidc-*` flag was given without `--auth`. |
| `HTTP tunnel cannot be combined with TCP or UDP` | Remove `--tcp` / `--udp`, or drop sign-in. |
| `application auth cannot be combined with relay cache` | Remove `--cache`, or drop sign-in. |
| The provider reports a redirect URI mismatch | The registered redirect URI differs from `https://<host>/_portal/auth/callback`; the host must match the tunnel's public hostname exactly. |
| `application auth provider is not usable` in the log | The issuer is wrong or unreachable from this machine. |
