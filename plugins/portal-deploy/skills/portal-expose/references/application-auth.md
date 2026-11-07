# Protect an app with visitor sign-in

Use this when only chosen people should open the public URL ("only me", "my team", "private", "add a login", "restrict access"). The check runs inside the `portal` process on the user's machine, not at the relay, and covers the whole HTTP gateway: the proxied target, `--serve` files, every `--http-route`, and paid routes. Without it, anyone who learns the hostname can open the app. Add sign-in only when the user asks for it; do not enable it on your own (the workflow in `SKILL.md` says when to offer it).

> **Sync notice**: the method table, allowlist forms, session lifetime, secret handling, identity proof, and verification steps in this file mirror `docs/src/routes/siwe-authentication/+page.md`. When sign-in behavior changes, update both files together. The docs page is the human-facing source; this reference is the agent-facing copy.

## Choose a method

| The user wants | Method | Visitors need | The operator needs |
|---|---|---|---|
| A few named people, nothing external to set up | `credential` | A link from `portal auth issue` | Nothing |
| People who own an Ethereum wallet | `siwe` | A browser wallet | Nothing |
| People who already sign in at Google, Microsoft, Keycloak or another OpenID Connect provider | `oidc` | An account at that provider | An OAuth client registered at the provider |
| People who sign in at a SAML identity provider (Okta, Entra ID, ADFS, Keycloak, Shibboleth) that issues no OpenID Connect client | `saml` | An account at that provider | A SAML application registered at the provider |
| People the user knows by email address, with no identity provider | `email` | A mailbox | An SMTP account: a mailbox app password or a transactional mail service |

When the user does not say which, use `credential`: it needs no external setup. A credential link is a bearer token, not a password; whoever holds the link gets in until it expires.

Two keys hold the list of who may sign in. `--auth-allow` (`auth_allowed_wallets`) is the list for `siwe` and `credential`. `--auth-email-list` (`auth_email_list`) is the list for `oidc`, `saml` and `email`: a tunnel runs one provider, so the one list serves all three. `oidc` and `saml` still read `--auth-allow` / `auth_allowed_wallets`, so existing configs keep working. Setting both keys is refused. `email` takes only `--auth-email-list`.

## credential

```sh
portal expose 3000 --name my-app --identity-path /absolute/path/to/identity.json --auth credential
portal auth issue <host> --subject alice --expires 720h --identity-path /absolute/path/to/identity.json
```

- **Which host.** A credential works only on the host it was issued for, and a tunnel answers on more than one: on each relay, the address-bound URL that the ready line prints first (`service ready at https://my-app-<address>.<relay-host>`) and the short URL printed after it (`(short URL: https://my-app.<relay-host>)`), which exists only when the relay grants the name, not when another identity owns it; with discovery on, the tunnel runs on any `--relays` plus auto-selected relays (three by default, `--max-active-relays`). Issue the link for the host of the URL you hand over: the `alias_url` when granted, otherwise the `public_url`, as `SKILL.md` says for the report. A visitor who opens another host needs a link issued for that host.
- `portal auth issue` prints `Credential: ...` and `Redeem URL: ...`; opening the redeem URL signs the person in. The credential travels in the URL fragment, which a browser never sends in a request, so the relay does not see it. Both lines are the same bearer secret: whoever holds either gets in until it expires.
- **Handing a link over.** The one authorized delivery is the redeem URL, once, to the user who asked for it, in your final answer, for them to pass to the invitee; do not send it to anyone else or through another channel. Everywhere else it is a secret: do not write it to a file, a commit, an issue or pull request, a log or a note you keep, do not print it a second time, and leave the `Credential:` line out (the redeem URL is enough).
- **Captured output.** Capture the command's output, take the `Redeem URL:` line from it, and show only that line. Do not paste the raw output. If a tool has already recorded it, say so instead of repeating it; if the link may have leaked, issue a new one under a different subject (for example `alice-2`), list that subject and every other subject that should keep access (a tunnel that had no allowlist rejects every unlisted subject once it has one), take the old subject out of `--auth-allow` and restart. A credential has no ID of its own, so the tunnel cannot tell two links for the same subject apart: with no allowlist, or with the old subject still listed, the leaked link keeps working until it expires or the tunnel is stopped.
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

1. Decide the hosts visitors will use. Pass `--name`, and pin one relay with `--relays <https-url> --discovery=false` unless the user wants several: with discovery on, the tunnel runs on any `--relays` plus auto-selected relays (three by default, `--max-active-relays`), each with its own host. On each relay the tunnel answers on the address-bound URL that the ready line prints first (`service ready at https://my-app-<address>.<relay-host>`) and on the short URL printed after it (`(short URL: https://my-app.<relay-host>)`). There is no short URL when another identity owns the name.
2. At the provider, create an OAuth client of the web-application type. Note the client ID, and the client secret if the provider issues one. Portal builds the redirect URI from the host the visitor opened, so register `https://<host>/_portal/auth/callback` for every host visitors will use: the host of the URL you hand over (the `alias_url` when granted, otherwise the `public_url`), and the short and address-bound hosts on every relay when visitors may open those. A host learned only from the ready line can be added at the provider after the tunnel starts; visitors on a host without a registered callback cannot sign in.
3. Find the issuer URL. Google's is `https://accounts.google.com`. Any provider that publishes `<issuer>/.well-known/openid-configuration` works. The issuer must be `https`.
4. Decide who may sign in. `--auth-email-list` is required with `oidc`; without at least one entry Portal refuses to start, because the provider authenticates accounts that have nothing to do with the app.
   - `alice@example.com`: that email, only when the provider reports it as verified.
   - `@example.com`: any verified email on exactly that domain, not its subdomains.
   - `sub:<id>`: the provider's own subject identifier, for providers that do not verify email. Compared exactly, including case.
   - Email and domain matching ignores case but needs ASCII; write an internationalized domain in punycode.
5. The client secret reaches Portal only as `AUTH_OIDC_CLIENT_SECRET` in the environment of the shell that runs `portal expose`, never on the command line, where `ps` would show it. Your shell cannot see a variable the user sets at their own prompt, and you must not learn the secret, so when there is a client secret the user starts the tunnel, not you: give them the full commands below to run in their own terminal, then only verify (see Verify), asking them to paste the `service ready at` line, which holds no secret. Do not ask for the secret, type it, print it, or write it to a file. The prompt does not echo the secret or save it in shell history; if the user presses Ctrl-C at the Linux and macOS prompt, `stty echo` makes typing visible again. When the provider issued no secret, run the command yourself.

The user first reads the secret at a prompt. Linux and macOS (bash, zsh):

```sh
printf 'OIDC client secret: '; stty -echo; read -r AUTH_OIDC_CLIENT_SECRET; stty echo; echo; export AUTH_OIDC_CLIENT_SECRET
```

Windows PowerShell:

```powershell
$secret = Read-Host 'OIDC client secret' -AsSecureString; $env:AUTH_OIDC_CLIENT_SECRET = [System.Net.NetworkCredential]::new('', $secret).Password
```

Then, in that same shell, the user starts the tunnel (on PowerShell, on one line):

```sh
portal expose 3000 --name my-app --identity-path /absolute/path/to/identity.json \
  --auth oidc --auth-oidc-issuer https://accounts.google.com --auth-oidc-client-id <client-id> \
  --auth-email-list alice@example.com --auth-email-list @example.com
```

- `AUTH_OIDC_ISSUER`, `AUTH_OIDC_CLIENT_ID` and `AUTH_OIDC_CLIENT_SECRET` stand in for the three flags, and are used only together with `--auth oidc`; exporting them for one app does not change other `portal expose` runs. An `--auth-oidc-*` flag without `--auth oidc` is refused.
- At start Portal fetches the provider's discovery document and keys once and logs `application auth provider is not usable` when that fails. The tunnel keeps running; visitors cannot sign in until the provider is reachable.
- A session follows the provider's token lifetime, between 15 minutes and 24 hours. Sessions are re-checked against `--auth-email-list` on every request. Changing the list takes effect when the tunnel restarts.

## saml

Do these in order. Stop and ask the user for the missing value instead of guessing it.

1. Decide the hosts visitors will use, as in step 1 of the oidc section.
2. Find the identity provider's metadata URL, for example Keycloak's `https://<keycloak-host>/realms/<realm>/protocol/saml/descriptor`. It must be `https`. When the provider gives only a metadata file, use `--auth-saml-metadata-file <absolute path>` instead. Give one of the two, not both.
3. At the provider, the user adds a SAML application. Portal serves its service provider metadata at `https://<host>/_portal/auth/saml/metadata` and receives the response at `https://<host>/_portal/auth/saml/acs` (HTTP-POST binding). Both follow the host the visitor opened, and so does the default entity ID, which is the metadata address. When visitors use more than one host, pass one `--auth-saml-entity-id` (for example `urn:portal:my-app`) and register the ACS address of every host with it. The provider must sign the response or the assertion, must not encrypt assertions, and must not require signed requests. The service provider metadata leaves `WantAssertionsSigned` off because either signature is accepted; a response with neither is refused.
4. Decide the subject. By default it is the `NameID`; `--auth-saml-subject-attribute email` uses that attribute instead, which must carry one value.
5. Decide who may sign in. `--auth-email-list` is required with `saml`; without at least one entry Portal refuses to start.
   - `alice@example.com` or `@example.com`: match a subject that is an email address, the domain entry on exactly that domain. SAML has no `email_verified`, so Portal trusts the email the provider signs; tell the user to release only addresses that their users cannot change.
   - `sub:<id>`: the subject exactly, including case. Use it for a persistent `NameID`. A transient `NameID` changes at every login and never matches.

```sh
portal expose 3000 --name my-app --identity-path /absolute/path/to/identity.json \
  --auth saml --auth-saml-metadata-url https://<idp-host>/realms/<realm>/protocol/saml/descriptor \
  --auth-email-list @example.com
```

- No secret is involved, so you can run the command yourself.
- `AUTH_SAML_METADATA_URL`, `AUTH_SAML_METADATA_FILE`, `AUTH_SAML_ENTITY_ID` and `AUTH_SAML_SUBJECT_ATTRIBUTE` stand in for the four flags, and are used only together with `--auth saml`. An `--auth-saml-*` flag without `--auth saml` is refused.
- At start Portal reads the metadata once and logs `application auth provider is not usable` when that fails; it reads the metadata again every 15 minutes. The tunnel keeps running. Metadata in which every signing certificate has expired is refused, because a signature by an expired certificate is never accepted: the user renews the certificate at the provider.
- Visitors must start at the tunnel URL: a sign-in started from the provider's app list (IdP-initiated) is refused. Single logout is not supported.
- A session follows the provider's `SessionNotOnOrAfter`, between 15 minutes and 24 hours (24 hours when the provider sends none). Sessions are re-checked against `--auth-email-list` on every request. Changing the metadata source, the entity ID or the subject attribute signs everyone out.

## email

Do these in order. Stop and ask the user for the missing value instead of guessing it.

1. Get the SMTP server as `host:port`, for example `smtp.gmail.com:587`. Port 465 uses TLS from the start. On any other port the server must offer STARTTLS. Only a server at `localhost`, `127.0.0.1` or `::1` can receive plaintext.
2. Get the SMTP username, when the server requires a login. The password reaches Portal only as `AUTH_SMTP_PASSWORD` in the environment of the shell that runs `portal expose`, never on the command line. Handle it as step 5 of the oidc section handles the client secret: the user reads it at a prompt and starts the tunnel in their own terminal, and you do not ask for it, type it, print it, or write it to a file. Username and password are set together or not at all.
3. Get the sender for `--auth-smtp-from`: one address that the SMTP account can send from, with an optional display name such as `"Portal <login@example.com>"`. Every mail comes from it, and no visitor input can change it.
4. Decide who may sign in. `--auth-email-list` is required with `email`; without at least one entry Portal refuses to start, because anyone could make the tunnel mail any address.
   - `alice@example.com`: that address.
   - `@example.com`: any address on exactly that domain, not its subdomains.
   - `sub:<id>` is refused: a mailbox has no other ID.
   - Matching ignores case but needs ASCII; write an internationalized domain in punycode.
   - An address entry that no visitor could sign in with, for example one that contains a space, `%` or `!`, stops the tunnel at startup.

The user first reads the password at a prompt. Linux and macOS (bash, zsh):

```sh
printf 'SMTP password: '; stty -echo; read -r AUTH_SMTP_PASSWORD; stty echo; echo; export AUTH_SMTP_PASSWORD
```

Windows PowerShell:

```powershell
$secret = Read-Host 'SMTP password' -AsSecureString; $env:AUTH_SMTP_PASSWORD = [System.Net.NetworkCredential]::new('', $secret).Password
```

Then, in that same shell, the user starts the tunnel (on PowerShell, on one line):

```sh
portal expose 3000 --name my-app --identity-path /absolute/path/to/identity.json \
  --auth email --auth-smtp-addr smtp.gmail.com:587 \
  --auth-smtp-username you@gmail.com --auth-smtp-from you@gmail.com \
  --auth-email-list alice@example.com --auth-email-list @example.com
```

- When the server needs no login, no secret is involved, so you can run the command yourself.
- `AUTH_SMTP_ADDR`, `AUTH_SMTP_USERNAME`, `AUTH_SMTP_PASSWORD` and `AUTH_SMTP_FROM` stand in for the four flags, and are used only together with `--auth email`. An `--auth-smtp-*` flag without `--auth email` is refused.
- The visitor enters an address on the sign-in page and gets a link `https://<host>/_portal/auth/login#email_token=...`. The link works once, for 10 minutes, and only on the host it was sent for. Opening it shows a page with a Continue button: the page removes the token from the address when it loads and posts it only on that click. A mail scanner that only fetches the URL, or that opens the page and runs its script without clicking, does not use up the link. Links are kept in memory: a restart cancels the unused ones, and the visitor asks again.
- Portal sends a link only for a host where the tunnel is published now (a relay's address-bound URL, or its short URL while granted). A request for any other host gets `403`.
- A visitor's address that contains `%` or `!` is refused with `400`: a mail server can route on those characters, so the allowlist could not vouch for where the mail ends up. The page answers every other well-formed address the same way, whether it is allowed or not, and sends the mail after it answers.
- One address gets at most one link per minute and five per hour. The addresses that only an `@domain` entry allows also share 50 links per hour: one budget for all `@domain` entries together, not one per domain. So made-up addresses in any allowed domain can use up the budget and block the real users of every `@domain` entry while the flood lasts and for up to an hour after it, because the window rolls; list addresses exactly where that matters. An exactly listed address is outside that budget, and the per-address limits bound its mailbox. A mailbox behind an `@domain` entry is limited only by the shared budget, because `alice+1@` and `alice+2@` can reach one mailbox.
- A visitor never sees why no mail came. A failed send shows only in the tunnel log as `email login link not sent`, and a refusal by a limit or by the allowlist logs nothing, so a quiet log can mean a refusal.
- The mail has no `To` header, by design: the recipient is named only in the SMTP envelope. Delivery, spam placement, SPF, DKIM and DMARC belong to the operator's SMTP account.
- Changing the SMTP server, username or sender ends every email session. A new password alone does not.
- At start Portal checks the SMTP server once without sending mail and logs `application auth provider is not usable` when that fails. The tunnel keeps running. The check proves the server, TLS, and the login. It sends no `MAIL FROM`, so it does not prove the sender. With no username it signs in to nothing, so it proves only that the server answers, with TLS where TLS is required.
- Portal signs in with AUTH PLAIN only. A server that offers only AUTH LOGIN fails at the startup check.
- A session lasts 24 hours. Sessions are re-checked against `--auth-email-list` on every request. Changing the list takes effect when the tunnel restarts.

## Common options

- `--auth-identity-headers` passes the verified identity to the app as `X-Portal-User` (wallet address, credential subject, `alice@example.com` / `sub:<id>` for OIDC and SAML, or the email address for email) and `X-Portal-Auth` (`siwe`, `credential`, `oidc`, `saml`, `email`). Portal strips any client-supplied copies. Tell the user the app may trust these headers only when nothing but Portal can reach the app's port: binding the app to loopback keeps other machines out, but any other process on the same machine can still connect to that port and send forged headers. When other local processes can reach it, add `--auth-identity-proof` (only with `--auth-identity-headers`, and only when the user's app will check it): Portal then also sends `X-Portal-Proof: <secret>`, always strips a visitor's copy, and the app compares the header with the same secret in constant time and ignores the identity headers when it differs or is missing. Pass the secret as `AUTH_IDENTITY_PROOF`, never as a flag value, where `ps` would show it. Generate it once into a file only the user can read, outside the repository, and set the variable for the one command, so it is never typed or printed:

  ```sh
  (umask 077 && mkdir -p ~/.config/portal && openssl rand -hex 32 > ~/.config/portal/my-app.proof)
  AUTH_IDENTITY_PROOF="$(cat ~/.config/portal/my-app.proof)" portal expose 3000 --name my-app --auth credential --auth-identity-headers
  ```

  The app reads the same file. Never print the file or the header value, and tell the user that the app must not log `X-Portal-Proof`. Use one secret per tunnel: it reaches every upstream of the tunnel, in cleartext over a plain `http` upstream. A persistent agent tunnel cannot send the proof.
- A session works from the app's own origin. When a request carries the session cookie and an `Origin` of another origin, Portal answers `403` to an upgrade such as a WebSocket and to any method other than `GET`, `HEAD`, or `OPTIONS`. A request without `Origin`, a request with `X-Portal-Access-Credential`, and a form post with `Origin: null` that a browser marks with `Sec-Fetch-Site: same-origin` (a page with `Referrer-Policy: no-referrer` sends one) are not affected.
- Sign-in cannot be combined with `--tcp`, `--udp` or `--cache`; the tunnel refuses to start. Portal answers ten exact paths itself and never forwards them to the app: `/_portal/auth/login`, `/_portal/auth/challenge`, `/_portal/auth/verify`, `/_portal/auth/redeem`, `/_portal/auth/callback`, `/_portal/auth/saml/acs`, `/_portal/auth/saml/metadata`, `/_portal/auth/email/request`, `/_portal/auth/email/redeem` and `/_portal/auth/logout`. The app must not need those paths; other paths under `/_portal/auth/` reach it behind the sign-in check.
- Sessions use a `Secure`, `HttpOnly` cookie that Portal removes before forwarding the request to the app.

## Persistent agent

The same settings are fields of a `[[tunnels]]` entry, except `--auth-identity-proof`, which has no key: an agent tunnel cannot send the identity proof, and the agent does not read `AUTH_IDENTITY_PROOF`. The agent does not read the `AUTH_OIDC_*` variables and has no way to refer to a secret, so a client secret can only be stored in the TOML file as plain text. Tell the user so, and store it only after they explicitly accept that risk (the rule is in `references/safety-and-verification.md`). If they do not, the user runs the tunnel with `portal expose` from their own terminal, as step 5 of the oidc section describes.

When they accept, first make the config file private, before any secret exists: `chmod 600 <config>`, and check that its folder is not open to other users. A new file takes the user's umask, often `0644`. A recent agent clears the group and other permissions itself before it stores a secret (on Windows it checks the file's ACL), but an older one writes the file with the mode it already has, so a `0644` file would hold the secret readable by everyone from the moment it is saved, and a file you write by hand is never tightened. Do it first either way. Then, without learning or writing the secret yourself, leave `auth_oidc_client_secret` out of the entry, and once the agent runs ask the user to type it in the dashboard. In `portal agent dashboard` they select the tunnel and open the Access screen (`F4`), type the secret in the Client secret row (hidden as typed; `F3` shows it so they can check it), and apply with `F2`. The agent writes it to the config file and restarts that tunnel only. Until then visitors cannot finish signing in with a provider that issues a secret. Writing it into the TOML file yourself is the fallback only when the user insists on it, after the same explicit acceptance and the same `0600` first, and then you handle the secret: never print it or paste it into logs or the final answer.

Either way the file then holds a secret: keep it outside the repository (or in an ignored path), owned by the user, still `0600`, and say in the handoff that the file holds a secret. Leave `auth_oidc_client_secret` empty only when the provider registered the client without a secret. A tunnel with neither `identity_path` nor `identity_json` keeps its identity in `<state_dir>/identity.json`, or `<state_dir>/<id>/identity.json` when the config has more than one tunnel: pass that file as `--identity-path` to `portal auth issue`; a relative `identity_path` is resolved against the config file's folder, not the shell's.

```toml
[[tunnels]]
id = "web"
name = "my-app"
target = "127.0.0.1:3000"
relays = ["https://<relay-host>"]
discovery = false
auth = "oidc"
auth_oidc_issuer = "https://accounts.google.com"
auth_oidc_client_id = "<client-id>"
# auth_oidc_client_secret = "<client-secret>"  # only with the user's consent; Google web clients need one
auth_email_list = ["alice@example.com"]
auth_identity_headers = true
```

A `saml` entry takes `auth = "saml"`, `auth_saml_metadata_url` (or `auth_saml_metadata_file`, relative to the config file), and the optional `auth_saml_entity_id` and `auth_saml_subject_attribute`. It holds no secret.

An `email` entry takes `auth = "email"`, `auth_email_list`, `auth_smtp_addr`, `auth_smtp_from`, and, for a server that requires a login, `auth_smtp_username` and `auth_smtp_password`. Each tunnel holds its own SMTP settings. The agent does not read the `AUTH_SMTP_*` variables, so the password can only be stored in the TOML file as plain text: it is a secret like the client secret, and the same consent, the same `0600` first, and the same rules for who types it apply. The Agent API never returns it and reports only `auth_smtp_password_set`.

`auth_email_list` holds the allowlist for `oidc`, `saml` and `email`, and `auth_allowed_wallets` holds it for `siwe` and `credential`. To change a list on a running agent tunnel, edit the file and run `portal agent restart`, which restarts every tunnel of the service, or have the user change it in the dashboard's Access screen (`F4`), or send `PATCH /agent/tunnels/{id}` (documented on the agent page), which restarts only that tunnel and writes the file too.

## Verify

Without signing in as the user:

1. `curl -sI https://<host>/` returns `303` with `Location: /_portal/auth/login?next=%2F`. A `200` means the gate is not on; stop and report it.
2. `curl -s -X POST https://<host>/` returns `401` with `{"error":"authentication required"}`.
3. `credential`: `curl -s -H "X-Portal-Access-Credential: $C" https://<host>/` returns the app's real response. Use the credential you already issued for the subject you hand over (from the captured output, kept in a shell variable); do not issue one just to verify, and do not paste it into the final answer. If you do not hold one, skip this step and say so.
4. `oidc` and `saml`: `curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' https://<host>/_portal/auth/login` prints `303` and the provider's authorization endpoint or SAML single sign-on URL. Use GET: a login starts only on GET, and HEAD answers `405`. Do not complete a provider login on the user's behalf.
5. `saml`: `curl -s https://<host>/_portal/auth/saml/metadata` returns the service provider metadata with the entity ID and the ACS address that the provider must have.
6. `email`: `curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Origin: https://<host>' -H 'Content-Type: application/json' -d '{"email":"nobody@example.invalid"}' https://<host>/_portal/auth/email/request` prints `202`. That address is on no allowlist, so no mail goes out. A `403` means the host is not one the tunnel is published at now. Do not request a link for a real address on the user's behalf.

## When it fails

| Message | Cause and fix |
|---|---|
| `oidc requires at least one --auth-email-list entry` | Add an allowlist entry. |
| `oidc issuer url is required` / `must use https` | Pass an `https` issuer. |
| `oidc client id is required` | Pass `--auth-oidc-client-id`. |
| `oidc settings require the oidc application auth provider` | An `--auth-oidc-*` flag was given together with another `--auth` provider. |
| `saml requires at least one --auth-email-list entry` | Add an allowlist entry. |
| `saml requires identity provider metadata` / `not both` | Pass exactly one of `--auth-saml-metadata-url` and `--auth-saml-metadata-file`. |
| `saml metadata url must use https` | Pass an `https` metadata URL. |
| `saml settings require the saml application auth provider` | An `--auth-saml-*` flag was given together with another `--auth` provider. |
| `email requires at least one --auth-email-list entry` | Add an allowlist entry. |
| `email allows email addresses and @domain entries only` | Remove the `sub:` entries. |
| `principal "...": email address is invalid` | No visitor could sign in with that `--auth-email-list` address, for example because it contains a space, `%` or `!`. Correct or remove it. |
| `email reads its addresses from --auth-email-list, not --auth-allow` | Move the entries to `--auth-email-list`. |
| `--auth-email-list and --auth-allow are the same list: set one` | Keep one of the two keys. |
| `--auth-email-list works with oidc, saml, and email; siwe and credential use --auth-allow` | Use `--auth-allow` with `siwe` and `credential`. |
| `email requires an SMTP server` / `email smtp address must be host:port` | Pass `--auth-smtp-addr host:port` with a port from 1 to 65535. |
| `email requires a sender address` / `email sender must be one ASCII email address` | Pass one sender address with `--auth-smtp-from`. |
| `email smtp username and password are set together or not at all` | Set both `--auth-smtp-username` and `AUTH_SMTP_PASSWORD`, or neither. |
| `email settings require the email application auth provider` | An `--auth-smtp-*` flag was given together with another `--auth` provider. |
| `unsupported application auth provider ""` | `--auth-allow`, `--auth-email-list`, `--auth-identity-headers`, `--auth-identity-proof`, or an `--auth-oidc-*`, `--auth-saml-*` or `--auth-smtp-*` flag was given without `--auth`. |
| `identity proof (--auth-identity-proof / AUTH_IDENTITY_PROOF) requires --auth-identity-headers` | Add `--auth-identity-headers`, or drop the proof. |
| `identity proof (--auth-identity-proof / AUTH_IDENTITY_PROOF) must be at least 16 characters of visible ASCII without spaces` | Generate the value with `openssl rand -hex 32` as above. |
| `HTTP tunnel cannot be combined with TCP or UDP` | Remove `--tcp` / `--udp`, or drop sign-in. |
| `application auth cannot be combined with relay cache` | Remove `--cache`, or drop sign-in. |
| `request origin is not allowed` (`403`) from a signed-in page | A page on another origin called this app with the session cookie. Serve that page from this app's origin. A credential header does not help in a browser: it forces a preflight, and the gate answers that with `401`. |
| "This account is not allowed" comes back on Sign in again | The browser is still signed in to the provider with the refused account, and the provider lets it straight back in. Sign in again asks the provider for its account chooser, so pick another account there, or sign out of the provider first. |
| The provider reports a redirect URI mismatch | No callback is registered for the host the visitor opened. Register `https://<host>/_portal/auth/callback` for that exact host too: the short and the address-bound host differ, and so does each relay's. |
| `application auth provider is not usable` in the log | The OIDC issuer or the SAML metadata source is wrong or unreachable from this machine, or the tunnel could not sign in to the SMTP server: a wrong address, username or password, a server without STARTTLS (`smtp server does not offer STARTTLS`), or a server that offers only AUTH LOGIN. Use port 465 or a server that offers STARTTLS, and a server that takes AUTH PLAIN. |
| `email login link not sent` in the log | The SMTP server refused the mail, for example a sender the account cannot send from, or the server could not be reached. For the recipient and data steps the error shows only the SMTP reply code, never the recipient. The visitor saw the same answer as for a sent link. |
| `email login link not sent` with the error `every email send slot is in use` | Four sends were running, so Portal dropped this one. The visitor saw the same answer as for a sent link and asks again. |
| No mail came and the log shows nothing | A limit or the allowlist may have refused the address: refusals log nothing. Otherwise the server took the mail, and delivery belongs to the SMTP account. |
| A SAML login ends on "Sign-in could not be completed" | The response failed a check: the entity ID or ACS address registered at the provider does not match this host, the provider encrypts assertions, signs nothing, or the login started at the provider's app list. Compare the provider's settings with `https://<host>/_portal/auth/saml/metadata`. |
