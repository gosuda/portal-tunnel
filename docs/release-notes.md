# Release notes

## Unreleased

### Relay: a budget for unapproved leases

An unapproved lease routes nothing, but it holds an alias, a port, and capacity.
`--unapproved-leases-per-source` (`UNAPPROVED_LEASES_PER_SOURCE`, default `64`)
bounds how many such leases one IP can hold. Over the budget, registration gets
`429 rate_limited` and the SDK retries every 5 minutes. Approved identities never
count, and this budget never refuses them. `0` turns the bound off.

An embedder of `portal.Server` with its own mux must follow two changes:
`HandleRegister` no longer takes an address, because a lease belongs to the source
that asked for its challenge, and `RefuseChallengeOverBudget` must be called after
the access decision for the limit to apply.

### Tunnels report the approval wait

On a `manual` relay, a tunnel now tells you when the relay does not route it.
`RelayStatus.Approval` is `pending` or `refused`, the `relay_status` log event
has the same `approval` field, and `/agent/status` reports it per relay. The
dashboard shows `waiting` or `refused`. While it is set, the status carries no
URL and no raw address.

A revoke, denial, or ban used to leave the tunnel `ready` while nothing routed.
The relay now closes the lease's idle reverse streams, so every SDK version
leaves `ready` at once. A denied or banned lease gets the new `lease_denied`
code on reverse connect. `lease_rejected` keeps meaning not approved yet. The
browser SDK cannot read these refusals, so a revoked lease there registers again
on each retry until the relay approves it.

Raw TCP and UDP tunnels now log `raw transport endpoints allocated` when a
reverse stream opens, not at registration. Automation that reads this line as
ready now waits for approval, which is what it needed.

In Go, `portal.Server.SetServiceIdentityRoutable` is now
`SetServiceIdentityAccess` and takes a `types.LeaseAccess`.
`SetIdentityRoutable` is gone.

### Relay: initial approval mode

`--approval-mode` (`APPROVAL_MODE`) sets the lease approval mode on startup, so
a private relay no longer has a window on `auto` before the first admin call.
The default stays `auto`, and any other value than `auto` or `manual` stops
startup. A mode saved in `policy.json` wins. The relay saves the mode on any
admin change, so a relay that has saved `auto` stays open under
`APPROVAL_MODE=manual` and logs a warning.
### Application auth for Go programs

Package `sdk/appauth` is the sign-in gate of `portal expose --auth` as an
`http.Handler`, for a Go program that embeds the SDK. `New` builds the gate and
reads no network, and `Check` tests the provider. `PrincipalFromContext` gives
the handler the provider, the subject, and the verified email. A rebuilt gate
keeps its sessions when the identity and the provider settings stay the same.
See [Go Application Auth](/api-reference/sdk#go-application-auth).

For `portal` users nothing changes: flags, config keys, and the Agent API stay
the same. A session cookie now also holds the verified email. A session made
before this release keeps working.

### Application auth: a session works from its own origin

When a request carries a session cookie and an `Origin` of another origin, the
sign-in gate now answers `403` to a protocol upgrade, such as a WebSocket, and
to any method other than `GET`, `HEAD`, or `OPTIONS`. A request without `Origin`,
a request that presents `X-Portal-Access-Credential`, and a form post with
`Origin: null` that a browser marks with `Sec-Fetch-Site: same-origin`, which a
page with `Referrer-Policy: no-referrer` sends, are not affected. A page on another
origin that called a protected tunnel this way must move to the tunnel's origin.

### Application auth: email sign-in links

`--auth email` signs visitors in with a one-time link that the tunnel sends
through the operator's own SMTP account. A visitor enters an email address, and
an address on the allowlist gets a link that works once, for 10 minutes. Opening
the link shows a page with a Continue button, and the token is posted only on
that click, so a mail scanner that does not click does not use up the link. A
visitor's address that contains `%` or `!` is refused with `400`, because a mail
server can route on those characters.

The CLI flags are `--auth-smtp-addr`, `--auth-smtp-username`,
`--auth-smtp-password` (`AUTH_SMTP_PASSWORD`), and
`--auth-smtp-from`. The agent config and the Agent API take the same settings
per tunnel as `auth_smtp_addr`, `auth_smtp_username`,
`auth_smtp_password`, and `auth_smtp_from`. The password is write-only:
`GET /agent/status` reports only `auth_smtp_password_set`. The startup check
tests the SMTP server, TLS, and the login without sending mail and reports in
`auth_provider_checked` and `auth_provider_error`.

`--auth-email-list` (`auth_email_list`) is the list for `oidc`, `saml`, and
`email`. `email` requires at least one entry and takes only this list. `oidc`
and `saml` keep reading `--auth-allow` (`auth_allowed_wallets`), so existing
configs keep working, and setting both keys is refused. `siwe` and `credential`
keep `--auth-allow`.

The command builder now writes `--auth-email-list` for `oidc` and `saml`. An
installed `portal` older than this release refuses that flag, so update
`portal` before you run a command that you copied from the builder.

### Agent config: one typed tunnel configuration

The CLI, the agent config, and the Agent API now share one typed tunnel
configuration. The keys of `config.toml` and the fields of the Agent API stay
the same. Three behaviors change:

- When the agent saves `config.toml`, it no longer writes defaults that were
  not set, such as `max_active_relays = 3` or `discovery = true`. A value that a
  file already holds stays in it. An earlier agent fills the same defaults, so
  it reads such a file the same way.
- Each `config.toml` value must have its documented type. The agent no longer
  converts a quoted number or boolean, so it refuses `max_active_relays = "3"`.
- `PATCH /agent/tunnels/{id}` refuses an `auth_*` field that the agent does not
  know. Before, the agent ignored it. It also refuses one auth field sent twice
  in two spellings, such as `auth` and `AUTH`.

### Agent control API: provider check fields renamed

`GET /agent/status` reports the startup check of an OIDC or SAML identity
provider as `auth_provider_checked` and `auth_provider_error`. The fields were
named `auth_oidc_provider_checked` and `auth_oidc_provider_error`, and the old
names are no longer sent. A client that reads them must read the new names. The
`portal agent dashboard` of the same release already does.

### Breaking SDK change: UDP replies preserve lease ownership

Applications using `Exposure.AcceptDatagram` and `Exposure.SendDatagram` must
reuse the accepted `types.DatagramFrame` and replace only its `Payload` for a
reply. Constructing a new frame with just `FlowID`, `RelayURL`, and `Address`
no longer works: replies now require the original frame's local `LeaseDone`
token to prevent traffic from crossing lease instances after re-registration.

`SendDatagram` rejects ended or missing lease ownership with an error wrapping
`net.ErrClosed`. Drop that reply and continue accepting datagrams. The built-in
`ProxyUDP` already preserves this metadata. The QUIC wire format is unchanged.
