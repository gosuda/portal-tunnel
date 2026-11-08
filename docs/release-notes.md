# Release notes

## Unreleased

### Agent: relay status and configuration compatibility

`/agent/status` now reports relay `state` (`ready`, `connecting`, or `failed`)
and optional `failure` instead of the `connecting` boolean. Scripts should use
`state == "connecting"` for that check. The previously unpopulated `explicit`,
`bootstrap`, `banned`, `supports_udp`, and `supports_tcp` fields are removed.
Stopped or retrying tunnels return no historical relay entries. A running
tunnel's failed relays remain removable with **Disconnect** in the dashboard.

HTTP route `methods` now rejects empty or whitespace-only entries, including
entries on free routes. Previously those entries could disappear during
normalization; on a paid route, an emptied list charged every method. Before
upgrading, replace blank entries with the intended methods, or remove `methods`
entirely when no method filter is needed. Free routes must omit `methods`.
One invalid saved route prevents the entire agent configuration from loading,
so correct it in the TOML configuration before restarting the upgraded agent.

Discovery announcement attempts, including network failures, now log at debug
level. An unreachable bootstrap target does not emit a warning every poll.

### Relay: accept tunnels only from your networks

`TUNNEL_SOURCE_CIDRS` lists the networks that may register tunnels. A tunnel from
anywhere else gets `403 source_not_allowed` when it registers or renews, before
the relay spends any pre-auth budget on it, and the SDK stops using that relay.
Visitors are not affected, and the list applies under either approval mode, so a
private relay can stay on `auto`. Empty, the default, accepts every network as
before, and a value that names no network stops the relay at startup. Behind a
reverse proxy the list needs `TRUST_PROXY_HEADERS` and `TRUSTED_PROXY_CIDRS`, or
every tunnel appears to come from the proxy, and the proxy must overwrite
`X-Forwarded-For` rather than append to it, or a client can choose a listed
address. An older
relay ignores the setting, so a downgrade accepts every network again. See
[Accept tunnels only from your networks](/self-hosting#accept-tunnels-only-from-your-networks).

### Local relay: a certificate Safari can trust

A local relay's self-signed certificate is now valid for 825 days instead of ten
years, because Apple platforms refuse a longer one even when it is trusted. On
its next start, a relay replaces a stored certificate that is valid for longer,
such as the ten-year one, or that expires within 30 days, so a browser that
trusted the old certificate must trust the new one. Apple platforms also refuse
the `*.localhost` wildcard, so to open local tunnels in Safari, set `PORTAL_URL`
one label deeper, such as `https://portal.localhost`.

## v2.7.3

### Application auth: a tunnel answers only for hosts it holds

The sign-in gate now answers `421` to a request for a host the tunnel does not hold
now, for every provider. A session on an alias lasts as long as the tunnel keeps
holding that alias: after a restart, or after the tunnel registers again, such as
after a network drop or a laptop sleep, visitors on the alias sign in again. A
sign-in that began before then does not finish. Sessions on the address-bound URL
keep working through all of these. A credential outlives a restart on either host,
so issue it for the address-bound URL. While the tunnel registers again, a request
on a connection that outlives the lease gets `421`, so a client should retry it.

In Go, `RelayStatus.AliasSince` says when the exposure came to hold its alias, and
`Config.PublicHosts` gives the gate its hosts. It replaces `Config.PublicURLs` from
v2.7.2, so an embedder must rename the field and return dated hosts, and it now
applies to every provider. Set it whenever the gate serves an exposure: without it
the gate believes the `Host` of a request.

## v2.7.2 and earlier

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
