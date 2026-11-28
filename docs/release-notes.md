## Breaking URL and cache contract

Only friendly aliases and negotiated Local TLS canonical URLs remain. Old
`<address>.<root>`, `<name>-<address>.<root>`, and `<hash>--<address>.<root>`
canonical URLs, `legacy_canonical_hostname`, and `LegacyURL` are removed with
no redirects. The tunnel protocol remains `10`; discovery remains `9`.
SDK v2.7.3 and v2.7.4 require the removed canonical field even when callers use
only an alias. They pass protocol negotiation but cannot complete registration
with the current response contract. Keeping protocol 10 preserves main's
version negotiation behavior; it does not repair this existing limitation. See
[the compatibility matrix and rollout](maintainer/sdk-compatibility.md).
Unnamed HTTP services require Local TLS. Dedicated raw TCP/UDP addresses use
the relay control hostname.

`--cache` / `--cache-ttl` now target the currently granted friendly alias and
can coexist with canonical Local TLS. An absent alias makes caching unavailable.
Alias reassignment detaches old snapshots and publication credentials before
the new owner is served. Canonical URLs remain ciphertext passthrough even
when offline and never fall back to cached content.

# Release notes

## Unreleased

### SDK and agent: a denied registration reports `refused`

When a relay denies or bans a registration, `RelayStatus.Approval` is now
`refused`, and `/agent/status` reports `approval` `refused` for that relay.
Before, only `state` `failed` and `failure` `terminal` were set, so the
dashboard showed `failed`, not `refused`. The refusal stays terminal: the
listener does not register again. The relay sends no retry delay for a
denial, and each new registration spends the pre-auth budget of the source.
After the relay operator lifts the denial or ban, connect the relay again or
restart the exposure.

### Agent: tunnels with an invalid name or target port are not saved

`POST /agent/tunnels` now refuses a tunnel whose name is longer than 63
characters or whose target port is not a number from 1 to 65535. Before, the
agent saved the tunnel to `config.toml`, and the tunnel failed when it started.
Now the request fails and the file does not change. A host without a port, such
as `abc`, still resolves to `abc:80`.

The check is part of the tunnel validation, so it also covers `udp_addr`,
`config.toml`, and `portal expose`. The check follows the tunnel mode. An HTTP
tunnel, for example one with `inspect` or application auth, reads its target as
an HTTP upstream, so a target URL with a base path or a query still works. A
stream, TCP, or UDP tunnel reads its target as an address, so a target URL with
a path, a query, or a fragment now fails when the file loads. Before, it failed
when the tunnel started. An agent whose `config.toml` holds an invalid tunnel no
longer loads the file. Correct or remove that tunnel.

`sdk.NewHTTPRoutes` also refuses an upstream URL whose port is not a number
from 1 to 65535. Before, the route accepted it, and each proxied request failed.

### Agent: metadata keys in `config.toml` are lower case

The agent now writes the metadata keys as `description`, `owner`,
`thumbnail`, `tags`, and `hide`, as documented. Before, it wrote `Description`,
`Owner`, `Thumbnail`, `Tags`, and `Hide`, and it wrote them for every tunnel,
even when they were empty. A file with the capitalized keys still loads, and
the next save writes them in lower case. The JSON fields and the relay wire
format do not change.

### Relay: a per-source budget for ClientHello inspection

`--inspections-per-source` (`INSPECTIONS_PER_SOURCE`, default `16`) bounds the
public sockets one IPv4 address or IPv6 /64 can hold while the relay waits for
their TLS ClientHello, inside the existing 128-socket budget. Over the budget,
the relay closes the new connection. Behind a TCP proxy every visitor shares
the proxy's address: set `0` there and limit clients at the proxy. An embedder
of `portal.Server` sets `ServerConfig.InspectionsPerSource`; zero keeps the old
behavior.

### Kubernetes: Helm charts for the relay and the tunnel client

`docs/examples/helm/portal-relay` runs the relay and `docs/examples/helm/portal-tunnel` runs
a tunnel client for an in-cluster Service. Release tags publish both to
`oci://ghcr.io/gosuda/charts` with the release version. Example values files
and plain client manifests are in `docs/static/examples/kubernetes`. Set
`env.PUBLIC_IPS` to the relay Service address so DNS points at it. See
[Kubernetes](/kubernetes).

### Relay: `PUBLIC_IPS` sets the addresses published in DNS

`PUBLIC_IPS` (`--public-ips`) lists the relay's public IPv4 and/or IPv6
address, at most one per family. When it is set, the relay publishes exactly
these addresses in A and AAAA records for the apex, the wildcard, and tracked
ENS hostnames, and no longer asks external services for the address of its
outbound connections. Use it behind a load balancer, a NAT gateway, a floating
IP, or a DNAT rule, where that outbound address is not the one clients reach.
A family left out of the list is not published, and existing records of that
family at an external provider stay until you remove them. Empty, the default,
keeps discovery. The relay now logs the addresses it publishes and their
source. See [IPv4 and IPv6](/configuration#ipv4-and-ipv6).

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

### Tunnels: several HTTP clients for one service URL

HTTP tunnels can now opt into replica mode with `portal expose --replica`,
`replica = true` in an agent tunnel, or `sdk.WithReplicas()`. Clients that hold
the same identity then serve one public URL, and the relay spreads new TLS
connections among them. Without the option, registration still replaces every
lease of the identity. Replica mode needs a relay that advertises it, and it
rejects dedicated TCP/UDP ports, relay cache, overlay, email/SAML authentication
and paid Nano routes. Replicas share the identity's policy and bandwidth limit,
so adding a replica does not add bandwidth. See
[HTTP Replicas](/api-reference/sdk#http-replicas).

The relay now issues an alias ownership epoch, and application auth binds alias
sessions and sign-ins to it. After the relay and the tunnel are upgraded,
visitors on an alias sign in again once. Sessions on the address-bound URL are
not affected. A Go program that builds `appauth.PublicHost` itself must pass
`RelayStatus.AliasEpoch` as `Epoch` for the alias.

### Relay: accept tunnels only from your networks

`TUNNEL_SOURCE_CIDRS` lists the networks that may register tunnels. A tunnel from
anywhere else gets `403 source_not_allowed` when it registers or renews, before
the relay spends any pre-auth budget on it, and the SDK stops using that relay.
Visitors are not affected, and the list applies under either approval mode, so a
private relay can stay on `auto`. Empty, the default, accepts every network as
before, and a value that names no network stops the relay at startup. Behind a
reverse proxy the list needs `TRUST_PROXY_HEADERS` and `TRUSTED_PROXY_CIDRS`, or
every tunnel appears to come from the proxy, and the proxy must write
`X-Forwarded-For` and `X-Real-IP` itself, or a client can choose a listed
address. The `starting relay server` log line shows the list as
`tunnel_source_cidrs`. An older relay ignores the setting, so a downgrade
accepts every network again. See
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
