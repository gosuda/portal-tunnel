# Release notes

## Unreleased

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
