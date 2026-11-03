# Release notes

## Unreleased

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
