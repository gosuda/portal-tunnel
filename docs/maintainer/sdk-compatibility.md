# SDK and relay compatibility

A relay update preserves its supported SDK contracts, including required fields,
omitted-field defaults, endpoint selection, authentication, renewal, reverse
connections, reconnect after relay restart, and unregister. A release number is
informational; it is neither a tunnel protocol nor a feature flag. Additive
updates preserve these contracts. A breaking change requires the explicit
exception and rollout process below.

## Current compatibility matrix

| SDK source or release | Tunnel protocol | Current relay behavior |
| --- | --- | --- |
| `v2.7.3` | `10` | Rejected during protocol negotiation; requires a compatible protocol-10 relay or an SDK upgrade |
| `v2.7.4` | `10` | Same as `v2.7.3` |
| Current SDK source | `11` | Named friendly aliases; identity-bound canonical URLs require explicit `local-tls-v1`; replicas and cache require their own advertised capabilities |

Protocol 10 was withdrawn after the legacy canonical URL removal in #790.
Those released SDKs require a nonempty legacy `canonical_hostname`, including
when the caller wants only a friendly alias. The current relay cannot honor
that contract. Advertising protocol 10 would allow negotiation to succeed and
then fail during registration, so the relay reports protocol 11 instead.

The source manifest carries release label `v2.8.0`, but this matrix does not yet
pin a released protocol-11 SDK. A release label alone does not establish that a
published artifact implements this contract. Publish and pin the replacement
SDK before rolling the new relay out to clients that use released modules.
Do not assume an existing tag or `@latest` contains the current protocol change.

`TestReleasedSDKRejectsRemovedProtocol` builds a small program against each
listed released module in a temporary module with `GOWORK=off` and no local
`replace`. For named and unnamed exposures, it observes the released SDK's
public relay status, checks the terminal protocol-mismatch error, and verifies
that the relay has no public lease. Those releases' `WaitReady` does not return
terminal errors, so the test reads their `Relays` and `Updates` APIs. Current
SDK lifecycle, renewal, restart, TLS, cache, and replica behavior remains covered
by the existing owner tests and E2Es.

Adding a supported release means pinning its actual module and lifecycle
coverage. The matrix is an explicit list, not a promise to support every `v2`
release or every SDK claiming a protocol identifier.

## Negotiation and additive changes

`GET /sdk/domain` reports:

- `protocol_version`: the default tunnel contract, currently `11`. Shipped
  protocol-10 SDKs use exact equality and reject this relay before registration.
- `supported_protocol_versions`: an optional, authoritative list for newer
  SDKs. The current relay advertises `["11"]`. If absent or null, newer SDKs use
  exact equality with `protocol_version`. A present empty list supports nothing.
  An explicit list excludes protocols not in it even if they equal the default.
- `namespaces`, `replicas`, `cache`, and `tenant_certificate_issuance`: separate,
  narrowly scoped feature advertisements. Protocol compatibility alone does
  not enable any of them.

New SDKs select their implemented protocol by membership, then include it as
`protocol_version` in the registration challenge request. The relay validates
that selection before allocating a challenge. Unsupported selections return
HTTP 426, `protocol_incompatible`, and an upgrade/compatible-relay instruction.
Omitting the selection uses the advertised default contract; it does not select
the withdrawn protocol-10 behavior. Adding another list entry requires an
implemented and tested wire contract, not just a changed report.

New optional fields must preserve the current meanings when omitted:

- No namespace means Keyless registration using a granted friendly alias.
  `canonical_hostname` is empty. An unnamed HTTP exposure therefore needs Local
  TLS to obtain a usable public hostname. Never infer Local TLS from a protocol,
  SDK release, discovery result, or missing field.
- `local-tls-v1` requires explicit namespace support and confirmation. Its
  `canonical_hostname` is identity bound. The removed
  `legacy_canonical_hostname` field is not used or fabricated. Automatic TLS with
  `requireLocal=false` permits an available friendly alias while issuance is
  pending on a namespace-capable relay; it never permits a namespace downgrade.
- Missing `replicas` means exclusive registration. Missing `cache` means no
  advertised static-cache support. Explicit requests must be confirmed or
  rejected; omission never grants cache consent or replica membership.
- Missing tenant issuance reporting retains the older-relay meaning; it does
  not grant issuance. Manual Local TLS and automatic issuance remain distinct.
  Unsupported certificate requests retain their explicit API errors.
- Access tokens, reverse capability bounds, TTL defaults, renewal responses,
  and unregister semantics remain part of the protocol contract.

Keep one registration/lease implementation. Add version-specific handling only
when a supported wire contract requires it. Additive capabilities do not require
a tunnel protocol bump. Incompatible semantics do.

## Canonical removal exception and rollout

The current exception is the protocol-10 withdrawal for #790/#772. The current
relay retains friendly aliases and the Local TLS canonical origin, and removes
legacy one-label canonical routes. Keeping an alias route cannot preserve old
SDK validation, and a supported-version list cannot change shipped SDK code.

Before deployment:

1. Keep protocol-10 relays available for clients that still use `v2.7.3` or
   `v2.7.4`. Do not redirect those clients to a protocol-11 relay.
2. Publish and pin replacement SDK and relay artifacts that both implement
   protocol 11. Current-source SDKs also reject protocol-10 relays, so roll the
   paired components out together on the replacement infrastructure.
3. Move named HTTP clients to their granted friendly alias or explicit Local
   TLS hostname. Give unnamed HTTP clients a service name or configure Local
   TLS with the required certificate material or issuance approval.
4. Move traffic after the replacement client has registered and is ready. Keep
   the old relay until its remaining clients and active connections are drained.

Do not restore deleted canonical routes, fabricate canonical response values
for a different origin, or relax tenant certificate isolation to make an old
SDK pass validation. Future removals must update this matrix, the release
protocol, migration instructions, and released-SDK coverage together. Ordinary
future updates default to compatibility with the supported matrix.

## Independent trust boundaries

Discovery's wire version and signed relay descriptors remain independent.
Being listed in `/discovery` or a service directory establishes no SDK
compatibility. SDK negotiation uses `/sdk/domain`; it never changes descriptor
signatures, discovery routing, or discovery version acceptance.

The Local TLS canonical origin uses the exact per-service certificate and
tunnel-owned private key. Protocol negotiation cannot enable relay signing,
relay snapshots, retained responses, or fallback on that origin. Static cache
publication requires explicit consent and serves only the separately granted
friendly alias with its existing ownership checks. Advertising compatibility
cannot broaden that consent or change its hostname.
