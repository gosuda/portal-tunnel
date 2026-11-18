# SDK and relay compatibility

A relay update preserves its supported SDK contracts, including required fields,
omitted-field defaults, endpoint selection, authentication, renewal, reverse
connections, reconnect after relay restart, and unregister. A release number is
informational; it is neither a tunnel protocol nor a feature flag. Additive
updates preserve these contracts. A breaking change must identify affected
SDK releases and document their migration.

## Current compatibility matrix

The relay retains tunnel protocol `10`, matching main. Protocol-list negotiation
is additive and keeps SDKs that require the existing version from being refused
solely because of a new protocol label.

| SDK source or release | Tunnel protocol | Current relay behavior |
| --- | --- | --- |
| `v2.7.3` | `10` | Passes version negotiation; registration requires the removed nonempty `canonical_hostname` and remains incompatible |
| `v2.7.4` | `10` | Same as `v2.7.3` |
| Current SDK source | `10` | Named friendly aliases; identity-bound canonical URLs require explicit `local-tls-v1`; replicas and cache require their own advertised capabilities |

The legacy canonical removal in #790 changed registration-response behavior
while retaining protocol 10. This existing limitation remains. Keeping the
protocol label does not establish lifecycle compatibility for every SDK that
reports 10. Released v2.7.3 and v2.7.4 require a nonempty canonical field even
when their caller intends to use only an alias.

The source manifest carries release label `v2.8.0`. Pin the actual SDK module
or binary used in a deployment; a release label alone does not establish its
registration behavior. Current-source lifecycle behavior is covered by the
existing registration, renewal, restart, TLS, cache, and replica tests and E2Es.
Adding a supported release requires real lifecycle coverage against that pinned
module. The matrix does not promise support for every historical `v2` SDK.

## Negotiation and additive changes

`GET /sdk/domain` reports:

- `protocol_version`: the default tunnel contract, currently `10`. Shipped
  protocol-10 SDKs use exact equality and pass this version check.
- `supported_protocol_versions`: an optional, authoritative list for newer
  SDKs. The current relay advertises `["10"]`. If absent or null, newer SDKs use
  exact equality with `protocol_version`. A present empty list supports nothing.
  An explicit list excludes protocols not in it even if they equal the default.
- `namespaces`, `replicas`, `cache`, and `tenant_certificate_issuance`: separate,
  narrowly scoped feature advertisements. Protocol compatibility alone does
  not enable any of them.

New SDKs select their implemented protocol by membership, then include it as
`protocol_version` in the registration challenge request. The relay validates
that selection before allocating a challenge. Unsupported selections return
HTTP 426, `protocol_incompatible`, and an upgrade/compatible-relay instruction.
Omitting the selection uses the advertised default protocol 10. Adding another
list entry requires an implemented and tested wire contract, not just a changed
report.

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

## Deployment compatibility

Protocol 10 and discovery 9 remain unchanged from main. A relay upgrade keeps
working protocol-10 deployments eligible at version negotiation. Feature
capabilities and registration-response requirements still determine which
SDK and relay combinations can complete their lifecycle.

For SDK v2.7.3/v2.7.4 deployments, retain a relay that provides their required
canonical response and routing behavior until the clients can be upgraded.
Named HTTP services can use a granted friendly alias with the current SDK;
unnamed HTTP services need explicit Local TLS and usable certificate material.
Move traffic after replacement clients have registered and are ready, then
drain old connections before retiring the previous relay.

Future compatibility claims must cover required fields, omitted-field defaults,
authentication, endpoint selection, renewal, reconnect, and unregister. Keep
protocol-list negotiation distinct from feature capabilities. Any deliberate
break must identify affected SDK releases and provide an explicit migration.

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
