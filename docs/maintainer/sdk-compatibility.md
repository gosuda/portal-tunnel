# SDK and relay compatibility

A relay update preserves the supported SDK contracts below, including required
fields, omitted-field defaults, endpoint selection, authentication, renewal,
reverse connections, reconnect after relay restart, and unregister. A release
number is informational; it is neither a tunnel protocol nor a feature flag.

## Supported baseline

The current relay supports these released Go SDK modules:

| SDK module release | Tunnel protocol | HTTP endpoints and lifecycle | Other existing features | Local TLS / replicas |
| --- | --- | --- | --- | --- |
| `v2.7.3` | `10` | Named friendly alias and legacy canonical; unnamed legacy canonical; renew, reconnect, close | Raw TCP, UDP, overlay, and explicitly opted-in legacy canonical static cache, subject to relay policy and the release's option restrictions | Not implemented by this release |
| `v2.7.4` | `10` | Same as `v2.7.3` | Same as `v2.7.3` | Not implemented by this release |
| Current SDK source | `10` | Same baseline | Existing options retain their restrictions | Explicit `local-tls-v1` namespace or replica capability required |

This is an explicit release list, not a promise to support every historical
`v2` SDK or every SDK claiming protocol `10`. Older releases are outside the
tested support baseline. Adding a supported release means pinning it in
`e2e/released_sdk_test.go`; withdrawing one requires a documented compatibility
exception and migration instructions before release. Ordinary additive relay
updates must continue accepting the listed SDKs.

`TestReleasedSDKCompatibility` builds a small program against each actual
released module in a temporary module with `GOWORK=off` and no local `replace`.
The program uses the released SDK's real negotiation, signing, response
validation, TLS, reverse transport, normal renewal timers, reconnection, and
close implementation. It exercises named and unnamed exposures against the
current relay, reaches canonical and granted alias endpoints, observes a renewed
lease without opting into Local TLS, restarts the relay, reaches the service
again, and closes the exposure. The other feature combinations retain their
existing owner tests and E2Es; the pinned lifecycle test is HTTP coverage.

## Negotiation and additive changes

`GET /sdk/domain` reports:

- `protocol_version`: the existing default tunnel contract. Keep it `10` while
  supporting the released SDKs above: they require exact equality before they
  even attempt registration.
- `supported_protocol_versions`: an optional, authoritative list for newer
  SDKs. The current relay advertises `["10"]`; this adds negotiation, not a new
  runtime implementation. If absent or null, newer SDKs use exact equality with
  `protocol_version`. A present empty list supports nothing. An explicit list
  excludes protocols not in the list even if they equal `protocol_version`.
- `namespaces`, `replicas`, `cache`, and `tenant_certificate_issuance`: separate,
  narrowly scoped feature advertisements. Protocol compatibility alone does
  not enable any of them.

New SDKs select their implemented protocol by membership, then include it as
`protocol_version` in the registration challenge request. The relay validates
the selection before allocating a challenge; unsupported selections return
HTTP 426, `protocol_incompatible`, and an upgrade/compatible-relay instruction.
Omitting the selection retains the existing default contract for shipped SDKs.
Adding another list entry requires an actual implemented and tested wire
contract; changing the report alone does not provide compatibility.

New optional fields must preserve old meanings when omitted. In particular:

- No namespace means the existing Keyless/legacy canonical registration,
  including a nonempty `canonical_hostname`. Never infer Local TLS from a
  protocol, SDK release, discovery result, or missing field.
- `local-tls-v1` requires explicit namespace support and confirmation. Its
  `canonical_hostname` stays identity bound, and the current response retains
  `legacy_canonical_hostname`, which namespace-aware SDKs use to validate the
  alias/root. Missing namespace support produces an incompatibility error;
  requesting Local TLS never silently changes to Keyless. Automatic TLS with
  `requireLocal=false` permits the legacy endpoint while issuance is pending
  on a namespace-capable relay; it does not permit a namespace downgrade.
- Missing `replicas` means exclusive registration, and missing `cache` means no
  advertised static-cache support. Explicit requests must be confirmed or
  rejected; omission never grants cache consent or replica membership.
- Missing tenant issuance reporting retains its existing older-relay meaning;
  it does not grant issuance. Manual Local TLS and automatic issuance remain
  distinct. Unsupported certificate requests retain their explicit API errors.
- Existing access tokens, reverse capability bounds, TTL defaults, renewal
  responses, and unregister semantics remain part of the protocol contract.

Keep one registration/lease implementation. Only add version-specific handling
when a supported wire contract actually requires it. Additive capabilities do
not require a tunnel protocol bump. Incompatible semantics do.

## Canonical URL removal and compatibility exceptions

There is no active exception to the baseline above. The legacy canonical
response fields and routes currently remain in the relay.

The proposed canonical removal in #790/#772 conflicts with this baseline:
`v2.7.3` and `v2.7.4` reject a missing `canonical_hostname` even when the caller
only wants a friendly alias. Namespace-aware SDKs additionally validate against
`legacy_canonical_hostname`. Keeping `protocol_version=10` while deleting those
guarantees breaks supported clients; adding a supported-version list cannot
teach shipped clients different validation rules.

The removal must therefore be released as an explicit compatibility exception
if its two-hostname contract is retained: withdraw the affected protocol-10
contract from the new relay, use a new tunnel protocol identifier, and publish
the replacement SDK version and upgrade instructions before deployment. New
SDKs receive an actionable negotiation error; shipped SDKs fail their existing
exact-version check, whose wording cannot be changed on the relay. Operators
must keep an older compatible relay available until affected clients upgrade,
or upgrade those clients before moving them to the new relay. Do not claim
alias-only old clients work merely because an alias route still exists.

This policy does not authorize restoring deleted canonical routes, fabricating
canonical response values pointing at a different origin, or relaxing tenant
certificate isolation to make an old client pass validation. A removal PR must
update this matrix, its release protocol, migration guide, and corresponding
released-SDK coverage together. Until that exception ships, preserve the
current supported contract. Ordinary future updates default to compatibility.

## Independent trust boundaries

Discovery's wire version and signed relay descriptors remain independent. Being
listed in `/discovery` or a service directory establishes no SDK compatibility.
SDK negotiation uses `/sdk/domain`; it never changes descriptor signatures,
discovery routing, or discovery version acceptance.

The Local TLS canonical origin always uses the exact per-service certificate
and tunnel-owned private key. Protocol negotiation cannot enable relay signing,
relay snapshots, retained responses, or fallback on that origin. Static cache
publication still requires explicit consent and the existing ownership checks;
advertising compatibility cannot broaden that consent or change its hostname.
