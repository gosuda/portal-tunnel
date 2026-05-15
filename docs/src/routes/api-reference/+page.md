---
title: API Reference
description: Complete API reference for Portal relay server endpoints.
---

<script>
import Mermaid from '$lib/components/Mermaid.svelte'
</script>

# API Reference

This page provides a complete reference for the Portal relay server HTTP API. Control-plane endpoints are served over the relay API HTTPS listener; tenant TLS is handled separately by the SDK using the relay's keyless signing endpoint.

## Response Envelope

Every API response uses a consistent JSON envelope:

```json
{
  "ok": true,
  "data": { ... },
  "error": null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `ok` | `boolean` | `true` if the request succeeded |
| `data` | `T` | Response payload (omitted on error) |
| `error` | `object \| null` | Error details (omitted on success) |

Error responses include a structured error object:

```json
{
  "ok": false,
  "error": {
    "code": "unauthorized",
    "message": "unauthorized"
  }
}
```

## Authentication

Portal uses two separate authentication mechanisms depending on the caller.

### SDK Authentication (SIWE Challenge/Response)

SDK clients authenticate using Sign-In with Ethereum (SIWE):

1. POST a challenge request to `/sdk/register/challenge` with your identity
2. Sign the returned SIWE message with your Ethereum private key
3. POST the signed message to `/sdk/register` to receive a JWT access token
4. Include the access token in subsequent requests via the `X-Portal-Access-Token` header or in the JSON request body

### Admin Authentication (Wallet Session)

Admin clients authenticate with a wallet signature:

1. POST to `/admin/auth/challenge` with `{ "address": "<wallet-address>" }`
2. Sign the returned SIWE message with the wallet
3. POST the signed message to `/admin/auth/login`
4. The server sets a `portal_admin` session cookie (HttpOnly, Secure, SameSite=Strict)
5. Include the cookie in subsequent admin requests
6. Sessions expire after 24 hours

The local agent has its own loopback wallet auth endpoints under
`/v1/agent/auth/*`. Agent wallet sessions can read `/v1/agent/status`; mutating
agent actions require the bearer token stored in the agent state directory. See
[Portal Agent](/portal-agent) for the local control API.

## Endpoint Summary

### SDK Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `GET` | [`/sdk/domain`](/api-reference/sdk#get-sdkdomain) | Get relay domain and version info | None |
| `POST` | [`/sdk/register/challenge`](/api-reference/sdk#post-sdkregisterchallenge) | Request a SIWE challenge for registration | None |
| `POST` | [`/sdk/register`](/api-reference/sdk#post-sdkregister) | Complete registration with signed challenge | None |
| `POST` | [`/sdk/renew`](/api-reference/sdk#post-sdkrenew) | Renew an existing lease TTL | Access Token |
| `POST` | [`/sdk/unregister`](/api-reference/sdk#post-sdkunregister) | Remove an active lease | Access Token |
| `GET` | [`/sdk/connect`](/api-reference/sdk#get-sdkconnect) | Establish reverse tunnel connection | Access Token |

### Admin Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `POST` | [`/admin/auth/challenge`](/api-reference/admin#post-adminauthchallenge) | Request wallet login challenge | None |
| `POST` | [`/admin/auth/login`](/api-reference/admin#post-adminauthlogin) | Complete wallet login | None |
| `POST` | [`/admin/logout`](/api-reference/admin#post-adminlogout) | End admin session | Session Cookie |
| `GET` | [`/admin/auth/status`](/api-reference/admin#get-adminauthstatus) | Check authentication status | None |
| `GET` | [`/admin/snapshot`](/api-reference/admin#get-adminsnapshot) | Get full relay state snapshot | Session Cookie |
| `POST` | [`/admin/settings/landing-page`](/api-reference/admin#post-adminsettingslanding-page) | Toggle landing page | Session Cookie |
| `POST` | [`/admin/settings/udp`](/api-reference/admin#post-adminsettingsudp) | Configure UDP settings | Session Cookie |
| `POST` | [`/admin/settings/tcp-port`](/api-reference/admin#post-adminsettingstcp-port) | Configure TCP port settings | Session Cookie |
| `POST` | [`/admin/settings/approval-mode`](/api-reference/admin#post-adminsettingsapproval-mode) | Set approval mode | Session Cookie |
| `POST` | [`/admin/leases/{name}/{addr}/ban`](/api-reference/admin#lease-management) | Ban a lease identity | Session Cookie |
| `DELETE` | [`/admin/leases/{name}/{addr}/ban`](/api-reference/admin#lease-management) | Unban a lease identity | Session Cookie |
| `POST` | [`/admin/leases/{name}/{addr}/bps`](/api-reference/admin#lease-management) | Set bandwidth limit for a lease | Session Cookie |
| `DELETE` | [`/admin/leases/{name}/{addr}/bps`](/api-reference/admin#lease-management) | Remove bandwidth limit | Session Cookie |
| `POST` | [`/admin/leases/{name}/{addr}/approve`](/api-reference/admin#lease-management) | Approve a lease | Session Cookie |
| `DELETE` | [`/admin/leases/{name}/{addr}/approve`](/api-reference/admin#lease-management) | Revoke lease approval | Session Cookie |
| `POST` | [`/admin/leases/{name}/{addr}/deny`](/api-reference/admin#lease-management) | Deny a lease | Session Cookie |
| `DELETE` | [`/admin/leases/{name}/{addr}/deny`](/api-reference/admin#lease-management) | Remove lease denial | Session Cookie |
| `POST` | [`/admin/ips/{ip}/ban`](/api-reference/admin#ip-management) | Ban an IP address | Session Cookie |
| `DELETE` | [`/admin/ips/{ip}/ban`](/api-reference/admin#ip-management) | Unban an IP address | Session Cookie |

### System Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `GET` | `/healthz` | Health check | None |
| `GET` | `/discovery` | Relay discovery | None |
| `POST` | `/discovery/announce` | Relay discovery self-announce | Signed Descriptor |
| `POST` | `/v1/sign` | Keyless TLS signing | Access Token |
| `GET` | `/thumbnail/{hostname}` | Cached thumbnail screenshot | None |
| `GET` | `/tunnel/status` | Tunnel connection status | Access Token |

## System Endpoints

These endpoints are small enough to document inline.

### `GET /healthz`

Returns relay health status.

**Response:**

```json
{
  "ok": true,
  "data": {
    "status": "ok"
  }
}
```

### `GET /discovery`

Returns signed relay discovery descriptors for this relay and any known peer relays. Only available when discovery is enabled in the server configuration.

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `protocol_version` | `string` | Protocol version identifier |
| `generated_at` | `string` | ISO 8601 timestamp |
| `relays` | `RelayDescriptor[]` | Signed descriptors for this relay and known peer relays |

`RelayDescriptor` contains the signed relay contract and relay-reported telemetry:

| Field | Type | Description |
|-------|------|-------------|
| `address` | `string` | Relay signing address used to verify `signature` |
| `version` | `string` | Discovery protocol version used by this signed descriptor |
| `issued_at` | `string` | Descriptor issue time |
| `expires_at` | `string` | Descriptor expiry time |
| `api_https_addr` | `string` | Public HTTPS API base URL |
| `wireguard_public_key` | `string` | WireGuard overlay public key, present when overlay is enabled |
| `wireguard_port` | `number` | Public WireGuard UDP port on the `api_https_addr` host, present when overlay is enabled |
| `supports_overlay` | `boolean` | Relay can participate in WireGuard multi-hop overlay routing |
| `supports_udp` | `boolean` | Relay can allocate public UDP leases |
| `supports_tcp` | `boolean` | Relay can allocate raw TCP port leases |
| `active_connections` | `number` | Current proxied connection count reported by the relay |
| `tcp_bps` | `number` | Recent proxied TCP throughput in bytes per second |
| `signature` | `string` | Signature over the descriptor fields above |

Relay telemetry is sampled when the descriptor is issued; use `issued_at` to judge freshness.

Overlay peer support is advertised by `supports_overlay`. When it is true, `wireguard_public_key` and `wireguard_port` are present. The WireGuard endpoint host is the `api_https_addr` host, and the overlay IPv4 is derived from the WireGuard public key. Relay-local observations such as recent overlay reachability are not part of the signed descriptor.

**Example:**

```bash
curl https://relay.example.com/discovery
```

### `POST /discovery/announce`

Submits this relay's signed descriptor to a bootstrap relay so registry-external relays can enter the discovery mesh. Relays self-announce periodically when discovery is enabled.

**Auth:** Signed relay descriptor

**Request fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `protocol_version` | `string` | No | Discovery protocol version |
| `descriptor` | `RelayDescriptor` | Yes | Signed relay descriptor |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `protocol_version` | `string` | Discovery protocol version |
| `accepted` | `boolean` | Whether the descriptor was accepted |

### `POST /v1/sign`

Keyless TLS signing endpoint. Used by the SDK-side tenant TLS server during the
default stream handshake. Requests must include a valid lease access token in
the `X-Portal-Access-Token` header.

Only available when the API server is configured with a TLS private key.

Returns `404 Not Found` if signing is not configured.

### `GET /thumbnail/{hostname}`

Returns a cached thumbnail screenshot for a registered tunnel hostname.

**Response headers:**

| Header | Value |
|--------|-------|
| `Content-Type` | Image content type (e.g. `image/png`) |
| `Cache-Control` | `public, max-age=300` |

Returns `404 Not Found` if the hostname is not registered or no thumbnail is available.

**Example:**

```bash
curl https://relay.example.com/thumbnail/myapp.relay.example.com
```

## Error Codes

All error codes that may appear in the `error.code` field:

| Code | Description |
|------|-------------|
| `feature_unavailable` | Requested feature is not available |
| `hijack_failed` | HTTP connection hijack failed |
| `hijack_unsupported` | HTTP connection hijack not supported |
| `hostname_conflict` | Hostname already in use by another lease |
| `http11_only` | Endpoint requires HTTP/1.1 |
| `invalid_address` | Invalid Ethereum address |
| `invalid_ip` | Invalid IP address format |
| `invalid_json` | Malformed JSON request body |
| `invalid_mode` | Invalid approval mode value |
| `invalid_request` | General request validation failure |
| `internal` | Internal server error |
| `ip_banned` | Source IP is banned |
| `lease_not_found` | No lease found for the given identity |
| `lease_rejected` | Lease is not approved for routing |
| `method_not_allowed` | HTTP method not allowed for this endpoint |
| `unauthorized` | Authentication required or token invalid |
| `udp_port_exhausted` | No UDP ports available |
| `udp_disabled` | UDP transport is disabled |
| `udp_capacity_exceeded` | UDP lease capacity reached |
| `tcp_port_exhausted` | No TCP ports available |
| `tcp_port_disabled` | TCP port transport is disabled |
| `tcp_port_capacity_exceeded` | TCP port lease capacity reached |
| `transport_mismatch` | Transport type mismatch |
