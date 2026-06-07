---
title: SDK API
description: Portal SDK endpoints for relay discovery, lease lifecycle, and reverse tunnel streaming.
---

# SDK API

SDK endpoints are the stable lease protocol between a Portal tunnel process and
a relay. Normal JSON endpoints use the shared envelope from
[API Reference](/api-reference). `GET /sdk/connect` is the only SDK endpoint
that switches to a raw stream after a successful HTTP/1.1 response.

## Flow

1. `GET /sdk/domain` checks relay compatibility and optional ENS/payment support.
2. `POST /sdk/register/challenge` creates a Sui challenge for the requested identity.
3. The SDK signs the returned `message`.
4. `POST /sdk/register` exchanges the signature for a lease `access_token`.
5. The SDK keeps the lease alive with `/sdk/renew` and opens reverse streams with `/sdk/connect`.
6. `POST /sdk/unregister` removes the lease.

## Endpoints

| Method | Path | Auth | Body | Data |
|--------|------|------|------|------|
| `GET` | `/sdk/domain` | None | none | `DomainResponse` |
| `POST` | `/sdk/register/challenge` | None | `RegisterChallengeRequest` | `RegisterChallengeResponse` |
| `POST` | `/sdk/register` | Sui signature body | `RegisterRequest` | `RegisterResponse` |
| `POST` | `/sdk/renew` | lease token body | `RenewRequest` | `RenewResponse` |
| `POST` | `/sdk/unregister` | lease token body | `UnregisterRequest` | `{}` |
| `GET` | `/sdk/connect` | lease token header | none | hijacked stream |

## Domain

`GET /sdk/domain` returns:

| Field | Type | Notes |
|-------|------|-------|
| `protocol_version` | `string` | SDK tunnel protocol version |
| `release_version` | `string` | relay software release |
| `ens` | `ENSStatus` | gasless ENS status |
| `x402` | `X402FacilitatorInfo` | relay-local payment facilitator info |

`ENSStatus`:

| Field | Type |
|-------|------|
| `enabled`, `verified` | `boolean` |
| `provider`, `address`, `dnssec_state`, `ds_record`, `message`, `last_error` | `string` |

`X402FacilitatorInfo`:

| Field | Type |
|-------|------|
| `enabled` | `boolean` |
| `url`, `network`, `network_name`, `supported_url` | `string` |

## Register Challenge

`RegisterChallengeRequest`:

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `identity` | `Identity` | yes | `name` and `address` |
| `metadata` | `LeaseMetadata` | no | public lease metadata |
| `ttl` | `number` | no | requested TTL in seconds |
| `udp_enabled` | `boolean` | no | request UDP transport |
| `tcp_enabled` | `boolean` | no | request dedicated TCP port |

Overlay-only fields are also accepted by relay-to-relay clients:
`hop_token`, `route_hostname`, `hostname_hash`, and `ech_config_list`.

`RegisterChallengeResponse`:

| Field | Type |
|-------|------|
| `challenge_id` | `string` |
| `expires_at` | `string` |
| `message` | `string` |

## Register

`RegisterRequest`:

| Field | Type | Required |
|-------|------|----------|
| `challenge_id` | `string` | yes |
| `message` | `string` | yes |
| `signature` | `string` | yes |
| `reported_ip` | `string` | no |

`RegisterResponse`:

| Field | Type | Notes |
|-------|------|-------|
| `identity` | `Identity` | normalized lease identity |
| `expires_at` | `string` | lease expiry |
| `access_token` | `string` | token for renew, unregister, connect, and signer access |
| `sni_port` | `number` | omitted when not needed |
| `udp_addr`, `tcp_addr` | `string` | omitted when transport is disabled |
| `udp_enabled`, `tcp_enabled` | `boolean` | active transport flags |

The response does not include a separate `hostname` field. The public hostname
is derived from the registered identity and relay root domain.

## Renew And Unregister

`RenewRequest`:

| Field | Type | Required |
|-------|------|----------|
| `access_token` | `string` | yes |
| `ttl` | `number` | no |
| `reported_ip` | `string` | no |
| `metadata` | `LeaseMetadata` | no |

`RenewResponse`:

| Field | Type |
|-------|------|
| `expires_at` | `string` |
| `access_token` | `string` |

`UnregisterRequest`:

| Field | Type | Required |
|-------|------|----------|
| `access_token` | `string` | yes |

`/sdk/unregister` returns `{}` on success.

## Reverse Connect

`GET /sdk/connect` opens a reverse tunnel stream.

Requirements:

| Requirement | Value |
|-------------|-------|
| HTTP version | HTTP/1.1 |
| Header | `X-Portal-Access-Token: <lease access_token>` |
| Connection | keep-alive capable connection that supports hijack |

On success, the relay writes `HTTP/1.1 200 OK` and hijacks the TCP connection.
There is no JSON response body. Before the hijack, failures still use the
standard JSON error envelope.

The SDK keeps several ready reverse streams open. When an end user connects to
the lease hostname, the relay claims one ready stream and bridges encrypted
tenant bytes between the browser side and the SDK side.

## Relay Overlay

`/sdk/hop` is reserved for relay-to-relay overlay routing. It accepts
`POST` and `DELETE` with a signed `HopRoute` body and returns `HopRouteResponse`
or `{}`. Normal SDK clients should not call it directly.
