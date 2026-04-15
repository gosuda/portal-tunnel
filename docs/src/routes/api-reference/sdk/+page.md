---
title: SDK API
description: Portal SDK endpoints for tunnel registration and connection.
---

<script>
import Mermaid from '$lib/components/Mermaid.svelte'

const registrationDiagram = `sequenceDiagram
    participant Client as SDK Client
    participant Relay as Portal Relay

    Client->>Relay: POST /sdk/register/challenge
    Note right of Client: Send identity + metadata
    Relay->>Client: challenge_id + siwe_message

    Client->>Client: Sign SIWE message with private key

    Client->>Relay: POST /sdk/register
    Note right of Client: challenge_id + signed message
    Relay->>Client: access_token + lease info
    Note left of Relay: hostname, udp_addr, tcp_addr`

const reverseConnectDiagram = `sequenceDiagram
    participant SDK as SDK Client
    participant Relay as Portal Relay
    participant Browser as End User

    SDK->>Relay: GET /sdk/connect
    Note right of SDK: X-Portal-Access-Token header
    Relay->>SDK: HTTP/1.1 200 OK (hijacked)
    Note over SDK,Relay: Connection upgraded to raw TCP

    Browser->>Relay: TLS ClientHello (SNI: app.relay.example.com)
    Relay->>Relay: Match SNI to lease
    Relay->>SDK: 0x02 marker, then encrypted tenant bytes
    Note over SDK: Tenant TLS terminates locally via keyless signer
    SDK->>Relay: Response traffic
    Relay->>Browser: Forward response
    Note over SDK,Browser: Relay bridges ciphertext only`
</script>

# SDK API

These endpoints are used by the Portal SDK to register tunnels, manage leases, and establish reverse connections to the relay server.

## Registration Flow

<Mermaid code={registrationDiagram} />

## Reverse Connect Flow

<Mermaid code={reverseConnectDiagram} />

---

### `GET /sdk/domain`

Get relay domain and protocol version information. Used by the SDK to verify relay compatibility before registration.

**Auth:** None

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `protocol_version` | `string` | Protocol version (must match SDK version) |
| `release_version` | `string` | Relay software release version |

**Example:**

```bash
curl https://relay.example.com/sdk/domain
```

**Response:**

```json
{
  "ok": true,
  "data": {
    "protocol_version": "5",
    "release_version": "v2.1.5"
  }
}
```

---

### `POST /sdk/register/challenge`

Request a SIWE (Sign-In with Ethereum) challenge message for tunnel registration. This is the first step of the two-phase registration flow.

**Auth:** None

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identity` | `object` | Yes | Identity object (see below) |
| `identity.name` | `string` | Yes | Lease name (used as subdomain) |
| `identity.address` | `string` | Yes | Ethereum address (hex, `0x`-prefixed) |
| `metadata` | `object` | No | Lease metadata |
| `metadata.description` | `string` | No | Human-readable description |
| `metadata.tags` | `string[]` | No | Tags for categorization |
| `metadata.thumbnail` | `string` | No | Base64-encoded thumbnail image |
| `ttl` | `int` | No | Lease TTL in seconds (default: server-configured) |
| `udp_enabled` | `bool` | No | Request UDP (QUIC) transport |
| `tcp_enabled` | `bool` | No | Request dedicated TCP port |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `challenge_id` | `string` | Unique challenge identifier |
| `expires_at` | `string` | ISO 8601 challenge expiration |
| `siwe_message` | `string` | SIWE message to sign |

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `ip_banned` | 403 | Source IP is banned |
| `feature_unavailable` | 503 | UDP or TCP transport not available |
| `udp_disabled` | 403 | UDP transport disabled by admin policy |
| `udp_capacity_exceeded` | 503 | UDP lease capacity reached |
| `tcp_port_disabled` | 403 | TCP port transport disabled by admin policy |
| `tcp_port_capacity_exceeded` | 503 | TCP port lease capacity reached |

**Example:**

```bash
curl -X POST https://relay.example.com/sdk/register/challenge \
  -H "Content-Type: application/json" \
  -d '{
    "identity": {
      "name": "my-app",
      "address": "0x1234567890abcdef1234567890abcdef12345678"
    },
    "metadata": {
      "description": "My web application"
    },
    "ttl": 60
  }'
```

**Response:**

```json
{
  "ok": true,
  "data": {
    "challenge_id": "abc123",
    "expires_at": "2025-01-01T00:05:00Z",
    "siwe_message": "relay.example.com wants you to sign in..."
  }
}
```

---

### `POST /sdk/register`

Complete tunnel registration by submitting the signed SIWE challenge. Returns an access token and lease information including the assigned hostname.

**Auth:** None (authenticated by SIWE signature)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `challenge_id` | `string` | Yes | Challenge ID from `/sdk/register/challenge` |
| `siwe_message` | `string` | Yes | The SIWE message that was signed |
| `siwe_signature` | `string` | Yes | Ethereum personal sign signature (hex) |
| `reported_ip` | `string` | No | Client-reported public IP address |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `identity` | `object` | Normalized identity (name + address) |
| `expires_at` | `string` | ISO 8601 lease expiration |
| `hostname` | `string` | Assigned tunnel hostname (e.g. `my-app.relay.example.com`) |
| `access_token` | `string` | ES256K JWT access token for subsequent API calls |
| `sni_port` | `int` | SNI port for QUIC transport (omitted if UDP not enabled) |
| `udp_addr` | `string` | UDP address for QUIC transport (e.g. `relay.example.com:4443`) |
| `udp_enabled` | `bool` | Whether UDP transport is active |
| `tcp_addr` | `string` | Dedicated TCP address (e.g. `relay.example.com:10001`) |
| `tcp_enabled` | `bool` | Whether TCP port transport is active |

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `unauthorized` | 403 | Invalid SIWE signature |
| `hostname_conflict` | 409 | Hostname already registered |
| `ip_banned` | 403 | Source IP is banned |
| `udp_port_exhausted` | 503 | No UDP ports available |
| `tcp_port_exhausted` | 503 | No TCP ports available |
| `udp_disabled` | 403 | UDP transport disabled by admin policy |
| `udp_capacity_exceeded` | 503 | UDP lease capacity reached |
| `tcp_port_disabled` | 403 | TCP port transport disabled by admin policy |
| `tcp_port_capacity_exceeded` | 503 | TCP port lease capacity reached |
| `feature_unavailable` | 503 | Requested transport not available |

**Example:**

```bash
curl -X POST https://relay.example.com/sdk/register \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_id": "abc123",
    "siwe_message": "relay.example.com wants you to sign in...",
    "siwe_signature": "0xdeadbeef..."
  }'
```

**Response:**

```json
{
  "ok": true,
  "data": {
    "identity": {
      "name": "my-app",
      "address": "0x1234567890abcdef1234567890abcdef12345678"
    },
    "expires_at": "2025-01-01T00:01:00Z",
    "hostname": "my-app.relay.example.com",
    "access_token": "eyJhbGciOiJFUzI1Nksi...",
    "udp_enabled": false,
    "tcp_enabled": false
  }
}
```

---

### `POST /sdk/renew`

Renew an existing lease to extend its TTL. Returns a new access token that should replace the old one.

**Auth:** Access token (in request body)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `access_token` | `string` | Yes | Current JWT access token |
| `ttl` | `int` | No | Requested TTL in seconds |
| `reported_ip` | `string` | No | Client-reported public IP address |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `expires_at` | `string` | ISO 8601 new expiration time |
| `access_token` | `string` | New JWT access token (replaces old one) |

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `unauthorized` | 403 | Invalid or expired access token |
| `lease_not_found` | 404 | No active lease for this identity |
| `ip_banned` | 403 | Source IP is banned |

**Example:**

```bash
curl -X POST https://relay.example.com/sdk/renew \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "eyJhbGciOiJFUzI1Nksi...",
    "ttl": 60
  }'
```

**Response:**

```json
{
  "ok": true,
  "data": {
    "expires_at": "2025-01-01T00:02:00Z",
    "access_token": "eyJhbGciOiJFUzI1Nksi...new"
  }
}
```

---

### `POST /sdk/unregister`

Remove an active lease and release all associated resources (hostname, ports, connections).

**Auth:** Access token (in request body)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `access_token` | `string` | Yes | Current JWT access token |

**Response fields:**

Empty data object on success.

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `unauthorized` | 403 | Invalid or expired access token |
| `lease_not_found` | 404 | No active lease for this identity |

**Example:**

```bash
curl -X POST https://relay.example.com/sdk/unregister \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "eyJhbGciOiJFUzI1Nksi..."
  }'
```

**Response:**

```json
{
  "ok": true,
  "data": {}
}
```

---

### `GET /sdk/connect`

Establish a reverse tunnel connection using HTTP/1.1 connection hijacking. The SDK opens this connection and the relay holds it in a ready queue. When a client connects to the tunnel hostname via TLS SNI, the relay claims a ready connection and bridges traffic bidirectionally.

**Auth:** `X-Portal-Access-Token` header

**Requirements:**
- Must use HTTP/1.1 (not HTTP/2)
- Connection header must be `keep-alive`

**Request headers:**

| Header | Value | Description |
|--------|-------|-------------|
| `X-Portal-Access-Token` | `string` | JWT access token from registration |
| `Connection` | `keep-alive` | Required for hijack |

**Response:**

On success, the server responds with `HTTP/1.1 200 OK` and hijacks the underlying TCP connection. No JSON body is returned — the connection is upgraded to a raw bidirectional TCP stream.

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `unauthorized` | 403 | Invalid or expired access token |
| `lease_not_found` | 404 | No active lease for this identity |
| `lease_rejected` | 403 | Lease not approved for routing |
| `http11_only` | 505 | Must use HTTP/1.1 |
| `hijack_unsupported` | 500 | Server does not support hijacking |
| `hijack_failed` | 500 | Connection hijack failed |
| `ip_banned` | 403 | Source IP is banned |

**Example:**

```bash
curl -X GET https://relay.example.com/sdk/connect \
  -H "X-Portal-Access-Token: eyJhbGciOiJFUzI1Nksi..." \
  -H "Connection: keep-alive" \
  --http1.1
```

> **Note:** In practice, the SDK does not use curl for this endpoint. It opens a raw TLS connection, writes the HTTP/1.1 request manually, reads the 200 response, and then uses the connection as a bidirectional TCP stream for tunneled traffic.
