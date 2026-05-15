---
title: Admin API
description: Portal relay admin endpoints for managing leases, settings, and access control.
---

<script>
import Mermaid from '$lib/components/Mermaid.svelte'

const adminWorkflowDiagram = `sequenceDiagram
    participant Admin
    participant Relay as Portal Relay
    Admin->>Relay: POST /admin/auth/challenge
    Relay->>Admin: SIWE message
    Admin->>Relay: POST /admin/auth/login
    Note right of Admin: wallet signature in body
    Relay->>Admin: Set-Cookie session token
    Admin->>Relay: GET /admin/snapshot
    Relay->>Admin: Full relay state
    Note left of Relay: leases, settings, bans
    alt Manage Leases
        Admin->>Relay: POST /admin/leases/.../ban
        Relay->>Admin: OK
    end
    alt Configure Settings
        Admin->>Relay: POST /admin/settings/approval-mode
        Relay->>Admin: Updated settings
    end
    Admin->>Relay: POST /admin/logout
    Relay->>Admin: Session cleared`
</script>

# Admin API

These endpoints allow relay operators to manage leases, configure settings, and control access. All endpoints (except authentication) require a valid admin session cookie.

## Admin Workflow

<Mermaid code={adminWorkflowDiagram} />

---

## Authentication

### `POST /admin/auth/challenge`

Request a SIWE message for wallet-based admin login.

**Auth:** None

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `address` | `string` | Yes | Ethereum wallet address |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `challenge_id` | `string` | Challenge identifier |
| `siwe_message` | `string` | Message to sign with the wallet |
| `expires_at` | `string` | ISO 8601 challenge expiration |

**Example:**

```bash
curl -X POST https://relay.example.com/admin/auth/challenge \
  -H "Content-Type: application/json" \
  -d '{ "address": "0x1234567890abcdef1234567890abcdef12345678" }'
```

---

### `POST /admin/auth/login`

Complete wallet login with the signed SIWE message. On success, sets a session cookie used for subsequent admin requests.

**Auth:** None

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `challenge_id` | `string` | Yes | Challenge identifier returned by `/admin/auth/challenge` |
| `siwe_message` | `string` | Yes | Exact SIWE message returned by `/admin/auth/challenge` |
| `siwe_signature` | `string` | Yes | Wallet signature for the SIWE message |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `wallet_address` | `string` | Authenticated wallet address |

**Response cookies:**

| Cookie | Value | Attributes |
|--------|-------|------------|
| `portal_admin` | Session token | `Path=/admin; HttpOnly; Secure; SameSite=Strict; MaxAge=86400` |

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `unauthorized` | 401/403 | Signature, challenge, or wallet address is invalid |

**Example:**

```bash
curl -X POST https://relay.example.com/admin/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{ "challenge_id": "...", "siwe_message": "...", "siwe_signature": "0x..." }'
```

**Response:**

```json
{
  "ok": true,
  "data": {
    "wallet_address": "0x1234567890abcdef1234567890abcdef12345678"
  }
}
```

---

### `POST /admin/logout`

End the current admin session and clear the session cookie.

**Auth:** Session Cookie

**Request body:** None

**Response:** Empty data object.

**Example:**

```bash
curl -X POST https://relay.example.com/admin/logout \
  -b cookies.txt
```

---

### `GET /admin/auth/status`

Check the current wallet session. Can be called without a session.

**Auth:** None (returns status regardless)

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `authenticated` | `bool` | `true` if the request has a valid session |
| `wallet_address` | `string` | Authenticated wallet address, when logged in |

**Example:**

```bash
curl https://relay.example.com/admin/auth/status \
  -b cookies.txt
```

**Response:**

```json
{
  "ok": true,
  "data": {
    "authenticated": true,
    "wallet_address": "0x1234567890abcdef1234567890abcdef12345678"
  }
}
```

---

## State

### `GET /admin/snapshot`

Get a full snapshot of the relay's current state including all active leases, approval mode, and transport settings.

**Auth:** Session Cookie

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `approval_mode` | `string` | Current mode: `"auto"` or `"manual"` |
| `landing_page_enabled` | `bool` | Whether the landing page is active |
| `leases` | `AdminLease[]` | All active leases (see below) |
| `udp` | `object` | UDP settings |
| `udp.enabled` | `bool` | Whether UDP transport is enabled |
| `udp.max_leases` | `int` | Maximum concurrent UDP leases (0 = unlimited) |
| `tcp_port` | `object` | TCP port settings |
| `tcp_port.enabled` | `bool` | Whether TCP port transport is enabled |
| `tcp_port.max_leases` | `int` | Maximum concurrent TCP port leases (0 = unlimited) |

**AdminLease fields:**

| Field | Type | Description |
|-------|------|-------------|
| `identity_key` | `string` | Unique identity key |
| `address` | `string` | Ethereum address |
| `name` | `string` | Lease name |
| `hostname` | `string` | Assigned hostname |
| `expires_at` | `string` | ISO 8601 lease expiration |
| `first_seen_at` | `string` | ISO 8601 first registration time |
| `last_seen_at` | `string` | ISO 8601 last activity time |
| `client_ip` | `string` | Client IP address |
| `reported_ip` | `string` | Client-reported public IP |
| `udp_addr` | `string` | UDP transport address |
| `tcp_addr` | `string` | TCP transport address |
| `metadata` | `object` | Lease metadata (description, tags, thumbnail) |
| `ready` | `int` | Number of ready reverse connections |
| `bps` | `int` | Bandwidth limit in bytes per second (0 = unlimited) |

**Example:**

```bash
curl https://relay.example.com/admin/snapshot \
  -b cookies.txt
```

**Response:**

```json
{
  "ok": true,
  "data": {
    "approval_mode": "auto",
    "landing_page_enabled": true,
    "leases": [
      {
        "identity_key": "my-app:0x1234...5678",
        "address": "0x1234...5678",
        "name": "my-app",
        "hostname": "my-app.relay.example.com",
        "expires_at": "2025-01-01T00:01:00Z",
        "first_seen_at": "2025-01-01T00:00:00Z",
        "last_seen_at": "2025-01-01T00:00:30Z",
        "client_ip": "203.0.113.1",
        "ready": 2,
        "bps": 0
      }
    ],
    "udp": {
      "enabled": true,
      "max_leases": 10
    },
    "tcp_port": {
      "enabled": false,
      "max_leases": 0
    }
  }
}
```

---

## Settings

### `POST /admin/settings/landing-page`

Enable or disable the relay landing page.

**Auth:** Session Cookie

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | `bool` | Yes | `true` to enable, `false` to disable |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `bool` | Current landing page state |

**Example:**

```bash
curl -X POST https://relay.example.com/admin/settings/landing-page \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{ "enabled": true }'
```

---

### `POST /admin/settings/udp`

Configure UDP (QUIC) transport settings.

**Auth:** Session Cookie

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | `bool` | Yes | Enable or disable UDP transport |
| `max_leases` | `int` | Yes | Maximum concurrent UDP leases (0 = unlimited) |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `bool` | Current UDP enabled state |
| `max_leases` | `int` | Current max leases value |

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `invalid_request` | 400 | `max_leases` must be non-negative |

**Example:**

```bash
curl -X POST https://relay.example.com/admin/settings/udp \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{ "enabled": true, "max_leases": 10 }'
```

---

### `POST /admin/settings/tcp-port`

Configure dedicated TCP port transport settings.

**Auth:** Session Cookie

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | `bool` | Yes | Enable or disable TCP port transport |
| `max_leases` | `int` | Yes | Maximum concurrent TCP port leases (0 = unlimited) |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `bool` | Current TCP port enabled state |
| `max_leases` | `int` | Current max leases value |

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `invalid_request` | 400 | `max_leases` must be non-negative |

**Example:**

```bash
curl -X POST https://relay.example.com/admin/settings/tcp-port \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{ "enabled": true, "max_leases": 5 }'
```

---

### `POST /admin/settings/approval-mode`

Set the lease approval mode. In `auto` mode, all leases are automatically approved. In `manual` mode, leases must be explicitly approved before they can route traffic.

**Auth:** Session Cookie

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mode` | `string` | Yes | `"auto"` or `"manual"` |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `approval_mode` | `string` | Current approval mode |

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `invalid_mode` | 400 | Mode must be `"auto"` or `"manual"` |

**Example:**

```bash
curl -X POST https://relay.example.com/admin/settings/approval-mode \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{ "mode": "manual" }'
```

**Response:**

```json
{
  "ok": true,
  "data": {
    "approval_mode": "manual"
  }
}
```

---

## Lease Management

Lease management endpoints use base64url-encoded identity components in the URL path:

```
/admin/leases/{name_b64}/{addr_b64}/{action}
```

Where `{name_b64}` is the base64url-encoded lease name and `{addr_b64}` is the base64url-encoded Ethereum address.

All lease management endpoints return an empty data object on success. All changes are persisted to the admin state file.

### `POST|DELETE /admin/leases/{name}/{addr}/ban`

Ban or unban a lease identity. Banned identities cannot register new leases or renew existing ones.

**Auth:** Session Cookie

| Method | Description |
|--------|-------------|
| `POST` | Ban the identity |
| `DELETE` | Remove the ban |

**Example:**

```bash
# Ban an identity
curl -X POST https://relay.example.com/admin/leases/bXktYXBw/MHgxMjM0/ban \
  -b cookies.txt

# Unban an identity
curl -X DELETE https://relay.example.com/admin/leases/bXktYXBw/MHgxMjM0/ban \
  -b cookies.txt
```

---

### `POST|DELETE /admin/leases/{name}/{addr}/bps`

Set or remove a bandwidth limit (bytes per second) for a specific lease identity.

**Auth:** Session Cookie

| Method | Description |
|--------|-------------|
| `POST` | Set bandwidth limit |
| `DELETE` | Remove bandwidth limit |

**Request body (POST only):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `bps` | `int` | Yes | Bandwidth limit in bytes per second (must be > 0) |

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `invalid_request` | 400 | `bps` must be greater than zero |

**Example:**

```bash
# Set 1 MB/s bandwidth limit
curl -X POST https://relay.example.com/admin/leases/bXktYXBw/MHgxMjM0/bps \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{ "bps": 1048576 }'

# Remove bandwidth limit
curl -X DELETE https://relay.example.com/admin/leases/bXktYXBw/MHgxMjM0/bps \
  -b cookies.txt
```

---

### `POST|DELETE /admin/leases/{name}/{addr}/approve`

Approve or revoke approval for a lease identity. Only relevant when approval mode is `manual`.

**Auth:** Session Cookie

| Method | Description |
|--------|-------------|
| `POST` | Approve the identity (also removes any deny) |
| `DELETE` | Revoke approval |

**Example:**

```bash
# Approve an identity
curl -X POST https://relay.example.com/admin/leases/bXktYXBw/MHgxMjM0/approve \
  -b cookies.txt

# Revoke approval
curl -X DELETE https://relay.example.com/admin/leases/bXktYXBw/MHgxMjM0/approve \
  -b cookies.txt
```

---

### `POST|DELETE /admin/leases/{name}/{addr}/deny`

Deny or remove denial for a lease identity. Denied identities are blocked from routing even in `auto` mode.

**Auth:** Session Cookie

| Method | Description |
|--------|-------------|
| `POST` | Deny the identity |
| `DELETE` | Remove the denial |

**Example:**

```bash
# Deny an identity
curl -X POST https://relay.example.com/admin/leases/bXktYXBw/MHgxMjM0/deny \
  -b cookies.txt

# Remove denial
curl -X DELETE https://relay.example.com/admin/leases/bXktYXBw/MHgxMjM0/deny \
  -b cookies.txt
```

---

## IP Management

### `POST|DELETE /admin/ips/{ip}/ban`

Ban or unban an IP address. Banned IPs are rejected at the SDK registration and renewal endpoints.

**Auth:** Session Cookie

| Method | Description |
|--------|-------------|
| `POST` | Ban the IP address |
| `DELETE` | Unban the IP address |

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `invalid_ip` | 400 | Invalid IP address format |

**Example:**

```bash
# Ban an IP
curl -X POST https://relay.example.com/admin/ips/203.0.113.50/ban \
  -b cookies.txt

# Unban an IP
curl -X DELETE https://relay.example.com/admin/ips/203.0.113.50/ban \
  -b cookies.txt
```

**Response:**

```json
{
  "ok": true,
  "data": {}
}
```
