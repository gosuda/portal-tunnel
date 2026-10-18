# Portal Tunnel Add-on for Home Assistant

Exposes Home Assistant (`127.0.0.1:8123`) or any other local LAN application (`target` such as a NAS, Jellyfin, or Immich) over end-to-end TLS through Portal relays without installing a client VPN app.

## Security Guarantees

- **Persistent Identity (`/data/identity.json`)**: Keeps the same cryptographic secp256k1 identity and public hostname across add-on restarts and upgrades.
- **Fail-Closed Authentication**: Refuses to start if `auth` (`credential`, `oidc`, or `siwe`) or `auth_allowed_principals` is empty, preventing accidental unauthenticated exposure.
- **Instant Per-Device Revocation**: Removing a principal from `auth_allowed_principals` immediately revokes both its bearer credential and active browser session cookie.
