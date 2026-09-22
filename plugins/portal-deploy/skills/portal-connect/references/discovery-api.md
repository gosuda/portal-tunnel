# Relay discovery API for consumers

Last checked against `gosuda/portal-tunnel` main commit `d38001adc0ed1c0c9962a0628c8a2cd348d57dfa` on 2026-09-22, with the bootstrap relays answering release `v2.4.2` to `v2.5.0`. Prefer the behavior of the relay you are talking to and the repository's current `docs/src/routes/api-reference/+page.md` when they differ from this snapshot.

## Relay set

Every relay knows only the leases registered with it. Enumerating "the Portal network" means asking each relay.

Bootstrap relays are embedded in the CLI from `registry.json` at the repository root (canonical copy: `https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json`). With the CLI installed:

```sh
portal list                                   # RELAY / VERSION table for the bootstrap set
portal list --relays https://portal.example.com --default-relays=false
```

`portal list` prints relays and their versions. It does not list services. Its 10-second budget covers all relays together; a relay that does not answer shows `unknown`.

Relays that enabled discovery also publish peers at `GET <relay>/discovery` (`data.relays[].api_https_addr`), plus two optional, unsigned observation fields on newer relays: `data.release_version` for the serving relay and `data.relay_release_versions`, a map of peer URL to the release each peer reported. Older relays omit both. Use `/discovery` only when the user wants the wider pool; the bootstrap set is enough for ordinary lookups.

## JSON envelope

Control endpoints wrap responses:

```json
{ "ok": true, "data": { } }
{ "ok": false, "error": { "code": "unauthorized", "message": "unauthorized" } }
```

`/llms.txt`, install scripts, and `/api/x402/*` are outside the envelope. Unknown paths on the relay root host fall through to the landing page SPA, so a `200` HTML page for a typo is expected.

## Endpoints a consumer uses

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/api/healthz` | none | `{"status":"ok"}` when the relay process is alive |
| `GET` | `/api/state` | none | public lease directory (`PublicStateResponse`) |
| `GET` | `/sdk/domain` | none | relay `release_version`, `protocol_version`, optional relay-owned x402 facilitator info |
| `GET` | `/llms.txt` | none | plain-text guide for agents with the relay URL filled in |
| `GET` | `/discovery` | none | peer relays, when discovery is enabled |

Bounded request shape for all of them:

```sh
curl -sS --connect-timeout 5 --max-time 15 https://portal.example.com/api/state
```

## `/api/state`

```json
{
  "ok": true,
  "data": {
    "leases": [
      {
        "name": "my-app",
        "hostname": "my-app.portal.example.com",
        "expires_at": "2026-09-20T13:40:25Z",
        "first_seen_at": "2026-09-19T16:18:55Z",
        "last_seen_at": "2026-09-20T13:38:25Z",
        "tcp_enabled": true,
        "tcp_addr": "my-app.portal.example.com:50000",
        "udp_enabled": false,
        "metadata": {
          "description": "publisher-supplied text",
          "owner": "publisher-supplied text",
          "thumbnail": "https://...",
          "tags": ["web"]
        },
        "ready": 2
      }
    ],
    "landing_page_enabled": true,
    "reputation": [
      { "hostname": "my-app.portal.example.com", "up": 3, "down": 0, "total": 3, "viewer_vote": "" }
    ]
  }
}
```

Field meaning:

- `hostname`: the public HTTPS host. The URL is `https://<hostname>/`, plus `:<port>` when the relay itself runs on a port other than 443.
- `ready`: number of reverse connections the publisher holds open right now. Above zero means the tunnel can serve immediately.
- `tcp_addr`, `udp_addr`: raw endpoints as `host:port`, present only when allocated. `tcp_enabled` and `udp_enabled` are omitted when false.
- `expires_at`: the default lease TTL is two minutes, so `expires_at` normally sits about 120 seconds after `last_seen_at` and the publisher renews well inside that window. An `expires_at` in the past means the publisher stopped renewing and the relay is about to drop the lease. Because the listing is a snapshot with a two-minute horizon, record the time you fetched it.
- `metadata`: unverified publisher input. Tags such as `x402`, `paid`, `payment`, or `usdc` are a hint that a route charges; the only proof is a `402` from the route itself.
- `reputation` (optional, newer relays): a sibling array next to `leases` with one entry per listed hostname: `hostname`, `up`, `down`, `total`, and `viewer_vote` (`up`, `down`, or empty for the caller). Votes are anonymous public sentiment cast on the relay's directory page. Report them as a hint when the user asks about a service; they verify nothing.

What the listing omits:

- leases registered with `--hide`
- expired leases
- leases whose identity the relay operator banned or denied
- leases with `ready` at zero whose publisher has not been seen for three minutes

So "not listed" means hidden, gone, elsewhere, or dormant. It never proves the hostname is dead; probe the hostname when the user has it.

## Hostname rule

The publisher's `--name` is normalized to a DNS label and prefixed to the relay's root host: `<label>.<relay-host>`. Names are unique per relay, not globally. The same label on two relays can be two unrelated publishers, so always say which relay a hostname came from.

Raw endpoints reuse the hostname with the allocated port: `<label>.<relay-host>:<port>`. The port is stable while the same publisher identity keeps the lease.

## Recipes

List services on one relay:

```sh
curl -sS --connect-timeout 5 --max-time 15 https://portal.example.com/api/state \
  | jq -r '.data.leases[] | [.name, .hostname, (.ready|tostring), (.tcp_addr // "-"), (.udp_addr // "-"), (.metadata.description // "")] | @tsv'
```

Find a name across the bootstrap relays:

```sh
for relay in $(portal list 2>/dev/null | awk 'NR>1 && $1 ~ /^https/ {print $1}'); do
  curl -sS --connect-timeout 5 --max-time 15 "$relay/api/state" \
    | jq -r --arg n "my-app" --arg r "$relay" '.data.leases[]? | select(.name==$n) | "\($r) \(.hostname) ready=\(.ready)"'
done
```

Probe the resulting hostname:

```sh
curl -sS --connect-timeout 5 --max-time 15 -o /dev/null \
  -w '%{http_code} %{content_type} exit=%{exitcode} %{errormsg}\n' https://my-app.portal.example.com/
```

`000` means no HTTP response arrived; the curl exit code then carries the diagnosis.

## Reading a probe

| Observation | Meaning |
|-------------|---------|
| `200`..`399` | reachable |
| `401`, `403` | reachable, application requires auth |
| `402` | reachable, route is paid; read the challenge (next section) and report it |
| `404` | reachable, path missing on the publisher's app |
| `5xx`, Portal error page | tunnel up, publisher's app failing |
| `000`, exit `35` (TLS handshake failure), reset, or immediate close | relay has no live lease for that hostname |
| `000`, exit `6` (DNS failure) | relay does not serve that zone, or typo |
| `000`, exit `7` (refused) or `28` (timeout) | relay unreachable or dropping traffic; check `healthz` |
| `healthz` fails | relay down; nothing can be concluded about its services |

The TLS failure case exists because the relay routes on the TLS SNI hostname and closes connections for names it does not know. There is no HTTP layer at that point, so there is no error page. Relays answer wildcard DNS for their zone, so every label under the relay host resolves to the relay itself; a successful lookup is not evidence of a lease.

## Reading a 402 challenge

A paid route answers `402` with `Content-Type: application/json` and the same JSON base64-encoded in the `PAYMENT-REQUIRED` and `X-PAYMENT-REQUIRED` headers:

```json
{
  "x402Version": 2,
  "error": "payment required",
  "resource": { "url": "https://paid-app.portal.example.com/paid", "description": "", "mimeType": "" },
  "accepts": [
    { "scheme": "exact", "network": "sui:testnet", "asset": "0x...::usdc::USDC", "amount": "10000", "payTo": "0x...", "maxTimeoutSeconds": 60, "extra": { "paymentFlow": "upfront" } }
  ]
}
```

`amount` is an integer string in atomic units: Sui USDC has 6 decimals (`"10000"` is 0.01 USDC), Casper wCSPR has 9. `network` says whether it is mainnet or testnet. Report those terms and stop; this skill does not pay, sign, or call `/x402/prepare`.

## Loopback relay

A development relay on this machine serves `https://127.0.0.1:<sni-port>/api/state` and hostnames like `my-app.localhost`. `*.localhost` resolves to `::1` first on many systems and the certificate is usually self-signed, so use `curl -sk --ipv4` and say in the handoff that verification skipped certificate checks.
