# Raw TCP and UDP endpoints

Last checked against `gosuda/portal-tunnel` main commit `d38001adc0ed1c0c9962a0628c8a2cd348d57dfa` on 2026-09-22. This mirrors `docs/src/routes/tcp-udp-tunneling/+page.md` and `docs/src/routes/game-server-hosting/+page.md`; prefer those pages when they differ.

## Where the address comes from

A publisher who ran `portal expose <target> --tcp` or `--udp` received an allocated relay port. The address appears in two places:

- the lease in `GET <relay>/api/state` as `tcp_addr` or `udp_addr`, formatted `<hostname>:<port>`
- the publisher's own log line `raw transport endpoints allocated tcp_addr=... udp_addr=...`, which they may have pasted to the user

Only relays whose operator enabled TCP or UDP leases allocate ports. Most public relays do not, so a service that is HTTP-only on one relay is not a mistake. The port stays the same while the same publisher identity holds the lease.

## Connecting

No Portal software is needed on the connecting side. Use the protocol's normal client with the relay host and allocated port, and never add `https://`:

| Service | Client |
|---------|--------|
| Minecraft Java | add a multiplayer server with address `<hostname>:<port>` |
| Minecraft Bedrock (UDP) | add a server with `<hostname>` and the UDP port |
| SSH | `ssh -p <port> <user>@<hostname>` |
| PostgreSQL | `psql "host=<hostname> port=<port> sslmode=verify-full sslrootcert=<CA file from the publisher> dbname=..."`; `require` only encrypts and does not verify the server, so do not send credentials until `verify-full` is configured |
| Redis | `redis-cli -h <hostname> -p <port> --tls --cacert <CA file from the publisher>` when the server offers TLS |
| Anything else | the protocol's client, or `nc <hostname> <port>` for a manual session |

## What the relay can see

Raw mode adds no TLS. The relay accepts the client's TCP connection or UDP datagrams and forwards the bytes to the publisher's tunnel. Whatever the protocol sends in the clear is readable at the relay. Prefer protocols that encrypt themselves (SSH, TLS-enabled database connections, games with their own encryption), and do not send passwords or tokens over a plaintext protocol through a public relay. Treat the endpoint exactly like a port open on the public internet, because it is one.

## Verifying without mutating

A completed TCP handshake proves only that the relay allocated the port. Look for the protocol's own first response:

```sh
# SSH: the server speaks first, so an empty client read shows the banner
nc -w 5 <hostname> <port> < /dev/null | head -c 64

# HTTP served over a raw TCP lease
curl -sS --connect-timeout 5 --max-time 15 -o /dev/null -w '%{http_code}\n' http://<hostname>:<port>/

# PostgreSQL
pg_isready -h <hostname> -p <port>

# Minecraft Java, when a status tool is installed
mcstatus <hostname>:<port> status
```

When no protocol probe is available, say that only the TCP-level connection was verified. For UDP there is no handshake at all; report a UDP endpoint as verified only after a protocol-level exchange such as a Bedrock unconnected ping, otherwise report it as allocated but unverified.

Limits that shape the probe:

- UDP datagrams above 1350 bytes are dropped.
- UDP flows idle for 5 minutes are forgotten by the relay; long-lived protocols need keepalives.
- Relays cap concurrent TCP and UDP leases by their configured port range, so a publisher may lose an allocation to capacity rather than to an error.

## Reading failures

| Observation | Meaning |
|-------------|---------|
| connection refused | no lease on that port, or the relay does not publish that port range |
| connects, then closes with no protocol response | relay port allocated, publisher's tunnel or local service offline |
| connect timeout | firewall or security group on the relay host does not pass that port range |
| protocol error after banner | the service is up; the problem is inside the application or the client configuration |

Do not retry in a tight loop and do not sweep neighboring ports. Each allocated port belongs to a different publisher.
