---
name: portal-relay-diagnose
description: Find which layer of a self-hosted Portal relay is failing - container and process, open ports, embedded DNS and NS/glue delegation, DNSSEC and the parent DS, TLS and SNI routing, the QUIC UDP backhaul and TCP/UDP lease ports, or approval and source policy - with bounded read-only checks, then report the cause and the fix. Use when a relay operator says the relay, its DNS, its certificates, its tunnels, or its game ports do not work. Do not use when the user is a publisher or visitor of one tunnel (portal-expose or portal-connect), for approving or banning leases (portal-relay-admin), or for first deployment (portal-relay).
license: MIT
---

# Diagnose a Portal relay

Work from the bottom layer up and stop at the first layer that fails: a DNS check means nothing while the container is down. Every check here is read-only and bounded (`curl --max-time 10`, `dig +time=3 +tries=1`, `--tail 200` on logs). Do not restart, recreate, or reconfigure anything during diagnosis; propose the fix and let the operator approve it.

Run checks from two places when possible, because a check on the relay host passes through no cloud firewall:

- **Host**: a shell on the relay machine.
- **Outside**: any other network, for example the agent's own environment.

Say which place each result came from.

## 1. Process and container (host)

- `docker compose ps portal` is running and not restarting.
- `docker compose logs portal --tail 200`: look for bind errors (`address already in use` on `443` or `53`), `permission denied` on `IDENTITY_PATH` (the image runs as uid/gid `65532`), embedded DNS start failures, and the `ds_record` line.
- `sudo ss -tulpn | grep -E ':(443|53) '`: the relay owns `443/tcp`, `53/tcp`, `53/udp`, and `443/udp` when UDP leases are on. Another process on `53` is often `systemd-resolved`.

## 2. Ports (outside)

- `curl -fsS --max-time 10 https://<relay>/api/healthz`. A timeout with the container healthy points to a cloud firewall or host firewall, not to Portal.
- `dig +time=3 +tries=1 @<relay IP> <relay domain> SOA` and the same with `+tcp`: one passing and one failing means only one of `53/udp` and `53/tcp` is open.
- Compare with the provider's firewall rules. OCI images also reject inbound in host iptables; Lightsail and Hetzner use their own firewalls in front of the host.

## 3. DNS delegation (outside)

1. `dig @<relay IP> test.<relay domain> A` answers: the embedded DNS works.
2. `dig +short NS <relay domain> @1.1.1.1` returns `ns.<relay domain>`, and `dig +short A ns.<relay domain> @1.1.1.1` (and `AAAA`) returns the relay address: the parent delegation and glue are right.
3. If 1 passes and 2 fails, the problem is at the parent zone: a missing NS, a wrong glue address (common after a public IP changed), a proxied glue record, or propagation still in progress. Read the parent's records with `dig @<parent NS> <relay domain> NS +norec`.
4. An empty AAAA on an IPv4-only relay is expected.

## 4. DNSSEC (outside)

- `dig DS <relay domain> @1.1.1.1` compared with the `ds_record` log line: key tag, algorithm `13`, digest type `2`, and digest must match exactly.
- `dig +dnssec <relay domain> SOA @1.1.1.1`: `SERVFAIL` from a validating resolver with a DS present, while `dig +cd` succeeds, means a DS mismatch or a replaced `dnssec-csk.json`. The fix is to publish the DS from the current key or to restore the old key file, never to delete the key.
- No DS at the parent means DNSSEC is simply not chained yet; it is not a failure.

## 5. TLS and SNI (outside)

- `openssl s_client -connect <relay IP>:443 -servername <relay domain> </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates` for the relay's own name.
- A tunnel hostname that fails the TLS handshake while the relay name works means no routable lease for that name (offline, pending approval, denied), not a certificate problem. Check it in layer 7.
- With `ACME_DNS_PROVIDER` set to an external provider, look for provider authentication errors in the logs.

## 6. Transport (outside, only when enabled)

- UDP leases need `443/udp` published and open, because the QUIC backhaul uses the public `PORTAL_URL` port.
- TCP/UDP lease ports: the Docker published range, the host firewall, and the cloud firewall must all cover the same `MIN_PORT`-`MAX_PORT` range. Probe one allocated port only, for example `nc -vz -w 5 <relay IP> <port>`. Never scan the range.
- Error codes from a publisher: `udp_disabled`, `tcp_port_disabled` (lease type off), `*_capacity_exceeded` (`max_leases` reached), and `*_port_exhausted` (range too small).

## 7. Policy (needs portal-relay-admin)

- `lease_rejected`: the lease waits for approval in `manual` mode. `lease_denied`: the identity is denied or banned.
- `source_not_allowed`: the publisher's address is outside `TUNNEL_SOURCE_CIDRS`. Behind a proxy that also needs `TRUST_PROXY_HEADERS` and `TRUSTED_PROXY_CIDRS`.
- Read the lease state through `portal-relay-admin`; do not change policy as part of diagnosis.

## Report

Give the first failing layer, the evidence (the command, where it ran, and its output), the most likely cause, and the fix as a proposal. List the layers that passed and the checks that could not run (for example no shell on the host). Do not print `ADMIN_TOKEN`, provider tokens, or the contents of `IDENTITY_PATH`.
