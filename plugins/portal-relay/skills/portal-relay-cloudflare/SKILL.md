---
name: portal-relay-cloudflare
description: Configure a Cloudflare-hosted parent zone for a Portal relay - the NS delegation of the relay subdomain to the relay's embedded DNS, the glue A/AAAA records, and the DS record for DNSSEC - with a zone-scoped API token, then verify delegation and DNSSEC from public resolvers. Use when the parent domain of a Portal relay is on Cloudflare DNS and the user wants the delegation or DS record created or checked. Do not use for hosting the relay (Cloudflare is not the VM provider here), for proxying relay traffic through Cloudflare, or for zones that are not on Cloudflare.
license: MIT
---

# Portal relay DNS on Cloudflare

Cloudflare is the **parent** DNS provider here, not the host. The relay serves its own subdomain from embedded DNS; this skill writes only the parent-zone records that point to it. Follow [`../portal-relay/references/provider-contract.md`](../portal-relay/references/provider-contract.md) (the `portal-relay` skill's contract in this same plugin; the path is relative to this file, so it matches the installed version and needs no network) for the phase order, credential rules, and approval rules. Take the record layout and DNSSEC facts from `portal-relay` and the [Embedded DNS reference](https://gosuda.github.io/portal-tunnel/configuration#embedded-dns).

## Records this skill may change

For relay domain `relay.example.com` in Cloudflare zone `example.com`:

| Type | Name | Content | When |
|---|---|---|---|
| `NS` | `relay.example.com` | `ns.relay.example.com` | Delegation |
| `A` | `ns.relay.example.com` | relay public IPv4, **DNS only** | Glue, when IPv4 is reachable |
| `AAAA` | `ns.relay.example.com` | relay public IPv6, **DNS only** | Glue, when IPv6 is reachable |
| `DS` | `relay.example.com` | key tag, algorithm, digest type, digest from the relay startup log | After the delegation resolves |

Change nothing else. If any other record already exists at `relay.example.com` or below it, stop and show it: Cloudflare cannot keep other records at a delegated name, and removing them is a separate decision. Glue records must not be proxied.

Cloudflare cannot delegate a subdomain of a zone on a partial (CNAME) setup. Glue at the registrar is needed only when the relay domain is the registered domain itself, which this layout avoids.

## Preflight and authentication

- Use a Cloudflare API token, never the Global API Key. Ask the user to create a custom token limited to the one zone with `Zone - DNS - Edit` (add `Zone - Zone - Read` only if the zone ID must be looked up), and to put it in this environment as `CLOUDFLARE_API_TOKEN` through a secret store or protected session, not in chat, files in the repository, or a command line.
- Keep the token out of process arguments: pass the header from a file descriptor, for example `curl -fsS -H @<(printf 'Authorization: Bearer %s\n' "$CLOUDFLARE_API_TOKEN") https://api.cloudflare.com/client/v4/...`. Never echo the variable.
- Check the token with `GET /user/tokens/verify` (account-owned tokens use `GET /accounts/<account_id>/tokens/verify`), then find the zone with `GET /zones?name=example.com` and read its DNSSEC state with `GET /zones/<zone_id>/dnssec`.
- If no token is usable here, give the user the records above to create in the Cloudflare dashboard instead, and continue with verification.

## Plan and apply

This skill runs in two parts at two points of the `portal-relay` workflow:

- **Part A, NS and glue** (steps 1-4 below): at **Delegate DNS**, before **Deploy**. The relay's first start issues its certificate through ACME DNS-01 answered by its own embedded DNS, so the delegation must exist first. The relay is not running yet, so verify Part A at the parent only.
- **Part B, DS** (step 5 below): at **Publish the DS**, after **Deploy**. The DS comes from the DNSSEC key that the relay creates at its first start, and the relay must answer for its zone before a DS is published.

Return to `portal-relay` after each part.

1. Read existing records with `GET /zones/<zone_id>/dns_records?name=<name>&type=<type>` for each row of the table. Decide one action per row and show the plan with current values:
   - **No record** of that name and type: `create` with `POST /zones/<zone_id>/dns_records`.
   - **A record with a different value** (content, `data`, or `proxied: true` on glue): `update` with `PATCH /zones/<zone_id>/dns_records/<id>` on that same `id`. Never delete and re-create it.
   - **A record with the same value**: `no-op`. Send no request.
2. Before any write, save a rollback record per row: the record `id` (from the read for an update, from the `POST` response for a create), the action, and for an update the full previous record (`type`, `content` or `data`, `ttl`, `proxied`).
3. After approval, apply the NS and glue actions. The request bodies are the same for `POST` and `PATCH`: `{"type": "NS", "name": "relay.example.com", "content": "ns.relay.example.com"}` and `{"type": "A", "name": "ns.relay.example.com", "content": "<ip>", "proxied": false}` (`AAAA` likewise).
4. Check Part A at the parent: `dig @<cloudflare NS of the zone> relay.example.com NS +norec` lists `ns.relay.example.com` with the glue address. Then return to `portal-relay` for **Deploy**.
5. Part B, after the relay is running: confirm `dig @<relay IP> relay.example.com SOA` answers, then apply the DS action with the same create / update / no-op rule and the body `{"type": "DS", "name": "relay.example.com", "data": {"key_tag": <tag>, "algorithm": 13, "digest_type": 2, "digest": "<hex>"}}`, copying every field exactly from the relay's `ds_record` log line. That line is in zone-file form, `relay.example.com. <ttl> IN DS <key tag> <algorithm> <digest type> <digest>`; the embedded DNS uses algorithm `13` and digest type `2`. A DS only builds a chain of trust when DNSSEC is active on the Cloudflare zone; if it is not, report that and let the user decide whether to enable it.

After Part B, return to `portal-relay` at **Verify**. Publishing a DS for a zone that does not answer yet makes validating resolvers fail for the whole subdomain.

## Verify

- `dig +short NS relay.example.com @1.1.1.1` returns `ns.relay.example.com`, and `dig +short A ns.relay.example.com @1.1.1.1` returns the relay address.
- `dig @<relay IP> relay.example.com SOA` answers from the relay itself.
- After the DS step: `dig +dnssec relay.example.com SOA @1.1.1.1` has the `ad` flag, and `dig DS relay.example.com @1.1.1.1` matches the log. Allow for record TTLs before calling a check failed.

## Hand off

Report each record with its action and previous value, and the DNSSEC state of the parent zone.

Rollback uses the saved rollback record, never a blanket delete:

- A record this workflow **created**: `DELETE /zones/<zone_id>/dns_records/<id>`.
- A record this workflow **updated**: `PATCH` the same `id` back to its saved previous value. Do not delete it; the old delegation or glue may still be in use.
- An **unchanged** record: leave it alone.

Keep DNSSEC safe while rolling back. Undo the DS first: delete a created DS, or restore an updated DS to its previous value. Then undo the NS and glue changes. If the restored DS does not match the key that the restored NS target serves, say so and do not restore both blindly; a DS that points to the wrong key breaks validation for the whole subdomain, and so does a DS left in place after its NS is removed.

Portal can also use Cloudflare as its ACME DNS provider (`ACME_DNS_PROVIDER=cloudflare` with `CLOUDFLARE_TOKEN`) instead of embedded DNS. That is a relay configuration choice with different records, covered by the configuration reference, not by this skill.
