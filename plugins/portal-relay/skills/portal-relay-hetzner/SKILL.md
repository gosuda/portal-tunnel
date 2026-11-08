---
name: portal-relay-hetzner
description: Create a Hetzner Cloud server for a Portal relay with the hcloud CLI, attach a Hetzner Cloud Firewall that opens only the relay ports, keep a stable primary IPv4, and hand the host to portal-relay for deployment. Use when the user wants to run a Portal relay on Hetzner Cloud. Do not use for a server that already exists (portal-relay), for DNS changes at Cloudflare (portal-relay-cloudflare), or for Hetzner Robot dedicated servers.
license: MIT
---

# Portal relay on Hetzner Cloud

This skill creates and opens the host. `portal-relay` deploys the relay on it. Follow [`../portal-relay/references/provider-contract.md`](../portal-relay/references/provider-contract.md) (the `portal-relay` skill's contract in this same plugin; the path is relative to this file, so it matches the installed version and needs no network) for the phase order, credential rules, and approval rules. This file adds only what is specific to Hetzner Cloud.

## Preflight

- `hcloud version`. If the CLI is missing, point to the official hcloud install instructions and stop.
- `hcloud context active` names the active project context, and a read-only call such as `hcloud server-type list -o noheader` proves the token works here. Do not open `~/.config/hcloud/cli.toml`; it stores the token.

## Authenticate

When no context works, ask the user to create a project API token in the Hetzner Console and run `hcloud context create <name>` locally; the CLI prompts for the token, so it never appears in chat or in shell history. A project token can change every resource in that project, so suggest a dedicated project for the relay. In a CI or sandbox environment that the user controls, `HCLOUD_TOKEN` in its secret store also works; never set it in a command line.

## Plan

Collect and show, then wait for approval:

- Location (`hcloud location list`) and server type (`hcloud server-type list`; read current names and prices from `hcloud server-type describe <type>` instead of assuming them). The smallest Arm or x86 type is enough; the relay image supports `linux/arm64` and `linux/amd64`.
- Image: a current Ubuntu image from `hcloud image list --type system`.
- SSH key: an existing key from `hcloud ssh-key list`, or the user's public key added with `hcloud ssh-key create --public-key-from-file`. Without one Hetzner emails a root password; avoid that.
- Firewall rules from the contract. Hetzner Cloud Firewalls allow only what a rule lists, so every port the relay needs must be present.
- Primary IPv4: billed separately from the server. Create it on its own (`hcloud primary-ip create --type ipv4 --name <name> --location <location>`, with auto-delete off) and pass it with `--primary-ipv4`, so the glue address survives server re-creation.
- Optional `--enable-protection delete,rebuild` against accidental deletion.

## Apply

1. `hcloud firewall create --name <name> --rules-file rules.json`, where each rule is `{"direction": "in", "protocol": "tcp" | "udp", "port": "443" | "40000-40009", "source_ips": ["0.0.0.0/0", "::/0"]}` (restrict SSH to the operator's address when known).
2. `hcloud server create --name <name> --type <type> --image <image> --location <location> --ssh-key <key> --firewall <firewall> --primary-ipv4 <ip>`.
3. Read the address with `hcloud server ip <name>`.

Ubuntu images on Hetzner Cloud have no extra host firewall by default; if the user enabled `ufw`, open the same ports there.

## Verify

- `ssh root@<ip>` works, and after deployment `dig @<ip> <relay domain> NS` and `curl -fsS https://<relay domain>/api/healthz` succeed. A port that times out is usually missing from the Cloud Firewall.

## Hand off

Then continue with the `portal-relay` skill from **Verify the host**, not from **Deploy**: a fresh image may lack Docker and Compose v2, and that step checks and, with approval, installs them. Use this host's public address as the glue address. The NS and glue records come before **Deploy**, at the common skill's **Delegate DNS** step, because the relay's first start needs them to issue its certificate; the DS comes after **Deploy**, at **Publish the DS**. Report the server, firewall, and primary IP with their hourly or monthly price, and rollback: `hcloud server delete <name>`, `hcloud firewall delete <name>`, and `hcloud primary-ip delete <name>` (disable protection first if it was enabled).

Portal can also use Hetzner DNS as its ACME DNS provider (`ACME_DNS_PROVIDER=hetzner`); that is a relay setting covered by the configuration reference, not by this skill, and Hetzner DNS does not support ENS DNSSEC automation.
