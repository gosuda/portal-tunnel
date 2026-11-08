---
name: portal-relay-oracle
description: Create an Oracle Cloud Infrastructure (OCI) compute instance for a Portal relay, including Always Free Ampere A1 shapes, open the VCN and host firewall for the relay ports, attach a stable public IP, and hand the host to portal-relay for deployment. Use when the user wants to run a Portal relay on Oracle Cloud or OCI, or asks to use an Oracle free-tier VM as a relay. Do not use for a host that already exists (portal-relay), for DNS changes at Cloudflare (portal-relay-cloudflare), or for other clouds.
license: MIT
---

# Portal relay on Oracle Cloud

This skill creates and opens the host. `portal-relay` deploys the relay on it. Follow [`../portal-relay/references/provider-contract.md`](../portal-relay/references/provider-contract.md) (the `portal-relay` skill's contract in this same plugin; the path is relative to this file, so it matches the installed version and needs no network) for the phase order, credential rules, and approval rules. This file adds only what is specific to OCI.

## Preflight

- `oci --version`. If the CLI is missing, point to the official OCI CLI install guide and stop.
- Find a working profile without reading `~/.oci/config` contents: `oci session validate --profile <profile>` for a session profile, or a read-only call such as `oci iam region-subscription list --profile <profile>` for an API-key profile. Add `--auth security_token` for session profiles.

## Authenticate

When no profile works in this environment, ask the user to run `oci session authenticate --region <region> --profile-name <profile>` on a machine with a browser. The session expires; `oci session refresh --profile <profile>` extends it. Session files created on the user's laptop are not present in a remote sandbox; do not report the session as available there.

## Plan

Collect and show, then wait for approval:

- Region, compartment, and availability domain (`oci iam availability-domain list -c <compartment>`).
- Shape. `VM.Standard.A1.Flex` with `--shape-config '{"ocpus": 1, "memoryInGBs": 6}'` is enough for a relay. Ampere A1 can be Always Free within the account's limits; check the tenancy's limits and say that usage beyond them is billed. The relay image is published for `linux/arm64` and `linux/amd64`.
- Image: an Ubuntu image that matches the shape, from `oci compute image list -c <compartment> --operating-system "Canonical Ubuntu" --shape <shape>`.
- Network: an existing VCN with a public subnet and an internet gateway. Creating a VCN is a separate change; prefer the console's "VCN with Internet Connectivity" wizard if none exists.
- Ingress: a new network security group (`oci network nsg create`) with the relay ports from the contract, attached with `--nsg-ids`. Do not edit a shared default security list unless the user asks.
- Public IP: a reserved public IP (`oci network public-ip create --lifetime RESERVED`) so the glue address survives instance replacement. An ephemeral IP changes on re-creation and breaks the delegation.
- SSH: `--ssh-authorized-keys-file` with the user's public key. Never generate or move private keys for the user.

## Apply

1. Create the NSG and add rules with `oci network nsg rules add --nsg-id <nsg> --security-rules file://rules.json`; each rule is `direction: INGRESS`, `protocol` `6` (TCP) or `17` (UDP), `source` `0.0.0.0/0` (or the operator's address for SSH), and `tcpOptions`/`udpOptions.destinationPortRange`.
2. Launch: `oci compute instance launch -c <compartment> --availability-domain <ad> --shape <shape> --shape-config <json> --image-id <image> --subnet-id <subnet> --nsg-ids '["<nsg>"]' --assign-public-ip false --ssh-authorized-keys-file <pub> --display-name <name>`, then attach the reserved public IP to the instance's primary private IP. "Out of host capacity" for A1 is common: report it and offer another availability domain or a later retry. Never loop launches without approval.
3. Open the host firewall. OCI Ubuntu images ship iptables rules that reject inbound traffic except SSH, so the NSG alone is not enough. Over SSH, insert `ACCEPT` rules for the same ports before the `REJECT` rule in `/etc/iptables/rules.v4`, apply them, and persist them with `netfilter-persistent save`. Show the exact rules before changing them.

## Verify

- From outside OCI: `ssh` works, and after deployment `dig @<public IP> <relay domain> NS` and `curl -fsS https://<relay domain>/api/healthz` succeed. A timeout with the NSG open almost always means the host iptables still rejects the port.

## Hand off

Then continue with the `portal-relay` skill from **Verify the host**, not from **Deploy**: a fresh image may lack Docker and Compose v2, and that step checks and, with approval, installs them. Use this host's public address as the glue address. The NS and glue records come before **Deploy**, at the common skill's **Delegate DNS** step, because the relay's first start needs them to issue its certificate; the DS comes after **Deploy**, at **Publish the DS**. Report the instance, NSG, and reserved IP; whether the shape is inside the Always Free limits; and rollback: `oci compute instance terminate --instance-id <id>` (boot volume handling stated explicitly), then delete the NSG and release the reserved IP.
