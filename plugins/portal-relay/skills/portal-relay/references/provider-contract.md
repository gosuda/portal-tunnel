# Provider adapter contract

Provider skills (`portal-relay-oracle`, `portal-relay-hetzner`, `portal-relay-cloudflare`) handle only what differs per provider: account authentication, creating the host, opening its network, or editing the parent DNS zone. Relay deployment, DNS layout, DNSSEC, and verification stay in `portal-relay`. A host that already exists with a public IP needs no provider skill.

A cloud provider and a DNS provider compose independently. "Deploy a relay on Oracle Cloud and configure DNS with Cloudflare" runs `portal-relay-oracle` for the host, `portal-relay` for the deployment, and `portal-relay-cloudflare` for the delegation and the DS record.

## Phases

Run every provider workflow in this order and do not skip a phase:

1. **Preflight**: find the provider CLI and check for usable credentials with a non-secret status command.
2. **Authenticate**: when no credential is usable, give the user the provider's own login or token command to run on their machine. Portal has no login or credential store of its own.
3. **Plan**: list each resource or record that will be created, changed, or deleted, with account or project, region, zone, size, open ports, and the estimated recurring cost where one applies.
4. **Approve**: get explicit approval for that exact plan. Ask again when the plan changes.
5. **Apply**: make only the approved changes through the provider CLI or API.
6. **Verify**: check the result from outside the provider, then hand off to the next skill.
7. **Hand off**: report what exists now, what it costs, how to undo it, and what was not verified. A cloud skill hands a new host to `portal-relay` at **Verify the host**, which owns the Docker and Compose bootstrap; provider skills do not install software on the host themselves, except the provider-specific network setup they document (such as OCI host iptables).

## Credential rules

- Credentials belong to the provider. Never ask the user to paste an API key, token, password, session token, or private key into the chat, and never write one into the repository, an issue, a log, or a command-line argument.
- Do not read, print, or copy credential files. Check state with the CLI's own status command, and let the CLI read its own config.
- The user's laptop and the agent's execution environment are often different machines. A user who says "I logged in" may be logged in somewhere else. Trust only a status command that succeeds in this environment. When it fails, give commands for the user to run, or use a connector the user has already approved.
- Prefer the smallest scope: a project-scoped token, a session that expires, or a token limited to one DNS zone.
- Redact identifiers that the user did not ask to share (OCIDs, account IDs, tokens) from the handoff.

## Mutation rules

- Account, region, zone, instance size, billing tier, opened ports, resource creation, deletion, and every DNS record change need approval before they happen.
- Open only the ports the relay uses: `22/tcp` (restrict to the operator's address when it is known), `443/tcp`, `53/tcp`, `53/udp`, and, only when the matching lease type is enabled, `443/udp` and the `MIN_PORT`-`MAX_PORT` range. Never open the admin dashboard on a separate port; it is served on `443`.
- Never delete or replace a resource that this workflow did not create.
- Give a rollback for each change: the delete command for each resource, and the previous value of each DNS record.
