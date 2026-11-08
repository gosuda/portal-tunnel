# Portal Relay plugin

`portal-relay` is a portable, skills-only Agent Plugin for relay operators: deploy a public Portal relay with Docker Compose, delegate its DNS zone, optionally enable TCP/UDP lease ports, verify it, and register it in the public pool. Publishing or reaching services through a relay belongs to the separate [`portal-tunnel`](../portal-tunnel/README.md) plugin.

## Layout

```text
plugins/portal-relay/
|-- plugin.json                         # Agent Plugins v1 manifest
|-- .codex-plugin/plugin.json           # Codex UI adapter
|-- assets/logo.svg
|-- skills/portal-relay/                # common deployment, DNS, and verification
|   |-- SKILL.md
|   |-- agents/openai.yaml              # OpenAI-specific skill UI metadata
|   `-- references/provider-contract.md # rules every provider skill follows
|-- skills/portal-relay-admin/          # approval, bans, limits, metrics
|-- skills/portal-relay-diagnose/       # layer-by-layer failure isolation
|-- skills/portal-relay-oracle/         # Oracle Cloud host
|-- skills/portal-relay-hetzner/        # Hetzner Cloud host
|-- skills/portal-relay-aws/            # AWS EC2 or Lightsail host
|-- skills/portal-relay-cloudflare/     # Cloudflare parent-zone DNS
`-- README.md
```

The repository catalogs (`.agents/plugins/marketplace.json`, `.claude-plugin/marketplace.json`, `.cursor-plugin/marketplace.json`) list this plugin next to `portal-tunnel`; see the [`portal-tunnel` README](../portal-tunnel/README.md#layout) for why each host needs its own catalog.

## Skills

| Skill | Priority | Workflow |
|---|---|---|
| `portal-relay` | | Deploy, delegate DNS, verify, and register a relay on any Linux host |
| `portal-relay-oracle` | P1 | Oracle Cloud host |
| `portal-relay-cloudflare` | P1 | Cloudflare parent-zone NS, glue, and DS records |
| `portal-relay-hetzner` | P2 | Hetzner Cloud host |
| `portal-relay-admin` | P2 | Approve, deny, ban, or rate-limit leases; approval mode and lease limits; metrics |
| `portal-relay-diagnose` | P2 | Read-only, layer-by-layer failure isolation |
| `portal-relay-aws` | P3 | AWS EC2 or Lightsail host |

## Provider skills

`portal-relay` deploys on any Linux host with a public IP. Provider skills cover only what differs per provider and then hand back to it:

- `portal-relay-oracle`, `portal-relay-hetzner`, and `portal-relay-aws` create the host and open its network.
- `portal-relay-cloudflare` writes the delegation and DS records when the parent zone is on Cloudflare.

A cloud skill and a DNS skill compose, for example "Deploy a relay on Oracle Cloud and configure DNS with Cloudflare." Each provider skill uses the provider's own CLI or API credentials, which the user sets up locally. The skills never ask for a key in chat, and they show a plan and wait for approval before they create, delete, or change billed resources or DNS records.

## Codex

```sh
codex plugin marketplace add gosuda/portal-tunnel
codex plugin add portal-relay@portal-tunnel
```

Start a new task and invoke `$portal-relay` or any skill in the table above, for example `$portal-relay-admin`.

## Claude Code

```sh
claude plugin validate ./plugins/portal-relay --strict
claude --plugin-dir ./plugins/portal-relay
```

For persistent repository installation:

```sh
claude plugin marketplace add gosuda/portal-tunnel
claude plugin install portal-relay@portal-tunnel
```

Invoke `/portal-relay:<skill>`, for example `/portal-relay:portal-relay` or `/portal-relay:portal-relay-diagnose`.

## Cursor

```sh
mkdir -p ~/.cursor/plugins/local
ln -s "$(pwd)/plugins/portal-relay" ~/.cursor/plugins/local/portal-relay
```

Each skill appears under its own name, for example `/portal-relay` or `/portal-relay-admin`.

## Example prompts

- `Run a public Portal relay on this server and verify its health endpoint.`
- `Set up a Portal relay at relay.example.com with TCP/UDP leases for game hosting.`
- `Register my Portal relay in the public relay pool.`
- `Deploy a Portal relay on Oracle Cloud's free tier and configure DNS with Cloudflare.`
- `Create a Hetzner Cloud server for a Portal relay with game-hosting ports.`
- `Check the NS, glue, and DS records for relay.example.com in my Cloudflare zone.`
- `Switch my relay to manual approval and approve the tunnel named my-app.`
- `My relay's tunnels stopped working after I moved the server. Find out why.`
- `Run a Portal relay on AWS Lightsail.`

## Development validation

From the repository root:

```sh
for s in plugins/portal-relay/skills/*/; do
  python3 /path/to/skill-creator/scripts/quick_validate.py "$s"
done
python3 /path/to/plugin-creator/scripts/validate_plugin.py \
  plugins/portal-relay
claude plugin validate ./plugins/portal-relay --strict
claude plugin validate . --strict
```

No MCP server, hook, background monitor, or credential is bundled. Provider credentials stay in each provider's own CLI configuration or the user's secret store, and the relay's `ADMIN_TOKEN` and identity directory stay on the operator's host.
