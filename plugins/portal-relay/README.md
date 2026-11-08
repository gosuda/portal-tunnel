# Portal Relay plugin

`portal-relay` is a portable, skills-only Agent Plugin for relay operators: deploy a public Portal relay with Docker Compose, delegate its DNS zone, optionally enable TCP/UDP lease ports, verify it, and register it in the public pool. Publishing or reaching services through a relay belongs to the separate [`portal-tunnel`](../portal-tunnel/README.md) plugin.

## Layout

```text
plugins/portal-relay/
|-- plugin.json                         # Agent Plugins v1 manifest
|-- .codex-plugin/plugin.json           # Codex UI adapter
|-- assets/logo.svg
|-- skills/portal-relay/
|   |-- SKILL.md
|   `-- agents/openai.yaml              # OpenAI-specific skill UI metadata
`-- README.md
```

The repository catalogs (`.agents/plugins/marketplace.json`, `.claude-plugin/marketplace.json`, `.cursor-plugin/marketplace.json`) list this plugin next to `portal-tunnel`; see the [`portal-tunnel` README](../portal-tunnel/README.md#layout) for why each host needs its own catalog.

## Codex

```sh
codex plugin marketplace add gosuda/portal-tunnel
codex plugin add portal-relay@portal-tunnel
```

Start a new task and invoke `$portal-relay`.

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

Invoke `/portal-relay:portal-relay`.

## Cursor

```sh
mkdir -p ~/.cursor/plugins/local
ln -s "$(pwd)/plugins/portal-relay" ~/.cursor/plugins/local/portal-relay
```

The skill appears as `/portal-relay`.

## Example prompts

- `Run a public Portal relay on this server and verify its health endpoint.`
- `Set up a Portal relay at relay.example.com with TCP/UDP leases for game hosting.`
- `Register my Portal relay in the public relay pool.`

## Development validation

From the repository root:

```sh
python3 /path/to/skill-creator/scripts/quick_validate.py \
  plugins/portal-relay/skills/portal-relay
python3 /path/to/plugin-creator/scripts/validate_plugin.py \
  plugins/portal-relay
claude plugin validate ./plugins/portal-relay --strict
claude plugin validate . --strict
```

No MCP server, hook, background monitor, or credential is bundled. The relay's `ADMIN_TOKEN` and identity directory stay on the operator's host.
