# Portal Deploy plugin

`portal-deploy` is a portable, skills-only Agent Plugin for exposing and verifying local apps through Portal. Portal keeps the service on the local machine; this plugin does not turn Portal into a cloud build or hosting platform.

## Layout

The root `plugin.json` is the single portable identity and metadata contract. Every host discovers the same `skills/` directory.

```text
plugins/portal-deploy/
|-- plugin.json                         # Agent Plugins v1 manifest
|-- .codex-plugin/plugin.json           # Codex UI adapter
|-- assets/logo.svg
|-- skills/portal-expose/
|   |-- SKILL.md
|   |-- agents/openai.yaml              # OpenAI-specific skill UI metadata
|   `-- references/
|-- skills/portal-relay/SKILL.md
`-- README.md
```

Cursor consumes the portable root manifest directly. Claude Code discovers `skills/` from the plugin root, so neither host needs a second per-plugin manifest.

Two repository catalogs remain because Codex and Claude Code require different catalog locations when installing a plugin from a repository:

- `.agents/plugins/marketplace.json` for Codex
- `.claude-plugin/marketplace.json` for Claude Code

The Claude catalog contains only the required plugin name and source. Common metadata stays in the portable manifest instead of being copied into catalogs.

`AGENTS.md` remains repository development guidance. `llms.txt` remains the generic discovery entry point served by a Portal relay; neither belongs to the plugin package contract.

## Codex

From the repository root:

```sh
codex plugin marketplace add .
codex plugin add portal-deploy@portal-tunnel
```

For the GitHub repository:

```sh
codex plugin marketplace add gosuda/portal-tunnel
codex plugin add portal-deploy@portal-tunnel
```

Start a new task and invoke `$portal-expose` or `$portal-relay`.

## Claude Code

Load the plugin directory directly during development:

```sh
claude plugin validate ./plugins/portal-deploy --strict
claude --plugin-dir ./plugins/portal-deploy
```

For persistent repository installation:

```sh
claude plugin marketplace add gosuda/portal-tunnel
claude plugin install portal-deploy@portal-tunnel
```

Invoke `/portal-deploy:portal-expose` or `/portal-deploy:portal-relay`.

## Cursor

Cursor supports the root Agent Plugins manifest without a `.cursor-plugin` adapter. Symlink the plugin directory for local development, then reload the window:

```sh
mkdir -p ~/.cursor/plugins/local
ln -s "$(pwd)/plugins/portal-deploy" ~/.cursor/plugins/local/portal-deploy
```

The skills appear as `/portal-expose` and `/portal-relay`.

## Example prompts

- `Deploy the app in this repository with Portal and verify the public URL.`
- `Expose this app with Portal, protect GET /paid with x402, and verify the payment challenge.`
- `Create a temporary Portal preview for the frontend on port 5173.`
- `Keep this service available through a persistent Portal agent tunnel.`
- `Run a public Portal relay and verify its health endpoint.`

## Marketplace review cases

Positive:

- Deploy this local app with Portal and verify the public URL.
- Protect GET /paid with a 0.01 USDC x402 payment and verify the public challenge.
- Create a temporary Portal preview for this project.
- Run this app as a persistent Portal tunnel.
- Serve this trusted static site through Portal.
- Create a temporary Portal preview for the frontend on port 5173.

Negative:

- Deploy a Portal relay with the app-exposure skill.
- Publish this plugin to a marketplace.
- Host this app on generic cloud hosting.

## Development validation

From the repository root:

```sh
python3 /path/to/skill-creator/scripts/quick_validate.py \
  plugins/portal-deploy/skills/portal-expose
python3 /path/to/skill-creator/scripts/quick_validate.py \
  plugins/portal-deploy/skills/portal-relay
python3 /path/to/plugin-creator/scripts/validate_plugin.py \
  plugins/portal-deploy
claude plugin validate ./plugins/portal-deploy --strict
claude plugin validate . --strict
```

No MCP server, hook, background monitor, or credential is bundled. The active host remains responsible for command approvals, sandboxing, and network access.
