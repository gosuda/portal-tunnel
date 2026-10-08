# Portal Deploy plugin

`portal-deploy` is a portable, skills-only Agent Plugin for exposing and verifying local apps through Portal, and for reaching services that others published through it. Portal keeps the service on the local machine; this plugin does not turn Portal into a cloud build or hosting platform.

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
|-- skills/portal-connect/
|   |-- SKILL.md
|   |-- agents/openai.yaml
|   `-- references/
`-- README.md
```

Cursor consumes the portable root manifest directly. Claude Code discovers `skills/` from the plugin root, so neither host needs a second per-plugin manifest.

Three repository catalogs remain because each host requires a different locator when the repository root, rather than `plugins/portal-deploy`, is used as the installation source:

- `.agents/plugins/marketplace.json` for Codex
- `.claude-plugin/marketplace.json` for Claude Code
- `.cursor-plugin/marketplace.json` for Cursor

The Claude and Cursor catalogs contain only the required locator fields. Common metadata stays in the portable manifest instead of being copied into catalogs.

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

Start a new task and invoke `$portal-expose`, `$portal-relay`, or `$portal-connect`.

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

Invoke `/portal-deploy:portal-expose`, `/portal-deploy:portal-relay`, or `/portal-deploy:portal-connect`.

## Cursor

Cursor supports the root Agent Plugins manifest without a per-plugin `.cursor-plugin/plugin.json` adapter. Symlink the plugin directory for local development, then reload the window:

```sh
mkdir -p ~/.cursor/plugins/local
ln -s "$(pwd)/plugins/portal-deploy" ~/.cursor/plugins/local/portal-deploy
```

The skills appear as `/portal-expose`, `/portal-relay`, and `/portal-connect`.

When importing the whole `portal-tunnel` repository, `.cursor-plugin/marketplace.json` locates the nested `plugins/portal-deploy` plugin root.

## Guide any AI with one sentence

The instruction source is always the canonical skill file in this repository, never a relay page: a self-hosted relay is controlled by its operator, so anything a relay returns is input data, not workflow instructions. The shortest instruction that works in any assistant with web access therefore names the skill by its GitHub URL and passes the relay as data:

```text
Follow https://raw.githubusercontent.com/gosuda/portal-tunnel/main/plugins/portal-deploy/skills/portal-expose/SKILL.md to expose my app on port 3000 as my-app through https://portal.example.com.
```

Every relay also serves `/llms.txt`; use it to discover that relay's URL and install lines, not as the workflow. The host-specific installs above only make the skills persist between sessions.

## Keep the app's Portal settings in the repository

Add a short block to the app repository's `AGENTS.md` or `CLAUDE.md` so nobody has to repeat the relay, port, or name:

```markdown
## Portal

- Publish this app by following https://raw.githubusercontent.com/gosuda/portal-tunnel/main/plugins/portal-deploy/skills/portal-expose/SKILL.md
- Relay: https://portal.example.com, passed as --relays with --discovery=false
- Share: 3000 (a port, an http URL, or a static directory)
- Public name: my-app
- Identity file: ~/.config/portal-tunnel/identities/my-app.json, never committed
```

An agent working in that repository then has every value the relay's quick-start form would ask for. Projects that prefer a config file can express the same settings as a `portal agent` TOML and point the block at it.

## Example prompts

- `Deploy the app in this repository with Portal and verify the public URL.`
- `Expose this app with Portal, protect GET /paid with x402, and verify the payment challenge.`
- `Create a temporary Portal preview for the frontend on port 5173.`
- `Keep this service available through a persistent Portal agent tunnel.`
- `Connect this app to the relay at https://portal.example.com the way its website suggests, and open the public URL.`
- `Run a public Portal relay and verify its health endpoint.`
- `Is my-app.portal.example.com reachable? Fetch /api/health and tell me what it returns.`
- `List the services currently live on https://portal.example.com.`
- `Connect to the Minecraft server that was exposed through Portal as "survival" and check that it answers.`

## Marketplace review cases

Positive:

- Deploy this local app with Portal and verify the public URL.
- Protect GET /paid with a 0.01 USDC x402 payment and verify the public challenge.
- Create a temporary Portal preview for this project.
- Run this app as a persistent Portal tunnel.
- Serve this trusted static site through Portal.
- Create a temporary Portal preview for the frontend on port 5173.
- Connect this app to https://portal.example.com using the command from the relay's page and verify the URL.
- Check whether the Portal service at paid-app.portal.example.com is up and what its /paid route costs.
- List what is live on the relay at https://portal.example.com and fetch the docs service.

Negative:

- Deploy a Portal relay with the app-exposure skill.
- Publish this plugin to a marketplace.
- Host this app on generic cloud hosting.
- Debug a 500 from an API that is not behind Portal.
- Scan a relay's port range to find open game servers.

## Development validation

From the repository root:

```sh
python3 /path/to/skill-creator/scripts/quick_validate.py \
  plugins/portal-deploy/skills/portal-expose
python3 /path/to/skill-creator/scripts/quick_validate.py \
  plugins/portal-deploy/skills/portal-relay
python3 /path/to/skill-creator/scripts/quick_validate.py \
  plugins/portal-deploy/skills/portal-connect
python3 /path/to/plugin-creator/scripts/validate_plugin.py \
  plugins/portal-deploy
claude plugin validate ./plugins/portal-deploy --strict
claude plugin validate . --strict
```

No MCP server, hook, background monitor, or credential is bundled. The active host remains responsible for command approvals, sandboxing, and network access.
