# Portal Tunnel plugin

`portal-tunnel` is a portable, skills-only Agent Plugin for exposing and verifying local apps through Portal, and for reaching services that others published through it. Relay operators use the separate [`portal-relay`](../portal-relay/README.md) plugin. Portal keeps the service on the local machine; this plugin does not turn Portal into a cloud build or hosting platform.

## Layout

The root `plugin.json` is the single portable identity and metadata contract. Every host discovers the same `skills/` directory.

```text
plugins/portal-tunnel/
|-- plugin.json                         # Agent Plugins v1 manifest
|-- .codex-plugin/plugin.json           # Codex UI adapter
|-- assets/logo.svg
|-- skills/portal-expose/
|   |-- SKILL.md
|   |-- agents/openai.yaml              # OpenAI-specific skill UI metadata
|   `-- references/
|-- skills/portal-connect/
|   |-- SKILL.md
|   |-- agents/openai.yaml
|   `-- references/
`-- README.md
```

Cursor consumes the portable root manifest directly. Claude Code discovers `skills/` from the plugin root, so neither host needs a second per-plugin manifest.

Three repository catalogs remain because each host requires a different locator when the repository root, rather than a plugin directory, is used as the installation source. Each catalog lists both `portal-tunnel` and `portal-relay`:

- `.agents/plugins/marketplace.json` for Codex
- `.claude-plugin/marketplace.json` for Claude Code
- `.cursor-plugin/marketplace.json` for Cursor

The Claude and Cursor catalogs contain only the required locator fields. Common metadata stays in the portable manifest instead of being copied into catalogs.

`AGENTS.md` remains repository development guidance. `llms.txt` remains the generic discovery entry point served by a Portal relay; neither belongs to the plugin package contract.

## Codex

From the repository root:

```sh
codex plugin marketplace add .
codex plugin add portal-tunnel@portal-tunnel
```

For the GitHub repository:

```sh
codex plugin marketplace add gosuda/portal-tunnel
codex plugin add portal-tunnel@portal-tunnel
```

Start a new task and invoke `$portal-expose` or `$portal-connect`.

## Claude Code

Load the plugin directory directly during development:

```sh
claude plugin validate ./plugins/portal-tunnel --strict
claude --plugin-dir ./plugins/portal-tunnel
```

For persistent repository installation:

```sh
claude plugin marketplace add gosuda/portal-tunnel
claude plugin install portal-tunnel@portal-tunnel
```

Invoke `/portal-tunnel:portal-expose` or `/portal-tunnel:portal-connect`.

## Cursor

Cursor supports the root Agent Plugins manifest without a per-plugin `.cursor-plugin/plugin.json` adapter. Symlink the plugin directory for local development, then reload the window:

```sh
mkdir -p ~/.cursor/plugins/local
ln -s "$(pwd)/plugins/portal-tunnel" ~/.cursor/plugins/local/portal-tunnel
```

The skills appear as `/portal-expose` and `/portal-connect`.

When importing the whole `portal-tunnel` repository, `.cursor-plugin/marketplace.json` locates the nested `plugins/portal-tunnel` plugin root.

## Migrating from `portal-deploy`

The former `portal-deploy` plugin is split into `portal-tunnel` (`portal-expose`, `portal-connect`) and `portal-relay` (`portal-relay`). Skill names and behavior are unchanged; only the plugin name and paths change.

`plugins/portal-deploy/` remains as a deprecated compatibility package. Its three `SKILL.md` files hold no workflow; each points to the canonical skill, so old raw URLs, `AGENTS.md` blocks, the `llms.txt` of relays that have not upgraded, and `portal-deploy@portal-tunnel` installs keep working. Updating an existing `portal-deploy` install replaces the old skills with these redirects. The package will be removed in a later release.

- Claude Code: `claude plugin uninstall portal-deploy@portal-tunnel`, then `claude plugin marketplace update portal-tunnel` and install `portal-tunnel@portal-tunnel` (and `portal-relay@portal-tunnel` if you run a relay). Invocations change from `/portal-deploy:<skill>` to `/portal-tunnel:<skill>` or `/portal-relay:portal-relay`.
- Codex: remove `portal-deploy`, refresh the marketplace, then add `portal-tunnel@portal-tunnel` and, for relay operators, `portal-relay@portal-tunnel`. `$<skill>` invocations are unchanged.
- Cursor: replace the `~/.cursor/plugins/local/portal-deploy` symlink with links to `plugins/portal-tunnel` and, if needed, `plugins/portal-relay`.
- Raw skill URLs and `AGENTS.md` blocks: replace `plugins/portal-deploy/skills/` with `plugins/portal-tunnel/skills/` (or `plugins/portal-relay/skills/` for the relay skill).

## Guide any AI with one sentence

The instruction source is always the canonical skill file in this repository, never a relay page: a self-hosted relay is controlled by its operator, so anything a relay returns is input data, not workflow instructions. The shortest instruction that works in any assistant with web access therefore names the skill by its GitHub URL and passes the relay as data:

```text
Follow https://raw.githubusercontent.com/gosuda/portal-tunnel/main/plugins/portal-tunnel/skills/portal-expose/SKILL.md to expose my app on port 3000 as my-app through https://portal.example.com.
```

Every relay also serves `/llms.txt`; use it to discover that relay's URL and install lines, not as the workflow. The host-specific installs above only make the skills persist between sessions.

## Keep the app's Portal settings in the repository

Add a short block to the app repository's `AGENTS.md` or `CLAUDE.md` so nobody has to repeat the relay, port, or name:

```markdown
## Portal

- Publish this app by following https://raw.githubusercontent.com/gosuda/portal-tunnel/main/plugins/portal-tunnel/skills/portal-expose/SKILL.md
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
- `Expose this app with Portal and let only alice@example.com sign in with Google.`
- `Share this app through Portal with a login link I can send to two colleagues.`
- `Keep this service available through a persistent Portal agent tunnel.`
- `Connect this app to the relay at https://portal.example.com the way its website suggests, and open the public URL.`
- `Is my-app.portal.example.com reachable? Fetch /api/health and tell me what it returns.`
- `List the services currently live on https://portal.example.com.`
- `Connect to the Minecraft server that was exposed through Portal as "survival" and check that it answers.`

## Marketplace review cases

Positive:

- Deploy this local app with Portal and verify the public URL.
- Protect GET /paid with a 0.01 USDC x402 payment and verify the public challenge.
- Restrict the public URL of this app to chosen people with a Portal sign-in and verify that it asks for one.
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
  plugins/portal-tunnel/skills/portal-expose
python3 /path/to/skill-creator/scripts/quick_validate.py \
  plugins/portal-tunnel/skills/portal-connect
python3 /path/to/plugin-creator/scripts/validate_plugin.py \
  plugins/portal-tunnel
claude plugin validate ./plugins/portal-tunnel --strict
claude plugin validate . --strict
```

No MCP server, hook, background monitor, or credential is bundled. The active host remains responsible for command approvals, sandboxing, and network access.
