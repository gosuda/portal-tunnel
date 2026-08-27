# Portal Deploy plugin

`portal-deploy` is a skills-only plugin for Codex, Claude Code, and Cursor. It teaches an agent to inspect a local app, choose the appropriate Portal tunnel mode, configure explicitly requested x402 paid routes, verify the public endpoint and payment challenge, and hand off the tunnel lifecycle safely. When a real Portal task encounters friction, it can retain sanitized local evidence and route an approved low-risk improvement through an upstream issue and PR.

Portal exposes a service that remains on the local machine. This plugin does not turn Portal into a cloud build or hosting platform.

## Layout

Shared skills, three host manifests. Do not copy `SKILL.md` per host.

```text
plugins/portal-deploy/
├── .codex-plugin/plugin.json      # Codex plugin manifest
├── .claude-plugin/plugin.json     # Claude Code plugin manifest
├── .cursor-plugin/plugin.json     # Cursor plugin manifest
├── skills/portal-expose/
│   ├── SKILL.md                   # Expose and verify Portal services
│   ├── agents/openai.yaml         # Codex skill UI metadata
│   └── references/
│       ├── feedback-evidence.md
│       ├── portal-cli.md
│       ├── game-hosting.md
│       ├── safety-and-verification.md
│       └── x402.md
├── skills/portal-feedback/
│   ├── SKILL.md                   # Turn approved friction into issues and PRs
│   ├── agents/openai.yaml
│   └── references/
│       ├── evidence-packet.schema.json
│       ├── finding.schema.json
│       ├── verification-attempt.schema.json
│       └── issue-and-pr-loop.md
├── skills/portal-relay/
│   └── SKILL.md                   # Run a public Portal relay
└── README.md
```

Repository-root catalogs, each pointing at this same plugin directory:

| Host | Catalog | Marketplace name |
| --- | --- | --- |
| Codex | `.agents/plugins/marketplace.json` | `portal-tunnel` |
| Claude Code | `.claude-plugin/marketplace.json` | `portal-tunnel` |
| Cursor | `.cursor-plugin/marketplace.json` | `portal-tunnel` |

Install unit is the plugin `portal-deploy`. Agent invocation units are the skills `portal-expose`, `portal-feedback`, and `portal-relay`.

## Local Codex setup

From the `portal-tunnel` repository root:

```sh
codex plugin marketplace add .
codex plugin add portal-deploy@portal-tunnel
```

Start a new Codex task and invoke `$portal-expose`, or ask Codex to deploy or share a local app with Portal.

After the repository is on GitHub:

```sh
codex plugin marketplace add gosuda/portal-tunnel
codex plugin add portal-deploy@portal-tunnel
```

## Local Claude Code setup

Validate and load directly during development:

```sh
claude plugin validate ./plugins/portal-deploy --strict
claude --plugin-dir ./plugins/portal-deploy
```

Or install through the repository marketplace:

```sh
claude plugin marketplace add .
claude plugin install portal-deploy@portal-tunnel
```

Run `/reload-plugins` when Claude Code asks for it. Invoke the skill as `/portal-deploy:portal-expose`.

After the repository is on GitHub:

```sh
claude plugin marketplace add gosuda/portal-tunnel
claude plugin install portal-deploy@portal-tunnel
```

## Local Cursor setup

Symlink the plugin for development, then reload the window:

```sh
mkdir -p ~/.cursor/plugins/local
ln -s "$(pwd)/plugins/portal-deploy" ~/.cursor/plugins/local/portal-deploy
```

Restart Cursor or run **Developer: Reload Window**. The skill appears as `/portal-expose`.

Public listing is a Git repository submitted at [cursor.com/marketplace/publish](https://cursor.com/marketplace/publish). Team marketplaces import the same `.cursor-plugin/marketplace.json`.

## Example prompts

- `Deploy the app in this repository with Portal and verify the public URL.`
- `Expose this app with Portal, protect GET /paid with x402, and verify the payment challenge.`
- `Create a temporary Portal preview for the frontend on port 5173.`
- `Keep this service available through a persistent Portal agent tunnel.`
- `Serve this trusted static site through Portal.`
- `Review the Portal friction recorded by my last tunnel attempt.`
- `Show the Portal feedback inbox and prepare the next issue brief.`
- `Approve this Portal feedback finding and carry the low-risk fix through a PR.`

`portal-expose` should not trigger for deploying a Portal relay, normal cloud hosting, or publishing the plugin. `portal-feedback` should trigger only for stored Portal friction or explicit feedback operations, not for an ordinary exposure request.

## Marketplace review cases

Positive:

- Deploy this local app with Portal and verify the public URL.
- Protect GET /paid with a 0.01 USDC x402 payment and verify the public challenge.
- Create a temporary Portal preview for this project.
- Run this app as a persistent Portal tunnel.
- Serve this trusted static site through Portal.
- Create a temporary Portal preview for the frontend on port 5173.
- Review the friction packet from the last failed Portal Agent setup.
- Show pending Portal feedback findings.
- Retry the blocked publication for this Portal feedback finding.

Negative:

- Deploy a Portal relay with this plugin.
- Publish this plugin to a marketplace.
- Host this app on generic cloud hosting.
- Expose this app through Portal. (`portal-expose`, not `portal-feedback`.)
- Explain a Portal error without creating upstream artifacts.

## Development validation

From the repository root:

```sh
python3 /path/to/skill-creator/scripts/quick_validate.py \
  plugins/portal-deploy/skills/portal-expose
python3 /path/to/skill-creator/scripts/quick_validate.py \
  plugins/portal-deploy/skills/portal-feedback
python3 /path/to/plugin-creator/scripts/validate_plugin.py \
  plugins/portal-deploy
claude plugin validate ./plugins/portal-deploy --strict
claude plugin validate . --strict
python3 -c 'import json,pathlib; [
  json.loads(pathlib.Path(p).read_text())
  for p in [
    "plugins/portal-deploy/.codex-plugin/plugin.json",
    "plugins/portal-deploy/.claude-plugin/plugin.json",
    "plugins/portal-deploy/.cursor-plugin/plugin.json",
    ".agents/plugins/marketplace.json",
    ".claude-plugin/marketplace.json",
    ".cursor-plugin/marketplace.json",
  ]
]'
```

No MCP server, hook, background monitor, or credential is bundled. The active Codex, Claude Code, or Cursor host remains responsible for command approvals, sandboxing, and network access.
