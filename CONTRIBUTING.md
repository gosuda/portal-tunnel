# Contributing

`AGENTS.md` is the core implementation and architecture guide. This file is contribution policy. The merge bar for agent-facing code is [#346](https://github.com/gosuda/portal-tunnel/issues/346).

## Pull requests

Fork, branch, make a focused change with tests or docs, open a PR.

## AI accessibility

Agents may file issues, reviews, and small PRs without prior assignment when the change is CLI, logs, diagnostics, docs, skills, or integration friction.

Every repeated agent instruction is a candidate accessibility bug. Fix the Portal surface and delete the instruction. Do not document another workaround.

Protocol, cryptography, trust, identity, transport, and architecture stay under `AGENTS.md`. Do not add a plugin workflow engine, finding store, or feedback CLI ([#331](https://github.com/gosuda/portal-tunnel/issues/331)).
