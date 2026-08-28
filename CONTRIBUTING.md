# Contributing

`AGENTS.md` is the core implementation guide. Architecture, product behavior, and design rationale belong in `docs/architecture.md` and `docs/adr/README.md`. This file is contribution policy. The merge bar for agent-facing changes is [#346](https://github.com/gosuda/portal-tunnel/issues/346).

## Pull requests

Fork, branch, make a focused change with tests or docs, open a PR.

## AI accessibility

Agents may file issues, reviews, and small PRs without prior assignment when the change is CLI, logs, diagnostics, docs, skills, or integration friction.

Every repeated agent instruction is a candidate accessibility bug. Fix the Portal surface and delete the instruction. Do not document another workaround.

Core semantic changes require stronger justification under [#346](https://github.com/gosuda/portal-tunnel/issues/346) and the repository's architecture rules. Generic feedback orchestration stays outside this repository ([#331](https://github.com/gosuda/portal-tunnel/issues/331)).