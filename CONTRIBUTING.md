# Contributing

`AGENTS.md` is the core implementation guide. Architecture, product behavior, and design rationale belong in `docs/architecture.md` and `docs/adr/README.md`. This file is contribution policy.

## Human contributions

Human contributors may propose issues, reviews, and pull requests across the project.

Fork, branch, make a focused change with tests or docs, and open a PR. Changes to protocol semantics, cryptography, trust, identity, transport, or architecture should explain the design rationale and follow `AGENTS.md` and the repository architecture rules.

## AI contributions

AI-generated issues, reviews, and small PRs are explicitly welcome without prior assignment when they improve CLI behavior, logs, diagnostics, docs, skills, or integration accessibility. The merge bar for agent-facing changes is [#346](https://github.com/gosuda/portal-tunnel/issues/346).

Every repeated agent instruction is a candidate accessibility bug. Fix the Portal surface and delete the instruction. Do not document another workaround.

Agent usability alone is not a reason to change protocol, cryptography, trust, identity, transport, or architecture semantics. Core changes follow the same repository rules as human contributions. Generic feedback orchestration stays outside this repository ([#331](https://github.com/gosuda/portal-tunnel/issues/331)).