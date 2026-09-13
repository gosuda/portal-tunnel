# AGENTS.md

Keep this file short and behavioral.
Architecture documentation should primarily describe the current architecture.
Issues and pull requests preserve short-lived refactoring, migration, and
rejected-design history.

## Development Principles

- Minimizing concepts, duplication, and ceremony.
- Do not keep historical artifacts that no longer explain or protect current behavior.
- Prefer a single stable contract with one real owner.
- Prefer local simplicity over premature or speculative abstraction.
- Add indirection only when it removes real coupling or protects a real boundary.
- Tests protect stable public behavior, protocol and security invariants, and real lifecycle E2E behavior.
- Keep a regression test when the regression reveals a contract or invariant that remains important.
- Do not test incidental implementation details such as call sequence, log output, retry count, or file metadata unless they are themselves part of a stable contract.
- When a refactor makes an implementation-coupled test obsolete, delete it if no enduring behavior or invariant would be left unprotected.

## Project Principles

- When caller and callee are both local and no real boundary exists, change both directly; do not preserve local call shapes.
- If a field, method, wrapper, or abstraction has no clear, current use and does not protect a real boundary, remove it immediately.
- No wrapper functions or helpers unless they remove real coupling or protect a real boundary.
- Prefer direct code over layers, facades, and indirection.
- Prefer flattening and merging nearby responsibilities over splitting by default.
- Remove dead fields, methods, config, and stale state while touching nearby code.
- Do not duplicate normalization, validation, or defaulting logic; keep it in a single real owner.
- Keep shared stateless transforms in `utils/`; keep stateful and domain-shaped logic with the real owner.
- Keep stable shared contracts, constants, and public paths in `types/`, not in runtime or helpers.
- Resolve complexity in the lowest coherent owner and expose only the minimum surface upward.
- Shared runtime logic must live in one real owner and be reused, not mirrored.
- Use ADRs sparingly for stable, long-lived architecture or compatibility decisions.
- Keep ordinary refactors, migrations, rejected approaches, and temporary implementation decisions in issues and pull requests unless they are needed to understand current operational compatibility.
- Remove stale or superseded documentation that no longer helps explain the current system or its supported compatibility constraints.

## Verification

- CI commands: `make vet`, `make lint`, `make test`.
- `make tidy` is local maintenance, not a CI requirement.
- Run tests only when explicitly requested.
- If verification seems necessary, ask before running it.
