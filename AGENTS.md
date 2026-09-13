# AGENTS.md

Keep this file short and behavioral.
Architecture documentation describes the current architecture. Issues and pull
requests preserve refactoring, migration, and rejected-design history.

## Development Principles

- Minimizing concepts, duplication, and ceremony.
- Do not preserve implementation history in the codebase.
- Prefer a single stable contract with one real owner.
- Prefer local simplicity over premature or speculative abstraction.
- Add indirection only when it removes real coupling or protects a real boundary.
- Tests protect stable public behavior, protocol invariants, and real lifecycle E2E behavior.
- Do not add tests whose only purpose is to preserve an implementation, regression fix, call sequence, log output, retry count, file metadata, or temporary design.
- When a refactor makes an implementation-coupled test obsolete, delete it rather than rewriting it around the new implementation.

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
- Do not create ADRs for refactors, migrations, rejected approaches, or temporary implementation decisions.
- Remove stale or superseded ADRs instead of maintaining them as historical artifacts.

## Verification

- CI commands: `make vet`, `make lint`, `make test`.
- `make tidy` is local maintenance, not a CI requirement.
- Run tests only when explicitly requested.
- If verification seems necessary, ask before running it.
