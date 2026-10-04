# AGENTS.md

Keep this file short and behavioral.
Architecture documentation should primarily describe the current architecture.
Issues and pull requests preserve short-lived refactoring, migration, and
rejected-design history.

## Development Principles

- Minimize concepts, duplication, and ceremony.
- Do not keep historical artifacts that no longer explain or protect current behavior.
- Prefer a single stable contract with one real owner.
- Prefer local simplicity over premature or speculative abstraction.
- Add indirection only when it removes real coupling or protects a real boundary.
- Before introducing a new mechanism or local subsystem, judge whether the problem is large, repeated, long-lived, or independent enough to justify one. Examples include interfaces, wrappers, helpers, callbacks, hooks, locks, channels, goroutines, registries, caches, shadow state, generation counters, configuration knobs, feature flags, state machines, reconciliation loops, adapters, and extension points. Prefer the existing owner, control flow, data flow, lifecycle, or serialization when they already express the requirement clearly; introduce a new mechanism when the problem itself warrants a durable new concept.
- Do not generalize a one-off problem by default. Generalize when multiple real callers, implementations, lifecycle paths, or an enduring boundary make the broader form useful on its own.
- Tests protect stable public behavior, protocol and security invariants, and real lifecycle E2E behavior.
- Keep a regression test when the regression reveals a contract or invariant that remains important.
- Do not test incidental implementation details such as call sequence, log output, retry count, or file metadata unless they are themselves part of a stable contract.
- When a refactor makes an implementation-coupled test obsolete, delete it if no enduring behavior or invariant would be left unprotected.
- Prefer deterministic unit tests at the lowest coherent owner, or real black-box E2E tests in `e2e/`; do not add middle-layer tests that assemble several subsystems with fake transports or callbacks to inspect internal state.
- Never add a production callback, interface, config knob, wrapper, synchronization primitive, or injection seam only to make a test possible.
- When a regression crosses components, protect the enduring invariant in its lowest owner; otherwise assert the real behavior in `e2e/`.

## Project Principles

- When caller and callee are both local and no real boundary exists, change both directly; do not preserve local call shapes.
- If a field, method, wrapper, or abstraction has no clear, current use and does not protect a real boundary, remove it immediately.
- No wrapper functions or helpers unless they remove real coupling, protect a real boundary, or represent independently meaningful behavior.
- Prefer changing existing code directly when the change remains local; introduce a new abstraction when the responsibility is substantial enough to deserve an owner of its own.
- Prefer direct code over layers, facades, and indirection when the extra structure would outgrow the problem it solves.
- Prefer existing ownership and serialization over adding synchronization unless concurrency itself is part of the problem being modeled.
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
