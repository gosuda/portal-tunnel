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
- Tests protect stable behavior, not refactor intermediates; apply the Test Selection section before adding or requesting one.

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

## Test Selection

Regression tests protect stable behavior, not intermediate implementations discovered during refactoring. Before adding a test, or requesting one in review, classify it:

1. What stable contract or invariant does this protect?
2. Which package actually owns that behavior?
3. Is the same behavior already covered at a more appropriate boundary?
4. Would this test still be valuable if the implementation were reorganized tomorrow?

If those questions do not produce a clear stable contract, fix the code without adding a permanent test.

Keep or add tests that protect exported API contracts, wire/protocol compatibility, security invariants, data integrity and persistence correctness, lifecycle guarantees callers rely on, real production bugs that could plausibly recur, and end-to-end behavior across a stable boundary.

Be conservative about tests for internal helper placement, package ownership decisions still in motion, config forwarding or assembly already covered by the owning package, duplicated diagnostics or policy assertions across layers, temporary refactor adapters, exact internal call structure or orchestration sequence that is not externally observable, and regression scenarios invented only because the current change touched that implementation.

Put each test in the package that owns the behavior and name the protected contract in a short doc comment. Do not request a test that merely proves a mechanical move, rename, or ownership transfer happened correctly when compile checks, owner-package tests, or integration coverage already protect the behavior; when a refactor makes an implementation-coupled test obsolete, delete it if no enduring behavior would be left unprotected.

## Verification

- CI commands: `make vet`, `make lint`, `make test`.
- `make tidy` is local maintenance, not a CI requirement.
- Run tests only when explicitly requested.
- If verification seems necessary, ask before running it.
