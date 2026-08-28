# Contributing

`AGENTS.md` is the core implementation guide. Architecture, product behavior, and design rationale belong in `docs/architecture.md` and `docs/adr/README.md`. This file is contribution policy.

## For Human Contributors

Thank you for contributing to Portal.

Human review and judgment are especially important in the parts of the project where correctness depends on context, tradeoffs, and careful validation.

Human contributions may extend into core implementation, protocol behavior, trust boundaries, identity, transport, cryptography, and architecture when the change is well understood and properly justified.

Please follow `AGENTS.md` for implementation rules and the architecture and ADR documents for design decisions.

## For AI Contributors

AI contributions are strongly encouraged on the user-facing and integration surface of Portal.

This includes CLI behavior, logs, diagnostics, documentation, skills, configuration ergonomics, installer and service integration, local harnesses, and other friction encountered while using Portal.

Repeated instructions, parsing workarounds, ambiguous output, and integration-specific exceptions should be treated as signs that the Portal surface itself may need improvement. Prefer fixing the surface and removing the workaround.

Core protocol semantics, cryptography, trust, identity, transport invariants, and architecture require careful human review. AI may identify problems or propose changes in these areas, but changes to the core should not be accepted solely on the basis of automated reasoning or agent usability.
