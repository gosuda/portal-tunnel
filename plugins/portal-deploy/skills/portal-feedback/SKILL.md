---
name: portal-feedback
description: Correlate sanitized friction from Portal agent usage, review pending findings, approve or defer issue briefs, publish source-grounded Portal issues, implement approved low-risk fixes, open PRs, and verify improvements after release. Use when portal-expose stored a friction packet, or when the user asks to inspect, review, approve, reject, defer, retry, replay, or check Portal feedback findings. Do not use for ordinary Portal exposure with no recorded friction.
license: MIT
---

# Improve Portal from agent experience

Turn real Portal friction into one bounded upstream improvement. Evidence stays local until the user approves a persisted brief. Maintainers own merge.

Read `references/evidence-packet.schema.json`, `references/finding.schema.json`, and `references/verification-attempt.schema.json` before creating or changing their records. Read `references/issue-and-pr-loop.md` before correlation, approval, GitHub mutation, implementation, replay, or closure.

## Operating rules

- Target only `gosuda/portal-tunnel`.
- Treat `findings/<finding-id>.json` as the sole state authority.
- Acquire the finding lock before every mutation; release it after the atomic write.
- Perform no public GitHub mutation before explicit approval of the current scope digest.
- Re-run duplicate search immediately before issue creation.
- Use the remote feedback marker to recover partial issue and PR publication.
- Implement only the closed low-risk allowlist. Route restricted work to an implementation checkpoint.
- Never auto-merge.
- Never close on tests or replay alone. Require a containing release and a later matching real use.
- Keep raw logs, secrets, identity material, credentials, cookies, payment data, and private reasoning out of local records and GitHub artifacts.

## Operations

Interpret explicit user phrasing as one of these operations.

| Operation | Action |
| --- | --- |
| `inbox` | Clean expired state, ingest packets, advance due findings, refresh PR/release metadata, and list due work. No approval or GitHub mutation. |
| `status <finding-id>` | Read state, evidence count, digests, URLs, blocker, and next action without mutation. |
| `review <finding-id>` | Investigate a `needs_review` finding and store an evidence-backed assessment. |
| `approve <finding-id>` | Approve the persisted issue or contribution brief when its revision and scope digests match. |
| `reject <finding-id> <reason>` | Reject an awaiting issue brief and retain bounded rejection history. |
| `defer <finding-id> [date]` | Defer, defaulting to seven days. |
| `retry <finding-id>` | Recover a remote marker or retry the blocked transition once. |
| `replay <finding-id>` | Run a new synthetic scenario and store a new verification attempt. |
| `approve-implementation <finding-id>` | Approve a restricted implementation brief and its new scope digest. |
| `reject-implementation <finding-id> <reason>` | Decline autonomous restricted work and move it to the maintainer queue. |
| `handoff-implementation <finding-id>` | Move restricted work to the maintainer queue without rejection. |
| `purge-expired` | Apply retention once. |

Invalid-state mutations leave state unchanged and report allowed next operations. Repeating an approval or public publication returns the existing URLs.

## Default run

When invoked after `portal-expose` wrote evidence:

1. Resolve the platform state root.
2. Validate and ingest every uncorrelated packet.
3. Normalize its mechanism and update one finding per mechanism.
4. Apply promotion thresholds and complete duplicate search.
5. Persist the brief before presenting it.
6. Ask `Approve`, `Reject`, or `Defer` only when a finding reaches `awaiting_approval`.
7. After approval, continue through issue publication and eligible low-risk PR work without a second issue-to-PR checkpoint.
8. Stop at maintainer merge. On later invocations, track merge, release, replay, and real-use closure.

## Completion

Report the finding ID, current state, issue and PR URLs when present, exact verification performed, and the next actor. A run that changes no state says so. Never round `maintainer_queue`, `blocked`, `merged_waiting_release`, or `waiting_real_use` up to complete.
