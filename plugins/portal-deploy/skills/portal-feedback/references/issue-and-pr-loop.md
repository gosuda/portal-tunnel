# Issue and PR loop

This reference owns Portal feedback state transitions, approval, publication, implementation, and closure. Evidence packet construction stays in `plugins/portal-deploy/skills/portal-expose/references/feedback-evidence.md`.

## State root and locks

Resolve the state root by platform:

```text
Linux:   $XDG_STATE_HOME/portal-feedback, else ~/.local/state/portal-feedback
macOS:   ~/Library/Application Support/Portal Feedback
Windows: %LOCALAPPDATA%\Portal Feedback
```

Use `runs/<run-id>/<packet-id>.json`, `findings/<finding-id>.json`, `verifications/<finding-id>/<attempt-id>.json`, and `locks/<finding-id>.lock`. Reject symlinks below the root. On POSIX, use `0700` directories and `0600` files. Write JSON through a flushed sibling temporary file and atomic rename.

Before mutating a finding, exclusively create its lock with `pid`, `hostname`, `acquired_at`, UUIDv4 `nonce`, and nullable `host_session_id`. Replace a same-host lock older than 15 minutes only when its PID is absent. Replace a different-host lock after 15 minutes because this implementation has no remote worker. Record replaced nonces.

## Retention

Run cleanup at the beginning and end of `inbox` and `purge-expired`.

- Delete unpromoted packets 30 days after `ended_at`.
- Delete rejected findings and packets 30 days after rejection.
- Delete deferred findings 30 days after `due_at`.
- Retain every sanitized packet for at most 30 days after `ended_at`, regardless of finding state.
- After packet expiry, retain only finding metadata, packet digests, public GitHub URLs, release data, and closure metrics for one year after closure.
- Keep regressed finding metadata under the same one-year rule until resolved again.

Invalid or future timestamps block deletion and move the finding to `needs_review`. Retained evidence packets stay immutable; cleanup deletes whole expired packets.

## Correlate packets

Validate each packet against `evidence-packet.schema.json` plus byte-length, timestamp-order, UUID-version, immutable-source, and secret checks. Invalid packets do not correlate.

Normalize mechanism fields in this order:

1. home prefix to `<home>`;
2. canonical UUID to `<uuid>`;
3. semantic version to `<version>`;
4. long hexadecimal identifiers to `<hex>`;
5. URL and dotted DNS hostnames to `<host>`;
6. ports to `<port>`;
7. lowercase ASCII, collapse whitespace, and trim surrounding punctuation.

Keep named error codes and source symbols. Join component, operation, error or expectation, corrective action, and source symbol or contract with newlines. SHA-256 the UTF-8 signature; the full lowercase digest is `finding_id`.

Keep votes only in `evidence[]` and derive unique voting run IDs at read time. One real run votes once per finding. Replay attempts never vote. Promote:

- `defect`: one voting real packet with immutable source cause and valid deterministic qualification;
- `ux-friction`: two voting real packets with different run IDs from different user tasks;
- `needs-review`: never automatically.

Reclassification updates finding assessment fields. Evidence packets remain immutable.

## Duplicate search

Search `gosuda/portal-tunnel` issues in all states and PRs in open, closed, and merged states. Run three independent query classes: normalized error text, command plus violated expectation, and source symbol plus component. Follow pagination to exhaustion. A provider cap, truncation, authentication error, rate limit, or outage makes the result incomplete and blocks promotion.

A duplicate shares the causal mechanism, not only the symptom. An unresolved match prepares a contribution brief. For a closed issue claiming a fix, identify its merge and containing release. A recurrence on a later containing version is a regression; otherwise link the existing result and stop.

## Persist and present the brief

Serialize digests with RFC 8785 JSON Canonicalization Scheme and SHA-256.

The complete brief contains title, summary, expected and actual behavior, acceptance boundary, implementation scope, packet digests, immutable sources, duplicate result, risk, and proposed public actions. Its hash is `brief_revision_digest`.

The authorization object contains mechanism digest, expected behavior, acceptance boundary, code or documentation scope, risk, duplicate target, and proposed public actions. Its hash is `scope_digest`. Citation and prose repairs do not change scope. A changed target, behavior, boundary, risk, scope, or public action does.

Persist before asking. Present:

```text
Finding
Impact
Evidence
Duplicate search
Expected vs actual
Proposed scope
Autonomous fix eligibility
Public actions

Approve | Reject | Defer
```

Use the host single-select question UI. Plain text counts only when it names the finding and action. Approval authorizes the listed issue or contribution, one low-risk implementation and PR inside scope, and review fixes inside scope. It does not authorize merge, comments, reopening, or scope expansion.

Before any public mutation, require an `approve` history entry whose `scope_digest` equals the current finding scope. Its `brief_revision_digest` must match the brief presented at approval time. Later citation- or prose-only revisions may differ only after an audit proves the scope digest unchanged. Restricted implementation additionally requires a matching `approve_implementation` entry with the current implementation scope digest.

For no-match restricted findings, the initial brief may authorize only issue creation. A later implementation checkpoint authorizes the PR as a separate public action after the restricted diff is reviewed.

## Issue gate and recovery

Before issue creation, rerun duplicate search and open every cited source at its immutable revision. The body uses `Summary`, `Reproduction`, `Evidence`, `Expected vs actual`, and `Scope`.

All six gates must pass:

1. Every factual claim has an immutable citation or is labeled as an observed reproduction.
2. The report describes a concrete defect or repeatable UX contract failure, not a preference.
3. A defect names its causal source mechanism; UX friction names the violated expectation and repeated corrective action.
4. Duplicate search completed with no match.
5. The title states the observed problem, not a proposed fix.
6. Every cited source was opened at the cited revision.

Add this marker to issue and PR bodies:

```html
<!-- portal-feedback:finding=<finding-id>;scope=<scope-digest> -->
```

Before retrying issue publication, search by repository and marker. Before retrying PR publication, search by marker and exact branch. Read back repository, artifact type, marker, title, scope digest, and URL. Recover an existing artifact instead of creating another.

## Implementation boundary

Autonomous work is limited to CLI output, documentation and skills, installer and OS-service generation, bounded configuration parsing and validation, and read-only status reporting.

Security, authentication, identity, signing, TLS, ECH, MITM policy, secrets, relay protocol, leases, x402, payments, persistent data formats, migrations, backward incompatibility, and every other category require an implementation checkpoint.

The checkpoint shows changed authorization scope, restricted areas, proposed tests, and public action. Approval authorizes implementation and PR under the new digest. Hand off or rejection moves to `maintainer_queue`.

A supported regression seam is an existing public CLI, config parser, generated artifact, skill trigger case, or documented API contract. Documentation and skill-only work uses positive and negative fixtures plus the skill validator. Without a supported seam, stop at `maintainer_queue`.

On Windows without a POSIX Portal checkout, stop at `maintainer_queue` with `posix_handoff_required`. Do not transfer local state automatically.

## Implement and publish the PR

Use a clean `gosuda/portal-tunnel` checkout and its current remote default branch. Create an isolated worktree and branch `portal-feedback/<finding-id>-<short-slug>`.

1. Pin issue URL, base revision, scope digest, and acceptance boundary.
2. Add the regression and observe red.
3. Apply the smallest fix and observe green.
4. Run affected checks and applicable current-OS CI commands that need no secret, privileged runner, or hosted service.
5. Replay the original scenario and write a `patched_replay` verification attempt.
6. Store attempt ID, record digest, and successful replay metrics before moving to `waiting_real_use`.
7. Push only after local gates pass; set `pr_publication_pending`.
8. Create and read back the PR before setting `pr_filed`.
9. Apply review feedback inside scope. Rerun checks and write `post_review` verification after relevant edits.

Hosted-only CI remains required. One clean rerun may classify a flaky failure. Restricted review changes return to the checkpoint. Maintainers merge.

## Track release and close

At `inbox`, inspect filed PRs and merged findings. Record maintainer merge SHA. Peel annotated release tags and prove containment with merge ancestry. A runner qualifies only when `portal version` maps unambiguously to a containing release tag.

The requested-outcome class is the RFC 8785 SHA-256 digest of `{"operation":"<enum>","mode":"<enum>","contracts":[{"kind":"<validation kind>","contract_code":"<contract code>"}]}`. Deduplicate contracts and sort by kind then contract code. Free-text summaries do not enter it.

A matching real use requires the same class, containing runner release, every validation passing, the original signal absent, no correction, no state mismatch, and no more diagnostic commands than patched replay.

### Internal `evaluate-closure`

`portal-expose` calls this procedure with a sanitized successful in-memory trace. Compute its requested-outcome class, find `waiting_real_use` records with that class, and sort by finding ID. For each finding, prove release containment and every closure condition. If any check fails, write nothing for that finding. Otherwise write one `real_use` verification attempt, validate its finding ID, kind, outcome class, digest, successful metrics, and tag ancestry, store attempt ID and record digest, then atomically move the finding to `closed`.

Patched replay cannot close. A recurrence moves to `regressed`. Reopening or commenting requires a new brief with `reopen_issue` or `comment_issue`, a new scope digest, and explicit approval.

## State transitions

| Current state | Operation | Required guard | Next state |
| --- | --- | --- | --- |
| `candidate` | correlate | promotion and duplicate search complete | `awaiting_approval` |
| `needs_review` | review | new source or contract evidence | `candidate` or `needs_review` |
| `awaiting_approval` | approve | current brief and scope digest | `approved` |
| `awaiting_approval` | reject | bounded reason | `rejected` |
| `awaiting_approval` | defer | future `due_at` | `deferred` |
| `deferred` | due | current time at or after `due_at` | `awaiting_approval` |
| `approved` | stage issue publication | approval and duplicate guard | `publication_pending` |
| `publication_pending` | publish issue | issue marker read-back | `issue_filed` or `linked_existing` |
| `issue_filed` or `linked_existing` | implement | low-risk scope | `implementing` |
| `issue_filed` or `linked_existing` | checkpoint | restricted or expanded scope | `implementation_checkpoint` |
| `implementation_checkpoint` | approve-implementation | matching implementation approval | `implementing` |
| `implementation_checkpoint` | handoff or reject-implementation | explicit operator action | `maintainer_queue` |
| `implementing` | push | regression, checks, and patched replay pass | `pr_publication_pending` |
| `pr_publication_pending` | publish | PR marker read-back | `pr_filed` |
| `pr_filed` | merge | maintainer merge recorded | `merged_waiting_release` |
| `merged_waiting_release` | release | merge is ancestor of release tag | `waiting_real_use` |
| `waiting_real_use` | evaluate-closure | qualifying real-use verification | `closed` |
| `waiting_real_use` or `closed` | recurrence | new brief required for public action | `regressed` |
| any active state | blocked | external transient failure; preserve resume state | `blocked` |
| `blocked` | retry | stored resume state and its guards | stored resume state |

Any mutation not in this table is invalid and leaves the finding unchanged. While `blocked`, validate every invariant of `resume_state`; blocking suspends an operation but never erases its approval, artifact identity, or verification proof.

## Operator behavior

- `inbox`: retention, packet ingestion, due-state advancement, blocked inspection without retry, PR/release refresh, then due listing. No public mutation.
- `retry`: recover a remote marker, then attempt the stored resume state once.
- `replay`: create a new attempt ID and execute the scenario.
- `status`: no state transition.
- `defer`: default seven days; deferred items do not block newer work.
- invalid-state mutation: no change; report allowed transitions.

## Skill trigger fixtures

Positive:

- Review the Portal friction recorded by my last tunnel attempt.
- Show the Portal feedback inbox.
- Approve finding `<id>` and carry the low-risk fix through a PR.
- Retry the blocked Portal feedback publication.
- Replay finding `<id>` against the patch.

Negative:

- Expose this app through Portal.
- Start a persistent Portal tunnel.
- Run a Portal relay.
- Explain the last Portal error without creating an upstream artifact.
