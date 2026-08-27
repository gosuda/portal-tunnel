# Feedback evidence

Use this reference only for Portal operations performed through `portal-expose`. It records friction locally without adding telemetry to Portal or retaining normal successful runs.

## Start an experience run

At the first Portal-specific action in the user task, generate one lowercase UUIDv4 `run_id`. Keep one in-memory trace through the final public verification or terminal failure. Retries and diagnostics in the same user task keep the same run ID.

Record only Portal-related top-level actions:

- sanitized argv;
- UTC start and end time;
- duration;
- termination: `exited`, `timeout`, `signal`, or `not_started`;
- nullable exit code and signal;
- the shortest stdout/stderr summaries that prove an observation;
- expected and observed validation results.

Never record private reasoning, environment-variable values, identity contents, signed payloads, credentials, cookies, payment secrets, or unrelated repository and browser data.

## Detect friction

Create evidence only when at least one signal applies.

- `objective_failure`: a documented Portal command fails, times out, is killed, never starts, leaves a required service inactive, or fails the requested public validation.
- `state_mismatch`: Portal reports a ready tenant URL but its external check fails, or a stable restart changes the URL despite reusing the requested name, identity, and relay root.
- `user_correction`: the user says a delivered result or an assumption already acted on was wrong. A new requirement after a correct handoff is a new task, not a correction.
- `excess_diagnosis`: after the first failed validation, at least three unplanned top-level diagnostic invocations are needed. Do not count the selected branch's local probe, Portal command, public probe, or prescribed source reads. One pipeline or internally retried command counts once.

HTTP validation contracts:

| Situation | Contract code | Pass condition |
| --- | --- | --- |
| Ordinary public app | `http_200_399` | `200..399` |
| App known locally to require authentication | `http_auth_401` or `http_auth_403` | matching status |
| Unpaid protected x402 method | `http_x402_402` | `402` and matching challenge fields |
| Managed service | `service_active` | service manager reports active |
| Stable restart | `hostname_stable` and `identity_reused` | same expected URL and identity |
| Raw transport | `protocol_nonmutating` | selected protocol probe succeeds |

## Split and classify

One run may produce several packets only when observations have different causal mechanisms. Give each packet a new UUIDv4 `packet_id`; one run can vote once per finding.

Classify as `defect` only when the minimal command reproduces twice in the run, or a static artifact deterministically violates its consumer's contract, and an immutable Portal source reference identifies the cause. The reference includes `gosuda/portal-tunnel`, commit SHA, path or contract section, line range when applicable, and commit-pinned URL. Store `defect_qualification.method` as `reproduced_command` with a count of at least two, or `static_contract_violation` with a count of one.

Classify reproducible ambiguity, poor defaults, extra-step cost, and user correction without a deterministic source mechanism as `ux-friction`. Otherwise use `needs-review`. When Portal could not run, store `portal_version: null`; never invent a version.

## Sanitize and persist

Resolve the state root:

```text
Linux:   $XDG_STATE_HOME/portal-feedback, else ~/.local/state/portal-feedback
macOS:   ~/Library/Application Support/Portal Feedback
Windows: %LOCALAPPDATA%\Portal Feedback
```

Write packets to `runs/<run-id>/<packet-id>.json` using the repository-relative schema `plugins/portal-deploy/skills/portal-feedback/references/evidence-packet.schema.json`.

Before writing:

1. Collapse summary whitespace and enforce schema bounds.
2. Replace the current home prefix with `$HOME`.
3. Remove URL query strings and authorization/cookie header values.
4. Redact values following names containing `token`, `secret`, `password`, `private-key`, `identity-json`, `api-key`, or `facilitator-token`, including environment assignment and `--flag=value` forms.
5. Run the host secret scanner when available, then always scan case-insensitively for `-----BEGIN .* PRIVATE KEY-----`, `Authorization: Bearer`, `github_pat_`, `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `AKIA[0-9A-Z]{16}`, and the acceptance fixture `github_pat_TEST_SECRET`.
6. Reject the packet if any possible secret remains. Keep no rejected artifact.
7. Reject symlinks below the state root. On POSIX, create directories as `0700` and files as `0600`.
8. Write a sibling temporary file, flush it, and atomically rename it.

After persistence, run the `portal-feedback` correlation procedure in the same conversation. If the task is ending, leave the packet for the next `portal-feedback inbox` invocation.

## Successful runs and closure

A successful run normally persists nothing. Before discarding it, inspect local findings for `waiting_real_use` records with the same requested-outcome class. If candidates exist, invoke the internal `portal-feedback evaluate-closure` procedure with the sanitized in-memory trace. It writes one `real_use` verification attempt per qualifying finding. A replay or ordinary success never casts a promotion vote.

When no closure candidate exists, retain the sanitized trace only in the active conversation until the user's next response. If that response corrects the delivered Portal result or an assumption already acted on, create a `user_correction` packet under the same run ID. If the response accepts the result, changes requirements, or starts unrelated work, discard the trace without writing.

## Feedback failure

Feedback capture is secondary to the requested Portal operation. If redaction, schema validation, locking, or writing fails, preserve the user's Portal result and report the feedback failure separately. Never weaken redaction to save a packet.
