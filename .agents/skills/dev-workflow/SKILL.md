---
name: dev-workflow
description: Build, lint, test, and verification workflow for the portal-tunnel Go+frontend monorepo. Use when setting up the repo, running CI-equivalent checks, or before committing changes.
---

# portal-tunnel dev workflow

## Toolchain
- Go pinned to `go1.26.4` via `go.mod`; the Makefile exports `GOTOOLCHAIN=go1.26.4`, so `make` targets self-pin even on other Go installs.
- `make install` installs the pinned dev tools: `goimports@v0.41.0` and `golangci-lint@v2.11.1` (into `$(go env GOPATH)/bin`, usually `~/go/bin` — put it on PATH).
- Frontend build/test needs Node 22+.
- `bun` is needed only for `make build-docs`.

## Verification (CI commands, from AGENTS.md)
Run these three before pushing; they are what CI enforces:
```
make vet     # go vet ./cmd/... ./portal/... ./sdk/... ./types/... ./utils/...
make lint    # golangci-lint run (same package set)
make test    # go test -coverprofile=coverage.out (same set) + `cd frontend && npm test` (vitest)
```
Per AGENTS.md, run tests only when needed/asked; `make tidy` is local maintenance, not a CI gate.

## Pre-commit hooks
`.pre-commit-config.yaml` runs whitespace/EOL/BOM fixers, golangci-lint (config-verify, `--new-from-rev HEAD --fix`, and full `--fix`), plus local `make fmt` and `go vet ./...`.
- `make fmt` runs `gofmt -w .` then `goimports -w .`, so `goimports` MUST be on PATH or the commit hook fails with `goimports: No such file or directory` — run `make install` first.
- Note the golangci-lint version differs between pre-commit (`v2.10.1`) and the Makefile (`v2.11.1`); expect minor lint-behavior drift.

## Build
- `make build` → `build-tunnel` + `build-server` (full artifacts).
- `make build-frontend` builds the SPA (`cd frontend && npm ci && npm run build`) and copies `frontend/dist/.` into `cmd/relay-server/dist/app` (embedded by the relay via `//go:embed dist/*`).
- `make build-server-bin` compiles only `bin/relay-server`; it assumes `dist/app` already exists (use after `build-frontend`, or the binary fails at startup asking you to run `make build-frontend`).
- `make build-tunnel` cross-compiles `cmd/portal-tunnel` for linux/darwin/windows × amd64/arm64.
- Shared Go build flags live in the Makefile var `GO_BUILD_FLAGS` (`-trimpath -ldflags "-s -w"`); the Dockerfile calls `make build-server-bin` rather than duplicating them.

## Making changes (AGENTS.md conventions — enforce in review)
- Shared contracts, constants, and **public path strings** belong in `types/` (e.g. `types/paths.go`), never duplicated in runtime/helpers.
- Stateless shared transforms go in `utils/`; stateful/domain logic stays with its real owner (`sdk/` or `portal/`).
- Prefer one owner per contract; no speculative abstraction, wrappers, or dead fields — remove them while touching nearby code.
