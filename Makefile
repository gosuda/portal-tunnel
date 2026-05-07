.PHONY: help install fmt vet lint lint-auto test vuln tidy all run build build-frontend build-docs build-tunnel build-server clean load-test

.DEFAULT_GOAL := help

GO_PACKAGES := ./cmd/... ./portal/... ./sdk/... ./types/...
GO_TOOLCHAIN_VERSION := $(shell awk '/^go / { print "go" $$2; exit }' go.mod)
GOIMPORTS_VERSION := v0.41.0
GOLANGCI_LINT_VERSION := v2.11.1
GOVULNCHECK_VERSION := v1.1.4

export GOTOOLCHAIN := $(GO_TOOLCHAIN_VERSION)

help:
	@echo "Available targets:"
	@echo "  make install           - Install Go developer tools used by this repo"
	@echo "  make fmt               - Apply gofmt/goimports"
	@echo "  make lint-auto         - Run autofix lint/format pipeline"
	@echo "  make build             - Build everything (frontend, tunnel, server)"
	@echo "  make build-frontend    - Build React frontend (Tailwind CSS 4)"
	@echo "  make build-docs        - Build documentation site (SvelteKit)"
	@echo "  make build-tunnel      - Build portal-tunnel binaries"
	@echo "  make build-server      - Build Go relay server (frontend built separately)"
	@echo "  make run               - Run relay server"
	@echo "  make clean             - Remove build artifacts"

install:
	go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

fmt:
	gofmt -w .
	goimports -w .

vet:
	go vet $(GO_PACKAGES)

lint:
	golangci-lint run $(GO_PACKAGES)

lint-auto:
	gofmt -w .
	goimports -w .
	golangci-lint run --fix $(GO_PACKAGES)

test:
	go test -v -coverprofile=coverage.out $(GO_PACKAGES)

vuln:
	govulncheck $(GO_PACKAGES)

tidy:
	go get -u ./...
	go mod tidy
	go mod verify

all: fmt vet lint test vuln build

run:
	./bin/relay-server

# Convenience target
build: build-frontend build-tunnel build-server

# Build React frontend with Tailwind CSS 4
build-frontend:
	@echo "[frontend] building React frontend..."
	@mkdir -p cmd/relay-server/dist/app
	@cd frontend && npm i && npm run build
	@echo "[frontend] build complete"

# Build documentation site
build-docs:
	@echo "[docs] building documentation site..."
	@cd docs && bun install --frozen-lockfile && bun run build
	@echo "[docs] build complete"

# Build portal-tunnel binaries for installer distribution
build-tunnel:
	@echo "[tunnel] building portal-tunnel binaries..."
	@mkdir -p cmd/relay-server/dist/tunnel
	@for GOOS in linux darwin windows; do \
		for GOARCH in amd64 arm64; do \
			EXT=""; \
			if [ "$${GOOS}" = "windows" ]; then EXT=".exe"; fi; \
			OUT="cmd/relay-server/dist/tunnel/portal-$${GOOS}-$${GOARCH}$${EXT}"; \
			echo " - $${OUT}"; \
			CGO_ENABLED=0 GOOS=$${GOOS} GOARCH=$${GOARCH} go build -trimpath -ldflags "-s -w" -o "$${OUT}" ./cmd/portal-tunnel; \
		done; \
	done

# Build Go relay server
build-server:
	@echo "[server] building Go portal..."
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/relay-server ./cmd/relay-server

clean:
	rm -rf bin
	rm -rf cmd/relay-server/dist/app
	rm -rf cmd/relay-server/dist/tunnel

# Run the uniformity probe. Extra flags are passed through after the target name:
#   make load-test -- -clients 1000 -relays 5
# GNU make consumes '--' and forwards remaining goals; the catch-all '%:' rule
# below silently absorbs them so make does not error with "no rule to make target."
load-test:
	go run ./cmd/portal-loadtest $(filter-out $@,$(MAKECMDGOALS))

%:
	@:
