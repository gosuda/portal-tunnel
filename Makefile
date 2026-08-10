.PHONY: help install fmt vet lint lint-auto test tidy all run build build-frontend build-docs build-tunnel build-server build-server-bin clean load-test check-env-example env-reference

.DEFAULT_GOAL := help

GO_PACKAGES := ./cmd/... ./portal/... ./sdk/... ./types/... ./utils/...
GO_BUILD_FLAGS := -trimpath -ldflags "-s -w"
GO_TOOLCHAIN_VERSION := $(shell awk '/^go / { print "go" $$2; exit }' go.mod)
GOIMPORTS_VERSION := v0.41.0
GOLANGCI_LINT_VERSION := v2.11.1

export GOTOOLCHAIN := $(GO_TOOLCHAIN_VERSION)

help:
	@echo "Available targets:"
	@echo "  make install           - Install Go developer tools used by this repo"
	@echo "  make fmt               - Apply gofmt/goimports"
	@echo "  make lint-auto         - Run autofix lint/format pipeline"
	@echo "  make test              - Run Go and frontend tests"
	@echo "  make check-env-example - Fail if .env.example is missing a configuration key"
	@echo "  make env-reference     - Print every configuration key, generated from the flags"
	@echo "  make build             - Build Go tunnel and relay server artifacts"
	@echo "  make build-frontend    - Build React frontend (Tailwind CSS 4)"
	@echo "  make build-docs        - Build documentation site (SvelteKit)"
	@echo "  make build-tunnel      - Build portal-tunnel binaries"
	@echo "  make build-server      - Build Go relay server"
	@echo "  make run               - Run relay server"
	@echo "  make clean             - Remove build artifacts"

install:
	go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

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
	cd frontend && npm test

tidy:
	go get -u ./...
	go mod tidy
	go mod verify

# The keys themselves are owned by the flag definitions in
# cmd/relay-server/main.go and by the catalog of keys other components read.
# .env.example and the configuration reference are documentation of that set.
# Adding a flag without documenting it is how configuration drifts away from the
# code, so fail loudly here rather than let an operator find the gap in
# production. Keys the bundled topology pins are excluded on purpose; see
# cmd/relay-server/envcatalog.go.
CONFIG_DOC := docs/src/routes/configuration/+page.md

check-env-example:
	@go run ./cmd/relay-server config --format names > /tmp/portal-env-names.txt
	@status=0; \
	missing=""; \
	while read -r name; do \
		grep -qE "^#? *$$name=" .env.example || missing="$$missing $$name"; \
	done < /tmp/portal-env-names.txt; \
	if [ -n "$$missing" ]; then \
		echo "[env] .env.example does not document:"; \
		for name in $$missing; do echo "  - $$name"; done; \
		status=1; \
	fi; \
	missing=""; \
	while read -r name; do \
		grep -qF "\`$$name\`" $(CONFIG_DOC) || missing="$$missing $$name"; \
	done < /tmp/portal-env-names.txt; \
	if [ -n "$$missing" ]; then \
		echo "[env] $(CONFIG_DOC) does not document:"; \
		for name in $$missing; do echo "  - $$name"; done; \
		status=1; \
	fi; \
	if [ "$$status" -ne 0 ]; then \
		echo "[env] run 'make env-reference' to see each key with its usage text"; \
		exit 1; \
	fi; \
	echo "[env] .env.example and $(CONFIG_DOC) document every configuration key"

env-reference:
	@go run ./cmd/relay-server config --format env

all: fmt vet lint test build

run:
	./bin/relay-server

# Convenience target
build: build-tunnel build-server

# Build React frontend with Tailwind CSS 4
build-frontend:
	@echo "[frontend] building React frontend..."
	@cd frontend && npm ci && npm run build
	@rm -rf cmd/relay-server/dist/app
	@mkdir -p cmd/relay-server/dist/app
	@cp -R frontend/dist/. cmd/relay-server/dist/app/
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
			CGO_ENABLED=0 GOOS=$${GOOS} GOARCH=$${GOARCH} go build $(GO_BUILD_FLAGS) -o "$${OUT}" ./cmd/portal-tunnel; \
		done; \
	done

# Build Go relay server
build-server: build-frontend build-server-bin

# Binary only; assumes frontend assets already exist in cmd/relay-server/dist/app.
build-server-bin:
	@echo "[server] building Go portal..."
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -o bin/relay-server ./cmd/relay-server

clean:
	rm -rf bin
	rm -rf cmd/relay-server/dist/tunnel
	rm -rf cmd/relay-server/dist/app
	rm -rf frontend/dist

# Run the uniformity probe. Extra flags are passed through after the target name:
#   make load-test -- -clients 1000 -relays 5
# GNU make consumes '--' and forwards remaining goals; the catch-all '%:' rule
# below silently absorbs them so make does not error with "no rule to make target."
load-test:
	go run ./cmd/portal-loadtest $(filter-out $@,$(MAKECMDGOALS))

%:
	@:
