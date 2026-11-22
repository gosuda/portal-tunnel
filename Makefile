.PHONY: help install install-lint install-ggui fmt vet lint lint-auto test test-unit test-go-unit test-e2e tidy all run build build-frontend build-docs build-tunnel build-desktop build-wasm build-server build-server-bin clean check-env-example check-charts env-reference

.DEFAULT_GOAL := help

GO_PACKAGES := . ./cmd/... ./e2e/... ./portal/... ./sdk/... ./types/... ./utils/...
GO_UNIT_PACKAGES := . ./cmd/... ./portal/... ./sdk/... ./types/... ./utils/...
GO_BUILD_FLAGS := -trimpath -ldflags "-s -w"
GO_TOOLCHAIN_VERSION := $(shell awk '/^go / { print "go" $$2; exit }' go.mod)
GOIMPORTS_VERSION := v0.52.0
GOLANGCI_LINT_VERSION := v2.15.0
GOIMPORTS_LOCAL := github.com/gosuda/portal-tunnel/v2
# Portal Desktop is a Go module of its own, so its GUI dependencies stay out of
# the module the CLI, SDK and relay build from. The Go targets cover it too.
DESKTOP_DIR := cmd/portal-desktop
DESKTOP_OUT := bin/desktop
GGUI_COMMAND_VERSION := v0.7.5

export GOTOOLCHAIN := $(GO_TOOLCHAIN_VERSION)

help:
	@echo "Available targets:"
	@echo "  make install           - Install Go developer tools used by this repo"
	@echo "  make lint              - Run golangci-lint"
	@echo "  make fmt               - Apply gofmt/goimports"
	@echo "  make lint-auto         - Run autofix lint/format pipeline"
	@echo "  make test              - Run Go and frontend tests"
	@echo "  make check-env-example - Fail if .env.example is missing a configuration key"
	@echo "  make check-charts      - Lint the Helm charts and validate the Kubernetes examples"
	@echo "  make env-reference     - Print every configuration key, generated from the flags"
	@echo "  make build             - Build Go tunnel and relay server artifacts"
	@echo "  make build-frontend    - Build React frontend (Tailwind CSS 4)"
	@echo "  make build-docs        - Build documentation site (SvelteKit)"
	@echo "  make build-tunnel      - Build portal-tunnel binaries"
	@echo "  make build-desktop     - Build Portal Desktop release packages (needs make install-ggui)"
	@echo "  make build-wasm        - Build portal-tunnel WebAssembly client"
	@echo "  make build-server      - Build Go relay server"
	@echo "  make run               - Run relay server"
	@echo "  make clean             - Remove build artifacts"

install: install-lint
	go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)

install-lint:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

install-ggui:
	go install github.com/ironpark/ggui/cmd/ggui@$(GGUI_COMMAND_VERSION)

fmt:
	gofmt -w .
	goimports -local $(GOIMPORTS_LOCAL) -w .

vet:
	go vet $(GO_PACKAGES)
	cd $(DESKTOP_DIR) && go vet ./...

lint:
	golangci-lint run $(GO_PACKAGES)
	cd $(DESKTOP_DIR) && golangci-lint run ./...

lint-auto:
	gofmt -w .
	goimports -local $(GOIMPORTS_LOCAL) -w .
	golangci-lint run --fix $(GO_PACKAGES)
	cd $(DESKTOP_DIR) && golangci-lint run --fix ./...

# ggui_debug makes a Probe panic on a state write from the wrong goroutine.
test:
	go test -v -coverprofile=coverage.out $(GO_PACKAGES)
	cd $(DESKTOP_DIR) && go test -tags ggui_debug ./...
	cd frontend && npm test

test-unit: test-go-unit
	cd frontend && npm test

test-go-unit:
	go test -v -coverprofile=coverage.out $(GO_UNIT_PACKAGES)
	cd $(DESKTOP_DIR) && go test -tags ggui_debug ./...

test-e2e:
	go test -count=1 -v ./e2e/...

tidy:
	go get -u ./...
	go mod tidy
	go mod verify
	cd $(DESKTOP_DIR) && go get -u ./... && go mod tidy && go mod verify

# Relay keys are owned by the flag definitions in cmd/relay-server/main.go.
# This deployment check excludes listener values fixed directly by the bundled
# Compose topology; that topology, not the relay binary, owns the exception.
CONFIG_DOC := docs/src/routes/configuration/+page.md
COMPOSE_PINNED_ENV_PATTERN := ^(SNI_PORT)$$

check-env-example:
	@go run ./cmd/relay-server config --format names | grep -Ev '$(COMPOSE_PINNED_ENV_PATTERN)' > /tmp/portal-env-names.txt
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

# Each *.values.yaml example renders through the chart its name starts with;
# the other examples are plain manifests. Needs helm and kubeconform.
HELM_CHARTS_DIR := docs/examples/helm
K8S_EXAMPLES_DIR := docs/static/examples/kubernetes

check-charts:
	@set -e; \
	for values in $(K8S_EXAMPLES_DIR)/*.values.yaml; do \
		case "$$(basename "$$values")" in \
			relay-*) chart=$(HELM_CHARTS_DIR)/portal-relay ;; \
			tunnel*) chart=$(HELM_CHARTS_DIR)/portal-tunnel ;; \
			*) echo "[charts] $$values names no chart"; exit 1 ;; \
		esac; \
		echo "[charts] $$chart -f $$values"; \
		helm lint --strict --quiet "$$chart" -f "$$values"; \
		helm template example "$$chart" -f "$$values" | kubeconform -strict -summary; \
	done; \
	echo "[charts] portal-relay with lease ports, HTTP redirect and PodMonitor"; \
	helm template example $(HELM_CHARTS_DIR)/portal-relay -f $(K8S_EXAMPLES_DIR)/relay-embedded-dns.values.yaml \
		--set env.TCP_ENABLED=true,env.UDP_ENABLED=true,env.HTTP_REDIRECT_ENABLED=true,env.MIN_PORT=40000,env.MAX_PORT=40009,podMonitor.enabled=true \
		| kubeconform -strict -summary -skip PodMonitor; \
	echo "[charts] portal-tunnel with PodMonitor"; \
	helm template example $(HELM_CHARTS_DIR)/portal-tunnel -f $(K8S_EXAMPLES_DIR)/tunnel.values.yaml \
		--set metrics.podMonitor.enabled=true \
		| kubeconform -strict -summary -skip PodMonitor; \
	echo "[charts] plain manifests"; \
	kubeconform -strict -summary $$(ls $(K8S_EXAMPLES_DIR)/*.yaml | grep -v '\.values\.yaml$$')

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

# Build WebAssembly tunnel client for browser smoke tests and relay assets
build-wasm:
	@echo "[wasm] building portal-tunnel wasm..."
	@mkdir -p cmd/relay-server/dist/tunnel
	@test "$$(go env GOVERSION)" = "$(GO_TOOLCHAIN_VERSION)"
	@CGO_ENABLED=0 GOOS=js GOARCH=wasm go build $(GO_BUILD_FLAGS) -o cmd/relay-server/dist/tunnel/portal-js-wasm.wasm ./cmd/portal-tunnel/wasm
	@cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" cmd/relay-server/dist/tunnel/wasm_exec.js

# Build portal-tunnel binaries for installer distribution
build-tunnel: build-wasm
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

# Build Portal Desktop for release with the ggui command: per architecture, a
# macOS app bundle in a tarball, a Windows program, and a Linux install tree in
# a tarball. ggui.toml keeps a placeholder version; the build stamps the
# release version from config.toml into a copy of it.
build-desktop:
	@rm -rf $(DESKTOP_OUT)
	@mkdir -p $(DESKTOP_OUT)
	@set -e; \
	version=$$(awk -F'"' '/^version/ { print $$2; exit }' config.toml | sed -E 's/^v//; s/[-+].*//'); \
	out="$(CURDIR)/$(DESKTOP_OUT)"; \
	trap 'rm -f $(DESKTOP_DIR)/ggui.release.toml' EXIT; \
	sed -E "s/^version = .*/version = \"$$version\"/" $(DESKTOP_DIR)/ggui.toml > $(DESKTOP_DIR)/ggui.release.toml; \
	for arch in amd64 arm64; do \
		echo " - $(DESKTOP_OUT)/portal-desktop-darwin-$$arch.tar.gz"; \
		(cd $(DESKTOP_DIR) && GOARCH=$$arch ggui build --config ggui.release.toml --target macos --out "$$out/build/darwin-$$arch" >/dev/null); \
		tar -C "$$out/build/darwin-$$arch" -czf "$$out/portal-desktop-darwin-$$arch.tar.gz" "Portal Desktop.app"; \
		echo " - $(DESKTOP_OUT)/portal-desktop-windows-$$arch.exe"; \
		(cd $(DESKTOP_DIR) && GOARCH=$$arch ggui build --config ggui.release.toml --target windows --out "$$out/build/windows-$$arch" >/dev/null); \
		mv "$$out/build/windows-$$arch/Portal Desktop.exe" "$$out/portal-desktop-windows-$$arch.exe"; \
		echo " - $(DESKTOP_OUT)/portal-desktop-linux-$$arch.tar.gz"; \
		(cd $(DESKTOP_DIR) && GOARCH=$$arch ggui build --config ggui.release.toml --target linux --format tar --out "$$out/build/linux-$$arch" >/dev/null); \
		mv "$$out/build/linux-$$arch/portal-desktop-$$version-linux-$$arch.tar.gz" "$$out/portal-desktop-linux-$$arch.tar.gz"; \
	done
	@rm -rf $(DESKTOP_OUT)/build

# Build Go relay server
build-server: build-tunnel build-frontend build-server-bin

# Binary only; assumes frontend assets already exist in cmd/relay-server/dist/app.
build-server-bin:
	@echo "[server] building Go portal..."
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -o bin/relay-server ./cmd/relay-server

clean:
	rm -rf bin
	rm -rf cmd/relay-server/dist/tunnel
	rm -rf cmd/relay-server/dist/app
	rm -rf frontend/dist
