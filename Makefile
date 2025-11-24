.PHONY: build

# Build Portal Tunnel CLI (cloudflared-style tunnel)
build:
	@echo "[tunnel] building Portal Tunnel CLI..."
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin ./cmd
