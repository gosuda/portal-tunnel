#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash ./publish.sh package
  bash ./publish.sh publish

Examples:
  bash ./publish.sh package
  bash ./publish.sh publish

Notes:
  - Run this from WSL or another Unix-like shell.
  - Export VSCE_PAT only for manual publish.
  - CI publishes with GitHub OIDC and does not use VSCE_PAT.
  - pnpm and vsce are pinned by package.json and pnpm-lock.yaml.
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

main() {
  local action="${1:-}"
  if [[ -z "$action" ]]; then
    usage
    exit 1
  fi
  shift || true

  if [[ "$#" -ne 0 ]]; then
    echo "Unexpected arguments: $*" >&2
    usage
    exit 1
  fi

  case "$action" in
    package)
      ;;
    publish)
      if [[ -z "${VSCE_PAT:-}" ]]; then
        echo "VSCE_PAT is required for publish." >&2
        exit 1
      fi
      ;;
    *)
      usage
      exit 1
      ;;
  esac

  require_command node
  require_command pnpm

  cd "$(dirname "$0")"

  local expected_pnpm
  local actual_pnpm
  expected_pnpm="$(node -p "require('./package.json').packageManager.split('@').pop()")"
  actual_pnpm="$(pnpm --version)"
  if [[ "$actual_pnpm" != "$expected_pnpm" ]]; then
    echo "pnpm $expected_pnpm is required; found $actual_pnpm." >&2
    exit 1
  fi

  pnpm install --frozen-lockfile
  mkdir -p release
  rm -f release/portal-tunnel.vsix
  pnpm exec vsce package \
    --no-dependencies \
    --out release/portal-tunnel.vsix

  if [[ "$action" == "publish" ]]; then
    pnpm exec vsce publish \
      --packagePath release/portal-tunnel.vsix \
      --skip-duplicate
  fi
}

main "$@"
