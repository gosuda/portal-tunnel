#!/usr/bin/env sh
set -eu

OS="$(uname -s)"
case "$OS" in
  Linux) PORTAL_OS="linux" ;;
  Darwin) PORTAL_OS="darwin" ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) PORTAL_ARCH="amd64" ;;
  arm64|aarch64) PORTAL_ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

BASE_URL="${BASE_URL:-https://github.com/gosuda/portal-tunnel/releases/latest/download}"
BIN_PATH_PREFIX="${BIN_PATH_PREFIX:-}"
BIN_SUFFIX="portal-$PORTAL_OS-$PORTAL_ARCH"
if [ -n "$BIN_PATH_PREFIX" ]; then
  BIN_URL="${BIN_URL:-$BASE_URL/$BIN_PATH_PREFIX/$PORTAL_OS-$PORTAL_ARCH}"
else
  BIN_URL="${BIN_URL:-$BASE_URL/$BIN_SUFFIX}"
fi
CHECKSUM_URL="${CHECKSUM_URL:-${BIN_URL}.sha256}"
RELAY_URL="${RELAY_URL:-https://your-relay.example.com}"

is_local_https_url() {
  case "$1" in
    https://localhost|https://localhost:*|https://127.0.0.1|https://127.0.0.1:*|https://[::1]|https://[::1]:*|https://*.localhost|https://*.localhost:*)
      return 0
      ;;
  esac
  return 1
}

download_url() {
  if is_local_https_url "$1"; then
    curl -k -fsSL "$1" -o "$2"
    return
  fi
  curl -fsSL "$1" -o "$2"
}

fetch_url() {
  if is_local_https_url "$1"; then
    curl -k -fsSL "$1"
    return
  fi
  curl -fsSL "$1"
}

TMPDIR="${TMPDIR:-/tmp}"
WORKDIR="$(mktemp -d "$TMPDIR/portal-install.XXXXXX" 2>/dev/null || mktemp -d -t portal-install)"
BIN_PATH="$WORKDIR/portal"
cleanup() {
  if [ -n "${TMP_INSTALL_PATH:-}" ]; then
    rm -f "$TMP_INSTALL_PATH"
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

echo "Downloading portal ($PORTAL_OS/$PORTAL_ARCH)..." >&2
download_url "$BIN_URL" "$BIN_PATH"

echo "Verifying SHA256 checksum..." >&2
CHECKSUM_PAYLOAD="$(fetch_url "$CHECKSUM_URL")" || {
  echo "Failed to download checksum from $CHECKSUM_URL. Aborting (fail-closed)." >&2
  exit 1
}

EXPECTED_SHA="$(printf '%s\n' "$CHECKSUM_PAYLOAD" | awk '{print $1}' | tr 'A-Z' 'a-z')"
if ! printf '%s\n' "$EXPECTED_SHA" | grep -Eq '^[0-9a-f]{64}$'; then
  echo "Invalid checksum payload from $CHECKSUM_URL. Aborting (fail-closed)." >&2
  echo "Hint: expected SHA256 sidecar format '<sha256>  <filename>'." >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA="$(sha256sum "$BIN_PATH" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA="$(shasum -a 256 "$BIN_PATH" | awk '{print $1}')"
else
  echo "No SHA256 checksum tool found (need sha256sum or shasum)." >&2
  exit 1
fi
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "Checksum mismatch for portal binary. Aborting (fail-closed)." >&2
  exit 1
fi

pick_install_path() {
  EXISTING="$(command -v portal 2>/dev/null || true)"
  if [ -n "$EXISTING" ]; then
    EXISTING_DIR="$(dirname "$EXISTING")"
    if [ -d "$EXISTING_DIR" ] && [ -w "$EXISTING_DIR" ]; then
      printf '%s\n' "$EXISTING"
      return 0
    fi
  fi

  if [ -n "${HOME:-}" ]; then
    for DIR in "$HOME/.local/bin" "$HOME/bin"; do
      mkdir -p "$DIR" 2>/dev/null || true
      if [ -d "$DIR" ] && [ -w "$DIR" ]; then
        printf '%s\n' "$DIR/portal"
        return 0
      fi
    done
  fi

  return 1
}

INSTALL_PATH="$(pick_install_path)" || {
  echo "No writable install directory found. Ensure an existing portal install is writable or create \$HOME/.local/bin or \$HOME/bin." >&2
  exit 1
}

INSTALL_DIR="$(dirname "$INSTALL_PATH")"
TMP_INSTALL_PATH="$(mktemp "$INSTALL_DIR/.portal.tmp.XXXXXX")"
cp "$BIN_PATH" "$TMP_INSTALL_PATH"
chmod +x "$TMP_INSTALL_PATH"
mv -f "$TMP_INSTALL_PATH" "$INSTALL_PATH"
TMP_INSTALL_PATH=""

echo "Installed portal to $INSTALL_PATH" >&2

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo "Warning: $INSTALL_DIR is not on PATH. Add it before running 'portal expose 3000'." >&2
    ;;
esac

echo "Next step:" >&2
echo "  portal expose 3000 --relays $RELAY_URL" >&2
