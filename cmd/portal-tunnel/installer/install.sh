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

# Portal Desktop is opt-in: --with-gui (sh -s -- --with-gui when piped) or
# PORTAL_WITH_GUI=1. Without it the installer installs the CLI alone.
WITH_GUI=""
case "${PORTAL_WITH_GUI:-}" in
  ""|0|false) ;;
  *) WITH_GUI=1 ;;
esac
for ARG in "$@"; do
  case "$ARG" in
    --with-gui) WITH_GUI=1 ;;
    *)
      echo "Unknown option: $ARG (supported: --with-gui)" >&2
      exit 1
      ;;
  esac
done

OFFICIAL_BASE_URL="https://github.com/gosuda/portal-tunnel/releases/latest/download"
BASE_URL="${BASE_URL:-$OFFICIAL_BASE_URL}"
BIN_PATH_PREFIX="${BIN_PATH_PREFIX:-}"
BIN_SUFFIX="portal-$PORTAL_OS-$PORTAL_ARCH"
RELAY_URL="${RELAY_URL:-https://your-relay.example.com}"

if [ -n "$WITH_GUI" ] && [ -n "$BIN_PATH_PREFIX" ]; then
  echo "This relay serves the portal CLI only, not Portal Desktop." >&2
  echo "Install both from the official release instead:" >&2
  echo "  curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | sh -s -- --with-gui" >&2
  exit 1
fi

# The CLI and the desktop must come from one release. Pin "latest" once, so a
# release published between the two downloads cannot split the pair.
if [ -n "$WITH_GUI" ] && [ "$BASE_URL" = "$OFFICIAL_BASE_URL" ] && [ -z "${BIN_URL:-}" ]; then
  RELEASE_URL="$(curl -fsSI "$BASE_URL/$BIN_SUFFIX" | tr -d '\r' | awk 'tolower($1) == "location:" { print $2; exit }')"
  case "$RELEASE_URL" in
    https://github.com/gosuda/portal-tunnel/releases/download/v*/"$BIN_SUFFIX")
      BASE_URL="${RELEASE_URL%/*}"
      ;;
    *)
      echo "Could not find the latest release. Aborting." >&2
      exit 1
      ;;
  esac
fi

if [ -n "$BIN_PATH_PREFIX" ]; then
  BIN_URL="${BIN_URL:-$BASE_URL/$BIN_PATH_PREFIX/$PORTAL_OS-$PORTAL_ARCH}"
else
  BIN_URL="${BIN_URL:-$BASE_URL/$BIN_SUFFIX}"
fi
CHECKSUM_URL="${CHECKSUM_URL:-${BIN_URL}.sha256}"
DESKTOP_URL="${DESKTOP_URL:-$BASE_URL/portal-desktop-$PORTAL_OS-$PORTAL_ARCH.tar.gz}"

is_local_https_url() {
  case "$1" in
    https://*) ;;
    *) return 1 ;;
  esac

  URL_HOSTPORT="${1#https://}"
  URL_HOSTPORT="${URL_HOSTPORT%%/*}"
  URL_HOSTPORT="${URL_HOSTPORT%%\?*}"
  URL_HOSTPORT="${URL_HOSTPORT%%#*}"

  case "$URL_HOSTPORT" in
    \[::1\]:*)
      URL_HOST="[::1]"
      URL_PORT="${URL_HOSTPORT#\[::1\]:}"
      ;;
    \[::1\])
      URL_HOST="[::1]"
      URL_PORT=""
      ;;
    *:*)
      URL_HOST="${URL_HOSTPORT%%:*}"
      URL_PORT="${URL_HOSTPORT#*:}"
      ;;
    *)
      URL_HOST="$URL_HOSTPORT"
      URL_PORT=""
      ;;
  esac

  case "$URL_PORT" in
    *[!0-9]*) return 1 ;;
  esac

  case "$URL_HOST" in
    localhost|127.0.0.1|\[::1\]|*.localhost)
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
DESKTOP_ARCHIVE="$WORKDIR/portal-desktop.tar.gz"
DESKTOP_DIR="$WORKDIR/desktop"
DESKTOP_TARGET=""
DESKTOP_BACKUP=""
cleanup() {
  if [ -n "${TMP_INSTALL_PATH:-}" ]; then
    rm -f "$TMP_INSTALL_PATH"
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# verify_sha256 FILE URL LABEL compares FILE with the SHA256 sidecar at URL.
verify_sha256() {
  CHECKSUM_PAYLOAD="$(fetch_url "$2")" || {
    echo "Failed to download checksum from $2. Aborting (fail-closed)." >&2
    exit 1
  }

  EXPECTED_SHA="$(printf '%s\n' "$CHECKSUM_PAYLOAD" | awk '{print $1}' | tr 'A-Z' 'a-z')"
  if ! printf '%s\n' "$EXPECTED_SHA" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "Invalid checksum payload from $2. Aborting (fail-closed)." >&2
    echo "Hint: expected SHA256 sidecar format '<sha256>  <filename>'." >&2
    exit 1
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA="$(sha256sum "$1" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA="$(shasum -a 256 "$1" | awk '{print $1}')"
  else
    echo "No SHA256 checksum tool found (need sha256sum or shasum)." >&2
    exit 1
  fi
  if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    echo "Checksum mismatch for $3. Aborting (fail-closed)." >&2
    exit 1
  fi
}

echo "Downloading portal ($PORTAL_OS/$PORTAL_ARCH)..." >&2
download_url "$BIN_URL" "$BIN_PATH"

echo "Verifying SHA256 checksum..." >&2
verify_sha256 "$BIN_PATH" "$CHECKSUM_URL" "portal binary"

# Everything is downloaded and verified before anything is installed.
if [ -n "$WITH_GUI" ]; then
  echo "Downloading Portal Desktop ($PORTAL_OS/$PORTAL_ARCH)..." >&2
  download_url "$DESKTOP_URL" "$DESKTOP_ARCHIVE"

  echo "Verifying SHA256 checksum..." >&2
  verify_sha256 "$DESKTOP_ARCHIVE" "${DESKTOP_URL}.sha256" "Portal Desktop"
  mkdir -p "$DESKTOP_DIR"
  tar -xzf "$DESKTOP_ARCHIVE" -C "$DESKTOP_DIR"
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

# restore_desktop puts back the desktop install_desktop replaced.
restore_desktop() {
  if [ -n "$DESKTOP_TARGET" ]; then
    rm -rf "$DESKTOP_TARGET"
    if [ -n "$DESKTOP_BACKUP" ]; then
      mv "$DESKTOP_BACKUP" "$DESKTOP_TARGET"
    fi
  fi
}

# install_desktop puts the verified desktop in place: the app bundle in
# ~/Applications on macOS, the program beside the CLI on Linux. It keeps the
# desktop it replaces until the CLI is installed too.
install_desktop() {
  if [ "$PORTAL_OS" = "darwin" ]; then
    DESKTOP_SOURCE="$DESKTOP_DIR/Portal Desktop.app"
    APPLICATIONS_DIR="${HOME:?HOME must be set to install Portal Desktop}/Applications"
    mkdir -p "$APPLICATIONS_DIR"
    DESKTOP_PATH="$APPLICATIONS_DIR/Portal Desktop.app"
  else
    DESKTOP_SOURCE="$DESKTOP_DIR/usr/bin/portal-desktop"
    DESKTOP_PATH="$INSTALL_DIR/portal-desktop"
  fi
  if [ ! -e "$DESKTOP_SOURCE" ]; then
    echo "The Portal Desktop package does not hold the app. Aborting." >&2
    exit 1
  fi
  if [ -e "$DESKTOP_PATH" ]; then
    rm -rf "$DESKTOP_PATH.old"
    mv "$DESKTOP_PATH" "$DESKTOP_PATH.old"
    DESKTOP_BACKUP="$DESKTOP_PATH.old"
  fi
  DESKTOP_TARGET="$DESKTOP_PATH"
  if ! mv "$DESKTOP_SOURCE" "$DESKTOP_TARGET"; then
    echo "Failed to install Portal Desktop to $DESKTOP_TARGET." >&2
    restore_desktop
    exit 1
  fi
}

if [ -n "$WITH_GUI" ]; then
  install_desktop
fi

if ! { cp "$BIN_PATH" "$TMP_INSTALL_PATH" && chmod +x "$TMP_INSTALL_PATH" && mv -f "$TMP_INSTALL_PATH" "$INSTALL_PATH"; }; then
  echo "Failed to install portal to $INSTALL_PATH." >&2
  restore_desktop
  exit 1
fi
TMP_INSTALL_PATH=""
if [ -n "$DESKTOP_BACKUP" ]; then
  rm -rf "$DESKTOP_BACKUP"
fi

echo "Installed portal to $INSTALL_PATH" >&2

if [ -n "$WITH_GUI" ]; then
  # The menu entry and icons of the Linux install tree go where the desktop
  # looks for a user's own, and the entry starts the program by its path.
  if [ "$PORTAL_OS" = "linux" ]; then
    DATA_HOME="${XDG_DATA_HOME:-${HOME:?HOME must be set to install Portal Desktop}/.local/share}"
    DESKTOP_ENTRY="$DATA_HOME/applications/org.gosuda.portal.desktop.desktop"
    mkdir -p "$DATA_HOME"
    cp -R "$DESKTOP_DIR/usr/share/." "$DATA_HOME/"
    sed "s|^Exec=.*|Exec=\"$DESKTOP_TARGET\"|" "$DESKTOP_ENTRY" > "$DESKTOP_ENTRY.tmp"
    mv -f "$DESKTOP_ENTRY.tmp" "$DESKTOP_ENTRY"
    update-desktop-database "$DATA_HOME/applications" >/dev/null 2>&1 || true
  fi
  echo "Installed Portal Desktop to $DESKTOP_TARGET" >&2
  if [ -n "$DESKTOP_BACKUP" ]; then
    echo "Reopen Portal Desktop if it is running." >&2
  fi
  if [ "$PORTAL_OS" = "linux" ] && [ -z "${DISPLAY:-}" ]; then
    echo "Note: DISPLAY is not set. Portal Desktop needs an X11 or XWayland session to run." >&2
  fi
fi

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    PROFILE_PATH=""
    if [ -n "${HOME:-}" ]; then
      SHELL_NAME="${SHELL:-}"
      SHELL_NAME="${SHELL_NAME##*/}"
      case "$SHELL_NAME" in
        zsh) PROFILE_PATH="$HOME/.zshrc" ;;
        bash) PROFILE_PATH="$HOME/.bashrc" ;;
        *) PROFILE_PATH="$HOME/.profile" ;;
      esac
    fi

    if [ -n "$PROFILE_PATH" ]; then
      mkdir -p "$(dirname "$PROFILE_PATH")" 2>/dev/null || true
      if [ ! -f "$PROFILE_PATH" ] || ! grep -F "$INSTALL_DIR" "$PROFILE_PATH" >/dev/null 2>&1; then
        {
          printf '\n# Added by Portal installer\n'
          printf 'export PATH="%s:$PATH"\n' "$INSTALL_DIR"
        } >> "$PROFILE_PATH" || PROFILE_PATH=""
      fi
    fi

    if [ -n "$PROFILE_PATH" ]; then
      echo "Added $INSTALL_DIR to PATH in $PROFILE_PATH" >&2
      echo "Open a new shell or run: export PATH=\"$INSTALL_DIR:\$PATH\"" >&2
    else
      echo "Warning: $INSTALL_DIR is not on PATH. Add it before running 'portal expose 3000'." >&2
    fi
    ;;
esac

echo "Next step:" >&2
echo "  portal expose 3000 --relays $RELAY_URL" >&2
if [ -n "$WITH_GUI" ]; then
  echo "  portal gui" >&2
fi
