# Portal VSCode Extension

Expose your local service to the internet via a [Portal](https://github.com/gosuda/portal-tunnel) relay tunnel, directly from VSCode.

## Features

- `Portal: Start Tunnel` prompts only for the local host:port, then starts the tunnel with configured relay URLs or the default public registry
- `Portal: Start Tunnel (Advanced)` prompts for host, optional service name, relay source, and optional thumbnail
- `Portal: Stop Tunnel` stops the active tunnel terminal
- Persisted settings for relay URLs, default local host, and default service name
- Runs the latest Portal release installer script before starting the tunnel
- When no relay URL is configured, the extension can use the public registry at `https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json`

## Requirements

- A running [Portal relay server](https://github.com/gosuda/portal-tunnel) with an `https://` URL
- `curl` on macOS/Linux, PowerShell on Windows
- GitHub release asset access for `https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh` or `install.ps1`

## Settings

| Setting | Default | Description |
|---|---|---|
| `portal.relayUrls` | `[]` | Relay server URLs (`https://` only). If empty, the extension uses `https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json`. |
| `portal.defaultHost` | `"localhost:3000"` | Default local host:port shown by `Portal: Start Tunnel`. |
| `portal.defaultName` | `""` | Default tunnel service name suggestion. If empty, the extension omits `--name`. |

Example `settings.json`:

```json
{
  "portal.relayUrls": ["https://my-relay.example.com"],
  "portal.defaultHost": "localhost:3000",
  "portal.defaultName": "my-app"
}
```

## Usage

1. Open Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`)
2. Run `Portal: Start Tunnel`
3. Enter the local host:port you want to expose
4. The tunnel starts in the integrated terminal

Use `Portal: Start Tunnel (Advanced)` when you need a different host, custom relay selection, or a thumbnail URL.

The extension runs the platform-appropriate installer script from the latest GitHub release assets and then runs `portal expose ...` with the selected relay settings.

To stop, run `Portal: Stop Tunnel` or close the `Portal Tunnel` terminal.

## Development

```bash
git clone https://github.com/gosuda/portal-tunnel
cd portal-tunnel/extensions/vscode
corepack pnpm install --frozen-lockfile
```

Open the folder in VSCode, then press `F5` to launch the Extension Development Host.

To test the extension locally:

1. Open `extensions/vscode` in VSCode.
2. Press `F5` and choose `Run Extension`.
3. In the new Extension Development Host window, run `Portal: Start Tunnel` or `Portal: Start Tunnel (Advanced)` from the Command Palette.

If you want Linux behavior from WSL, open the folder with `Remote - WSL` first so the extension host runs in WSL instead of Windows.

## Release Notes

### 0.0.3

- Run the latest GitHub release installer script before execution

### 0.0.2

- Enforce `https://` relay URLs
- Prompt only for the local host in `Portal: Start Tunnel`
- Add `Portal: Start Tunnel (Advanced)` for host, name, relay, and thumbnail overrides
- Generate a stable default service name in the extension when the name is empty
