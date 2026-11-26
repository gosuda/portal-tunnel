---
title: Portal Desktop
description: Manage the tunnels of the Portal agent from a native desktop window.
---

# Portal Desktop

Portal Desktop is a native window for the [Portal agent](/portal-agent). It
shows the tunnels that the agent runs, and it asks the agent to add, change,
and remove them. The agent owns every tunnel. If you close or quit Portal
Desktop, the agent and its tunnels keep running.

Portal Desktop is a separate program, built with
[ggui](https://github.com/ironpark/ggui). The `portal` CLI, the agent, the
SDK, the relay, and the container images do not include it or its GUI
libraries. The CLI and the agent never need a display.

## Install

The installers install the CLI alone by default. To install Portal Desktop
with the CLI, opt in.

On macOS and Linux:

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | sh -s -- --with-gui
```

On Windows, in PowerShell:

```powershell
$env:PORTAL_WITH_GUI = '1'; irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
```

`sh -s --` gives `--with-gui` to the piped script. The shell installer also
reads `PORTAL_WITH_GUI=1`. A piped PowerShell script cannot take parameters, so
the PowerShell installer reads only the environment variable.

The installer gets the CLI and Portal Desktop from one release. It compares
each download with its own SHA-256 sidecar file before it installs anything.
If a download or a checksum fails, the installer stops and changes nothing. If
the CLI cannot be installed after Portal Desktop, the installer puts the old
Portal Desktop back.

| OS | Where Portal Desktop goes |
|----|---------------------------|
| macOS | `~/Applications/Portal Desktop.app` |
| Linux | `portal-desktop` in the directory of `portal`, a menu entry in `~/.local/share/applications`, and icons in `~/.local/share/icons` |
| Windows | `portal-desktop.exe` in `%LOCALAPPDATA%\portal\bin`, and a Start menu shortcut |

If the release does not have Portal Desktop yet, the installer stops and
changes nothing. A release publishes Portal Desktop shortly after the CLI.

To add Portal Desktop to an installed CLI, run the same command. The installer
gets both from the latest release, so it also replaces an older CLI, and it
says so. Use Portal Desktop with the CLI and the agent of its own release.

The install script of a relay installs only the CLI. If you give `--with-gui`
to the script of a relay, it stops and shows the official command. A relay
distributes only the CLI, and Portal Desktop always comes from the official
release.

## Open Portal Desktop

```bash
portal gui
```

`portal gui` opens the installed Portal Desktop and returns. It does not install
anything, and it does not start, stop, or change the agent. If Portal Desktop is
not installed, `portal gui` shows the install command. On Linux, `portal gui`
stops with an error if `DISPLAY` is not set.

You can also open Portal Desktop from Launchpad, the Start menu, or the
application menu of your Linux desktop. Only one Portal Desktop runs for each
user. If you open it again, the window that is open comes to the front.

If the agent uses a config file at a path that is not the default, give the
path to Portal Desktop:

```bash
portal gui --config ./agent.toml
```

If Portal Desktop is open for another config, the window comes to the front and
says that it shows another agent. To open the other config, quit Portal
Desktop, then open it again with that config.

The `portal-desktop` program takes these flags:

| Flag | Meaning |
|------|---------|
| `--config` | The agent config. The default is the default config of the agent. |
| `--state-dir` | The state directory of the agent. The default is the directory that the config names. |
| `--hidden` | Start in the menu bar or the notification area, without the window. Linux has no tray, so it shows the window. |

## Start The Agent

Portal Desktop needs a running Portal agent. If the agent is not running,
Portal Desktop shows "Set up and start". Select it to see what Portal Desktop
will do. Nothing changes until you select "Install and start".

1. If the agent config does not exist, Portal Desktop creates it without
   tunnels. The agent keeps the tunnels that you add in this file.
2. Portal Desktop runs `portal agent run`, the same command that you can run in
   a terminal. The command installs the agent as a service and starts it.

| OS | What `portal agent run` installs |
|----|----------------------------------|
| macOS | A launchd agent of your user in `~/Library/LaunchAgents`, which starts when you log in |
| Linux | A systemd service of your user, which starts when you log in. As root, a system service. |
| Windows | A Windows service that starts with Windows. It needs administrator rights. |

The service runs the agent, not Portal Desktop. The agent and its tunnels keep
running after you quit Portal Desktop. To stop the agent and keep it from
starting again, run `portal agent stop`.

Portal Desktop looks for the `portal` CLI in its own directory, on `PATH`, and
in `~/.local/bin` and `~/bin`. If it does not find the CLI, it shows the command
to run in a terminal.

On Windows, only administrators can connect to an agent that runs as a Windows
service. Run Portal Desktop as an administrator to start the agent and to
manage its tunnels.

## Use Portal Desktop

Portal Desktop reads the agent config to find the state directory of the agent.
It then uses the [local Control API](/portal-agent#local-control-api) with the
token that the agent writes there, as `portal agent dashboard` does. It asks the
agent for its status every two seconds.

To add a tunnel, select "Expose a service". Enter a local port, such as
`3000`, or a `host:port`. You can also give a name, relay URLs, relay discovery,
and the number of relays that carry the tunnel at the same time.

Each tunnel shows its state, its target, and its errors. "Settings" changes the
relay count, the description, the tags, and whether relay service lists show
the tunnel. Portal Desktop sends the relay count only if you change it, and the
count cannot be empty, because the agent cannot go back to its default. "Delete"
asks first, then removes the tunnel.

Each relay shows how it carries the tunnel: `direct`, `connecting...`,
`waiting` for approval, `refused`, `failed`, `legacy TLS`, or `disconnected`.
"Connect" and "Disconnect" change the relays of a running tunnel. A relay from
the config that you disconnect stays on the tunnel as `disconnected`, so you
can connect it again. A relay that waits for approval or refused the tunnel
says so. Relay failures and certificate errors show the words of the agent.

When a relay carries an HTTP tunnel, Portal Desktop shows its URL with "Copy"
and "Open". "Open" gives only `http` and `https` URLs to the browser. A TCP
tunnel shows its address with "Copy" only, because a browser cannot open it. If
the relay also gives a TCP tunnel a URL, Portal Desktop shows both.

If the agent stops or cannot be reached, Portal Desktop says why and keeps the
last list that the agent sent. It disables the actions until the agent answers
again. Open forms keep what you typed. If the agent is not running, Portal
Desktop offers to start it. See [Start The Agent](#start-the-agent).

Portal Desktop sends a desktop notification when a tunnel fails or recovers,
when a relay waits for approval or refuses a tunnel, and when the agent stops
answering.

On macOS and Windows, Portal Desktop keeps an icon in the menu bar or the
notification area. Closing the window hides Portal Desktop there, so that
notifications keep coming. "Quit Portal Desktop" in the icon menu quits it.
The agent and its tunnels keep running.

## Update

```bash
portal update
```

If Portal Desktop is installed with the CLI, `portal update` updates it to the
same release. It downloads and checks both before it replaces either. It
replaces Portal Desktop first, and it puts the old Portal Desktop back if it
cannot replace the CLI. An installation without Portal Desktop stays CLI-only.
A Portal Desktop that is open keeps the old version until you open it again.
The agent and its tunnels keep running.

If `portal update` cannot update Portal Desktop, it changes nothing and says
why. For example, a new release publishes Portal Desktop shortly after the CLI,
and a release older than Portal Desktop does not have it. To update the CLI
alone, add `--cli-only`:

```bash
portal update --cli-only
portal update --cli-only --version v2.1.9
```

Portal Desktop then keeps its release. Use Portal Desktop with the CLI and the
agent of its own release. Later, run `portal update` to move both to one
release.

## Platform Support

| Feature | macOS | Windows | Linux |
|---------|-------|---------|-------|
| System requirement | macOS 13 or later | Direct3D 11 or OpenGL 3.3 | X11 or XWayland, OpenGL 3.3 or OpenGL ES 3.0, glibc |
| Tray icon and close to tray | Yes | Yes | No. Closing the window quits Portal Desktop. |
| Notifications | Yes | Yes, as toasts | Yes, through the freedesktop notification service |
| Screen readers | VoiceOver | UI Automation, not yet tested on hardware | No |
| Release package | App bundle, signed ad hoc | Program with icon and manifest, not code signed | Install tree in a tarball |

Know these limits before you install:

- macOS: The release app is signed ad hoc and is not notarized. The installer
  downloads it with `curl`, which does not mark it as quarantined, so macOS
  opens it. If you download the tarball in a browser, allow the app in System
  Settings, Privacy & Security. Notarization needs a Developer ID certificate in
  the release workflow.
- Windows: The program is not code signed, so SmartScreen can warn about it.
  When the agent runs as a Windows service, only administrators can read its
  control endpoint. Run Portal Desktop as an administrator to control that
  agent.
- Linux: Portal Desktop has no tray icon and no screen reader support. It runs
  under X11, or under XWayland in a Wayland session. On musl distributions,
  install `gcompat`.

## Build From Source

Portal Desktop is a Go module of its own in `cmd/portal-desktop`, so its GUI
dependencies stay out of the main module.

```bash
cd cmd/portal-desktop
go run .
```

`make vet`, `make lint`, and `make test-go-unit` include the module. The tests
drive the window without a display through ggui `Probe`, and one of them runs a
real agent.

To build the release packages, install the ggui command, then build. The
packages go to `bin/desktop`.

```bash
make install-ggui
make build-desktop
```
