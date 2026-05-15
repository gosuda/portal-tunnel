---
title: Getting Started
description: Install Portal and expose your first local service to the internet.
---

# Getting Started

This guide installs the `portal` CLI and exposes a local service through a
public relay.

## Prerequisites

- macOS, Linux, or Windows
- Internet connectivity
- A local service to expose, such as a web app on port `3000`

## Install The CLI

### macOS / Linux

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
```

### Windows PowerShell

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
```

The installer downloads the `portal` binary and adds it to your `PATH`. It does
not create a config file. Portal works out of the box because relay discovery is
enabled by default.

## Expose Your First App

Start your local app, then run:

```bash
portal expose 3000
```

Portal accepts:

| Input | Example | Meaning |
|-------|---------|---------|
| Bare port | `3000` | `127.0.0.1:3000` |
| Host and port | `localhost:8080` | that exact local address |
| URL host | `http://127.0.0.1:3000` | parsed as `127.0.0.1:3000` |

Portal prints a public HTTPS URL:

```text
https://your-name.relay.example.com
```

Open the URL in a browser. The relay routes the connection, but tenant TLS
terminates in the tunnel process running on your machine.

## What Happened

When you ran `portal expose`:

1. Portal loaded or created a local identity at `identity.json`.
2. Portal selected relay URLs from the public registry and discovery.
3. The tunnel process registered a lease with one or more relays.
4. The tunnel process opened reverse sessions to those relays.
5. A public HTTPS hostname was assigned.
6. Incoming connections were routed by the relay and handled by your tunnel
   process.

The relay provides routing and keyless certificate signing, but it does not
receive tenant TLS session keys on the default stream path.

## Choose The Right Mode

Most web apps use the default stream mode:

```bash
portal expose 3000 --name myapp
```

Use routed HTTP mode when one public URL should mount multiple local HTTP
services:

```bash
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

Use dedicated raw TCP mode for non-HTTP servers such as Minecraft:

```bash
portal expose localhost:25565 --name minecraft --tcp
```

Use UDP mode for datagram services:

```bash
portal expose localhost:8080 --udp --udp-addr localhost:19132 --name game
```

## Use A Specific Relay

```bash
portal expose 3000 --relays https://portal.example.com --discovery=false
```

`--discovery=false` limits the tunnel to the explicit relay URLs you supplied.

## Keep A Stable Identity

By default, Portal writes `identity.json` in the current working directory. Use a
fixed path when you want stable identity across projects or restarts:

```bash
portal expose 3000 \
  --name myapp \
  --identity-path ~/.config/portal/myapp.identity.json
```

## Update The CLI

```bash
portal update
portal version
```

`portal update` checks the latest GitHub release, downloads the matching asset,
verifies its SHA256 checksum, and replaces the current executable.

## Next Steps

- [Concepts](/concepts): understand Portal's relay and transport model
- [Portal Agent](/portal-agent): keep multiple tunnels running from config
- [CLI Reference](/cli-reference): complete command and flag documentation
- [TCP and UDP Tunneling](/tcp-udp-tunneling): raw TCP and UDP examples
- [Deployment](/deployment): run your own public relay
