---
title: Unprivileged Sandboxes (gvx)
description: Expose containerized services from unprivileged gVisor and gvx sandboxes through Portal without host root privileges or inbound firewall rules.
---

# Unprivileged Sandboxes (gvx)

> **Maintainer note**: the rules and patterns on this page are mirrored in the agent skill reference at `plugins/portal-tunnel/skills/portal-expose/references/unprivileged-sandboxes.md`. When either changes, update both files. This page is the human-facing source; the reference is the agent-facing copy.

In locked-down CI/CD runners, unprivileged Kubernetes pods, and AI agent execution environments, workloads often run without `root`, `sudo`, Docker daemon access (`docker.sock`), or Linux user namespaces (`CLONE_NEWUSER`).

User-space container runtimes like [gvx (`gfire-sigs/gvx`)](https://github.com/gfire-sigs/gvx)—a standalone, rootless gVisor engine—allow running full Linux containers and Docker environments safely in user space. Combining `gvx` with `portal` allows exposing these sandboxed services to the public internet or private relays without opening inbound host ports or modifying host firewalls.

## Why Combine Portal with Unprivileged Sandboxes?

- **Zero Host Inbound Ports:** Portal uses an outbound reverse session backhaul over TLS/WebSocket/QUIC. Neither the host nor the sandbox needs open inbound firewall ports.
- **Rootless & Daemonless:** Both `gvx` and `portal` run as standard unprivileged user processes. No daemon, kernel module, or root permission is required.
- **Ephemeral Sandbox URL:** Sandboxed test environments, AI agent rollouts, or CI preview apps can receive a temporary public HTTPS URL and tear it down cleanly upon completion.

---

## Pattern 1: In-Sandbox Reverse Tunnel (Recommended)

When `gvx` has outbound network egress via its user-space network stack (`netstack`), you can run `portal expose` directly inside the sandbox alongside your application.

```text
Relay Server (e.g., https://portal.example.com)
  ▲
  │ (Outbound reverse backhaul over TLS/QUIC)
┌─┼────────────────────────────────────────┐
│ gvx (rungv) Sandbox                      │
│ │                                        │
│ ├── portal expose 8080 (tunnel process)  │
│ │     │ (local loopback stream)          │
│ └── Target Service (listening on :8080)  │
└──────────────────────────────────────────┘
Host: No open ports, no root privileges required
```

### Steps

1. **Launch the sandbox container with network access:**

   ```bash
   rungv run -it --rm ubuntu:24.04 bash
   ```

2. **Start the local service inside the sandbox:**

   ```bash
   python3 -m http.server 8080 &
   ```

3. **Run Portal inside the sandbox:**

   Download and run the `portal` binary:

   ```bash
   curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
   portal expose 8080 --name my-sandbox-preview
   ```

4. **Verify the public URL:**
   The CLI outputs the public HTTPS endpoint:
   ```text
   service ready at https://my-sandbox-preview.portal.example.com (short URL: ...)
   ```

Because Portal initiates the outbound backhaul to the relay from within `gvx`, the host system requires no `-p` host port mappings.

---

## Pattern 2: Host-Side Tunnel with Sandbox Port-Forwarding

If you prefer to keep the `portal` binary on the host machine and run only the untrusted workload inside `gvx`:

```text
Browser / Client ──► Relay ──(outbound session)──► Host: portal expose 8080
                                                        │
                                                        ▼
                                       Host loopback (127.0.0.1:8080)
                                                        │
                                           (rungv -p 8080:80 proxy)
                                                        ▼
                                              gvx Container (:80)
```

1. **Run the container with unprivileged host port mapping:**

   ```bash
   rungv run -d -p 127.0.0.1:8080:80 nginx:alpine
   ```

2. **Expose the mapped port from the host:**

   ```bash
   portal expose 8080 --name my-app-preview
   ```

---

## Identity & State in Ephemeral Environments

In automated test pipelines or agent rollouts where containers are ephemeral:

- **Ephemeral Identity:** If you do not provide an `--identity-path`, Portal generates a new cryptographic key pair in memory or in the current directory (`identity.json`).
- **Pre-Configured Identity:** To maintain a consistent public hostname across ephemeral sandbox instances, inject your key via the `IDENTITY_JSON` environment variable:

  ```bash
  export IDENTITY_JSON='{"private_key":"<32-byte-hex>","token_secret":"<secret>"}'
  portal expose 8080 --name my-persistent-sandbox
  ```

- **Access Protection:** If the sandboxed application contains an administrative interface or interactive shell, protect it with Portal's native authentication flags:

  ```bash
  portal expose 8080 --auth siwe --auth-allow 0xYourWalletAddress...
  ```
