# Unprivileged Sandboxes and gvx Workloads

Use this reference when exposing a service running inside a locked-down, rootless, or unprivileged container sandbox, such as [`gfire-sigs/gvx`](https://github.com/gfire-sigs/gvx) (gVisor Everywhere), an unprivileged Kubernetes pod, or a restricted CI runner without Docker daemon or `sudo` access. The human-facing copy is the docs page `docs/src/routes/unprivileged-sandboxes/+page.md`; when either changes, update both.

Because Portal tunnels rely entirely on an outbound reverse session backhaul (over TLS/WebSocket/QUIC) to a relay server, workloads running inside unprivileged sandboxes require no inbound firewall ports on the host.

## Integration Patterns

### Pattern 1: In-Sandbox Reverse Tunnel (Preferred for Zero Host Inbound)

Run `portal expose` directly inside the sandbox alongside the target workload. This requires that the sandbox has outbound network egress (such as gVisor's user-space `netstack`).

- **Architecture:**
  - The application listens on sandbox loopback (e.g. `127.0.0.1:8080`).
  - `portal expose 8080 --name <app>` runs inside the sandbox.
  - The tunnel process initiates an outbound reverse connection to the relay.
  - The host machine has zero inbound ports open and requires no root privileges.

- **Sample Sandbox Script:**

  ```bash
  # Inside the gvx / unprivileged container:
  # 1. Start application in background
  python3 -m http.server 8080 &

  # 2. Expose via Portal
  portal expose 8080 --name sandbox-demo
  ```

### Pattern 2: Host Tunnel with Sandboxed Port-Forwarding

When the `portal` binary is managed on the host and the container only runs the target application:

- **Run container with unprivileged user-space port forward:**

  ```bash
  rungv run -d -p 127.0.0.1:8080:80 nginx:alpine
  ```

- **Run Portal on the host:**

  ```bash
  portal expose 8080 --name sandbox-preview
  ```

## Rules for Ephemeral Sandboxes & Agents

1. **Ephemeral vs Injected Identity:**
   - In ephemeral containers or RL rollouts, generate temporary keys by omitting `--identity-path`.
   - To keep a stable hostname across container restarts, inject the signing key via `IDENTITY_JSON` in the container environment rather than mounting host files:
     ```bash
     export IDENTITY_JSON='{"private_key":"<hex>","token_secret":"<secret>"}'
     portal expose 8080 --name stable-sandbox
     ```

2. **Access Control on Interactive Consoles:**
   - If the sandboxed service provides an interactive shell, code execution API, or debug console, always protect it with Portal's sign-in flags (`--auth siwe`, `--auth credential`, etc.) as documented in `application-auth.md`.

3. **Outbound Connectivity Requirement:**
   - Ensure the sandbox network policy permits outbound TCP/443 traffic to the configured relay domain(s).
