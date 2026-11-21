# Unprivileged Sandboxes and gvx Workloads

Use this reference for services in [gvx](https://github.com/gfire-sigs/gvx), rootless containers or restricted CI runners. The human-facing source is `docs/src/routes/unprivileged-sandboxes/+page.md`; update both copies together.

## Choose the Trust Boundary First

- **Untrusted or AI-generated code:** Prefer Host-Side Portal. Keep its identity, authentication configuration and secrets outside every guest mount. Do not inject persistent `IDENTITY_JSON` or expose host credential directories to the guest.
- **Trusted workload:** Either pattern is possible. Separate the public content directory from the identity directory.
- **Trusted ephemeral CI:** In-Sandbox Portal may use a new disposable identity. Never reuse a production publisher identity there or include keys in artifacts, logs or caches.

An application and Portal in the same guest share a security boundary. Different directories prevent accidental HTTP disclosure, but do not keep keys or signing authority safe from malicious guest code. Visitor authentication protects public access, not secrets from another process in the guest.

Follow the main skill's installation, exposure, authentication and lifecycle rules. Use the [gvx setup guide](https://github.com/gfire-sigs/gvx#3-quickstart) and [security model](https://github.com/gfire-sigs/gvx/blob/main/SECURITY.md) for host/backend prerequisites. These shell examples use Bash. Ensure DNS and outbound HTTPS to the selected relays; image pulls and package installation also require registry/repository access.

## Pattern 1: Host-Side Portal (Default for Untrusted Code)

Host terminal 1, with the application in the foreground and only a loopback port published:

```bash
rungv run -net=nat -p 127.0.0.1:8080:80 nginx:alpine
```

`rungv run -d` is unsupported: there is no background daemon. Retain this terminal or its managed process handle. This sample mounts no host files and passes no secrets. Review guest-to-host network access controls for the chosen workload; loopback binding is not an egress policy.

Host terminal 2, with Portal already installed on the trusted host:

```bash
curl --fail --max-time 5 http://127.0.0.1:8080/
umask 077
mkdir -p "$HOME/.local/state/portal/sandbox-preview"
portal expose 127.0.0.1:8080 --name my-app-preview \
  --identity-path "$HOME/.local/state/portal/sandbox-preview/identity.json"
```

Keep the identity outside the repository, document root and every sandbox mount. A persistent identity stays on this host. The host has a loopback listener, but needs no public listener or inbound firewall rule. The guest still controls the application's responses.

## Pattern 2: In-Sandbox Portal (Trusted Workloads Only)

With guest outbound egress, run Portal beside the trusted application without a host port mapping. Use a disposable identity for CI.

```bash
rungv run -it --rm -net=nat ubuntu:24.04 bash
```

Inside the guest, install dependencies explicitly. These commands use guest root, not host `sudo`; a non-root/read-only CI image must provide the dependencies beforehand.

```bash
set -euo pipefail
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates python3
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
export PATH="$HOME/.local/bin:$HOME/bin:$PATH"
portal version

mkdir -p /srv/preview/public
printf '%s\n' '<h1>Sandbox preview</h1>' > /srv/preview/public/index.html
python3 -m http.server 8080 --bind 127.0.0.1 --directory /srv/preview/public &
app_pid=$!
trap 'kill "$app_pid" 2>/dev/null || true' EXIT
curl --fail --max-time 5 --retry 5 --retry-connrefused --retry-delay 1 http://127.0.0.1:8080/

unset IDENTITY_JSON
umask 077
identity_dir="$(mktemp -d /tmp/portal-preview.XXXXXX)"
portal expose 127.0.0.1:8080 --name my-sandbox-preview \
  --identity-path "$identity_dir/identity.json"
```

The installer prints its destination and may update a profile, but does not change the current shell's PATH. Use the printed directory if it differs from the user bin directories above. The CLI defaults to `./identity.json`; omitting `--identity-path` does not make an identity ephemeral or memory-only. Always pass an absolute path outside the served directory. Never serve the whole current directory or guest home containing identity material. Discard this guest filesystem after the run; the private temporary directory is not an isolation boundary from other guest code.

## Identity, Readiness and Handoff

- The examples assume `IDENTITY_JSON` is unset; it overrides `--identity-path`. Persistent injected identity JSON belongs only in a trusted Portal environment, not alongside untrusted code.
- Read the actual ready output or JSON `public_url` and `alias_url`. Prefer a granted alias, otherwise the ready public URL, and verify that endpoint as the main skill requires. Never invent a hostname from `--name`: aliases are optional. A supported Local TLS setup may obtain a canonical URL when an alias is taken; alias-only registration may fail.
- For a user-selected relay, append `--relays <https-relay-url> --discovery=false`. Pending approval is not readiness.
- Before exposing an interactive console, administrative interface or code execution API, follow `application-auth.md` and the main skill's sensitive-service rules. With untrusted workloads, keep Portal authentication on the trusted host.
- Retain ownership of both the app/sandbox and Portal processes. Stop only this workflow's processes at the end or on cancellation; do not call a foreground preview permanent.
