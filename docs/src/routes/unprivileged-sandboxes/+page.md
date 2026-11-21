---
title: Unprivileged Sandboxes (gvx)
description: Expose sandboxed services through Portal while keeping publisher identities outside untrusted workloads.
---

# Unprivileged Sandboxes (gvx)

> **Maintainer note:** Update this page together with `plugins/portal-tunnel/skills/portal-expose/references/unprivileged-sandboxes.md`. Both describe the same commands and trust boundaries.

[gvx](https://github.com/gfire-sigs/gvx) runs Linux workloads through a user-space gVisor runtime. Portal can expose a service in that sandbox through an outbound connection to a relay, without a public listener or an inbound firewall rule on the publishing host.

## Choose Where Portal Runs

| Workload | Preferred pattern | Identity location |
| --- | --- | --- |
| Untrusted or AI-generated code | Host-Side Portal with a loopback port forward | Trusted host, outside every guest mount |
| Trusted application | Either pattern | Outside the application's served directory |
| Disposable CI with a trusted workload | In-Sandbox Portal is an option | A new disposable identity for each run |

A Portal process in the same guest shares the workload's security boundary. A separate directory prevents accidental HTTP publication, but does not protect keys or signing authority from malicious code in that guest. Keep persistent identities, visitor authentication configuration and other secrets on the trusted host for untrusted workloads. Do not mount them into the guest or inject them through `IDENTITY_JSON`.

## Prerequisites

- Install `rungv` and meet its platform/backend requirements using the [gvx setup guide](https://github.com/gfire-sigs/gvx#3-quickstart). Rootless execution does not remove platform setup requirements; follow its [security model](https://github.com/gfire-sigs/gvx/blob/main/SECURITY.md) when choosing a backend for untrusted code.
- These examples use Bash. The host-side example assumes `portal` is installed on the host; see [Getting Started](/getting-started). The installer prints its actual destination. It may update a shell profile, but cannot update the calling shell's PATH. If it installed to a user bin directory, run `export PATH="$HOME/.local/bin:$HOME/bin:$PATH"` in the current shell.
- Allow DNS resolution and outbound HTTPS to the selected relays from the machine running Portal. Image pulls and package installation also need access to their registries and repositories.
- The examples assume `IDENTITY_JSON` is unset: it takes precedence over `--identity-path`.

## Pattern 1: Host-Side Portal for Untrusted Workloads

Run only the application in gvx. Keep Portal and its identity on the trusted host:

```text
Visitor -> Relay -> established outbound tunnel -> Portal on trusted host
                                                   |
                                          127.0.0.1:8080
                                                   |
                                          rungv port forward
                                                   |
                                          sandbox application :80
```

**Host terminal 1:** Run the application in the foreground, forwarding only to host loopback:

```bash
rungv run -net=nat -p 127.0.0.1:8080:80 nginx:alpine
```

`rungv` has no background daemon and does not support `run -d`. Keep this terminal running. The sample does not mount host directories or pass host secrets to the guest. For your own workload, expose only its application port and review gvx's guest-to-host network access controls; a loopback listener alone is not a guest egress policy.

**Host terminal 2:** Verify the local application, then start Portal with an identity outside the repository and guest mounts:

```bash
curl --fail --max-time 5 http://127.0.0.1:8080/
umask 077
mkdir -p "$HOME/.local/state/portal/sandbox-preview"
portal expose 127.0.0.1:8080 --name my-app-preview \
  --identity-path "$HOME/.local/state/portal/sandbox-preview/identity.json"
```

This pattern has a host loopback listener, not a public host port. The guest application can still return arbitrary content through the forwarded service; keeping keys on the host does not make that content trusted.

## Pattern 2: In-Sandbox Portal for Trusted Workloads

Use this pattern when the workload is trusted and outbound relay access is available inside the guest. It needs no host port mapping. For ephemeral CI, use a fresh disposable identity and do not reuse a production publisher identity.

Start an Ubuntu guest:

```bash
rungv run -it --rm -net=nat ubuntu:24.04 bash
```

The following commands run **inside the guest**. The Ubuntu shell uses guest root for package installation; no host `sudo` is used. A non-root or read-only CI image should provide these dependencies in its image instead.

```bash
set -euo pipefail
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates python3
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
export PATH="$HOME/.local/bin:$HOME/bin:$PATH"
portal version

# Serve only public content, never the working directory or the guest home.
mkdir -p /srv/preview/public
printf '%s\n' '<h1>Sandbox preview</h1>' > /srv/preview/public/index.html
python3 -m http.server 8080 --bind 127.0.0.1 --directory /srv/preview/public &
app_pid=$!
trap 'kill "$app_pid" 2>/dev/null || true' EXIT
curl --fail --max-time 5 --retry 5 --retry-connrefused --retry-delay 1 http://127.0.0.1:8080/

# Use a new private identity directory outside the public document root.
unset IDENTITY_JSON
umask 077
identity_dir="$(mktemp -d /tmp/portal-preview.XXXXXX)"
portal expose 127.0.0.1:8080 --name my-sandbox-preview \
  --identity-path "$identity_dir/identity.json"
```

The default CLI identity path is `identity.json` in the current working directory, not an automatically disposable in-memory identity. Never run a directory-serving HTTP server against a directory containing that file. This example explicitly serves `/srv/preview/public` and puts the identity under a separate private temporary directory. Discard the guest filesystem after the run; exclude identity files from CI artifacts, caches and logs. File separation does not isolate the key from other code in the guest.

## Use the URL Actually Granted

Read the actual `service ready at ...` output or the `public_url` and `alias_url` fields in JSON logs. Use and verify the granted alias when present, otherwise use the ready public URL. `--name` selects the service and requests a short alias; it does not reserve that alias or guarantee readiness. If the name is occupied, a supported Local TLS setup may provide a canonical URL; an alias-only registration may fail instead. Do not construct a URL from the requested name.

For a relay you explicitly selected, add `--relays <https-relay-url> --discovery=false`. A manual relay may require operator approval before the tunnel becomes ready.

## Identity Lifetime and Visitor Access

For a persistent publisher identity, reuse its private host-side identity file. `IDENTITY_JSON` is an alternative only in a trusted Portal process environment; it is not a way to hide a key from untrusted code in the same sandbox. Reusing a key preserves service identity, not availability or ownership of a short alias.

The samples publish a plain demo page. Protect administrative interfaces, interactive shells and code execution APIs with a deliberate visitor authentication policy; see [Application Authentication](/siwe-authentication). For untrusted workloads, run Portal's authentication on the trusted host. Visitor sign-in controls public access and does not isolate co-resident guest processes from signing keys.

Keep both the application and Portal processes running. Stop the foreground Portal command and the `rungv` run when the preview is finished. For CI, retain process handles and clean them up on job completion or cancellation.
