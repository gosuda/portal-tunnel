/**
 * Classifies what a user pasted into the quick-start form so the generated
 * command matches their intent:
 *
 * - `url`  — an `http(s)://` link: expose the host/port it points at.
 * - `file` — a `file://` URL, a Windows path, or an absolute POSIX path: serve
 *            the local static site with `portal expose --serve <path>`.
 * - `port` — a bare port, `host:port`, or anything else: current behavior.
 */
export type ShareKind = "url" | "file" | "port";

export interface ShareInput {
  kind: ShareKind;
  /** Positional `portal expose <target>` value for `url` / `port` kinds. */
  target: string;
  /** Local filesystem path passed to `--serve` for the `file` kind. */
  path: string;
  /** Stable string used to seed auto-generated names. */
  seedTarget: string;
}

const WINDOWS_PATH = /^[A-Za-z]:[\\/]/;
const UNC_PATH = /^\\\\/;

export function classifyShareInput(raw: string): ShareInput {
  const trimmed = raw.trim();
  if (trimmed === "") {
    return { kind: "port", target: "", path: "", seedTarget: "" };
  }

  if (/^https?:\/\//i.test(trimmed)) {
    const target = urlToExposeTarget(trimmed);
    return { kind: "url", target, path: "", seedTarget: target || trimmed };
  }

  if (/^file:\/\//i.test(trimmed)) {
    const path = fileURLToPath(trimmed);
    return { kind: "file", target: "", path, seedTarget: path || trimmed };
  }

  if (WINDOWS_PATH.test(trimmed) || UNC_PATH.test(trimmed) || trimmed.startsWith("/")) {
    return { kind: "file", target: "", path: trimmed, seedTarget: trimmed };
  }

  return { kind: "port", target: trimmed, path: "", seedTarget: trimmed };
}

function urlToExposeTarget(raw: string): string {
  try {
    const parsed = new URL(raw);
    if (parsed.hostname === "") {
      return "";
    }
    return parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;
  } catch {
    return "";
  }
}

function fileURLToPath(raw: string): string {
  try {
    const parsed = new URL(raw);
    let path = decodeURIComponent(parsed.pathname);
    // file:///C:/dir/main.html -> /C:/dir/main.html -> C:/dir/main.html
    if (/^\/[A-Za-z]:[\\/]/.test(path)) {
      path = path.slice(1);
    }
    return path;
  } catch {
    return raw.replace(/^file:\/\//i, "");
  }
}
