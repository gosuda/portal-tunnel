import * as vscode from "vscode";

import {
  buildCommand,
  defaultRelayRegistryURL,
  validateRelayUrl,
} from "./command";

let tunnelTerminal: vscode.Terminal | undefined;
const defaultTunnelHost = "localhost:3000";

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("portal.startTunnel", () => startTunnel(false)),
    vscode.commands.registerCommand("portal.startTunnelAdvanced", () => startTunnel(true)),
    vscode.commands.registerCommand("portal.stopTunnel", stopTunnel),
    vscode.window.onDidCloseTerminal((t) => {
      if (t === tunnelTerminal) {
        tunnelTerminal = undefined;
      }
    })
  );
}

export function deactivate(): void {
  tunnelTerminal?.dispose();
}

async function startTunnel(advanced: boolean): Promise<void> {
  const host = await promptHost();
  if (!host) { return; }

  const name = advanced ? await promptName() : "";
  if (name === undefined) { return; }

  const relayUrls = await resolveRelaySelection(advanced);
  if (!relayUrls) { return; }

  const thumbnail = advanced ? await promptThumbnail() : "";
  if (thumbnail === undefined) { return; }

  runTunnelCommand({
    host,
    name,
    relayUrls,
    thumbnail,
  });
}

function runTunnelCommand(args: {
  host: string;
  name: string;
  relayUrls: string[];
  thumbnail: string;
}): void {
  let command: string;
  try {
    command = buildCommand({
      host: args.host,
      name: args.name,
      relayList: args.relayUrls.join(","),
      thumbnail: args.thumbnail,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to build the Portal tunnel command.";
    vscode.window.showErrorMessage(message);
    return;
  }

  if (tunnelTerminal) {
    tunnelTerminal.dispose();
  }
  tunnelTerminal = createTunnelTerminal();
  tunnelTerminal.show();
  tunnelTerminal.sendText(command);
}

function stopTunnel(): void {
  if (tunnelTerminal) {
    tunnelTerminal.dispose();
    tunnelTerminal = undefined;
    vscode.window.showInformationMessage("Portal tunnel stopped.");
  } else {
    vscode.window.showWarningMessage("No active Portal tunnel.");
  }
}

async function promptHost(): Promise<string | undefined> {
  const config = vscode.workspace.getConfiguration("portal");
  const defaultHost = config.get<string>("defaultHost") ?? defaultTunnelHost;
  return vscode.window.showInputBox({
    title: "Portal: Local Host",
    prompt: "Hostname or IP:Port where your service is running",
    value: defaultHost,
    validateInput: (v) => (v.trim() ? undefined : "Required"),
  });
}

async function promptName(): Promise<string | undefined> {
  const config = vscode.workspace.getConfiguration("portal");
  const defaultName = config.get<string>("defaultName") ?? "";
  return vscode.window.showInputBox({
    title: "Portal: Service Name",
    prompt: "Optional public hostname prefix. Leave empty to omit --name.",
    value: defaultName,
  });
}

async function resolveRelaySelection(interactive: boolean): Promise<string[] | undefined> {
  const config = vscode.workspace.getConfiguration("portal");
  const saved = config.get<string[]>("relayUrls") ?? [];
  if (saved.length > 0) {
    if (saved.some((url) => validateRelayUrl(url) !== undefined)) {
      vscode.window.showErrorMessage("portal.relayUrls must contain only valid https:// relay URLs.");
      return undefined;
    }
    return saved.map((url) => url.trim());
  }

  if (!interactive) {
    return [];
  }

  const choice = await vscode.window.showQuickPick([
    {
      label: "Use default public registry",
      description: defaultRelayRegistryURL,
    },
    {
      label: "Enter relay URL",
      description: "Connect the tunnel to a specific https:// relay",
    },
  ], {
    title: "Portal: Relay Source",
    placeHolder: "Choose a public registry or a specific relay URL",
  });
  if (!choice) {
    return undefined;
  }
  if (choice.label === "Use default public registry") {
    vscode.window.showInformationMessage(`Portal will use the default public registry: ${defaultRelayRegistryURL}`);
    return [];
  }

  const input = await vscode.window.showInputBox({
    title: "Portal: Relay URL",
    prompt: "Relay server URL (e.g. https://my-relay.example.com)",
    validateInput: validateRelayUrl,
  });
  if (!input) {
    return undefined;
  }
  return [input.trim()];
}

async function promptThumbnail(): Promise<string | undefined> {
  return vscode.window.showInputBox({
    title: "Portal: Thumbnail URL (optional)",
    prompt: "Image URL to display as thumbnail. Leave empty to skip.",
    placeHolder: "https://example.com/image.png",
    validateInput: (v) => {
      if (!v.trim()) { return undefined; }
      try { new URL(v.trim()); return undefined; } catch { return "Enter a valid URL or leave empty"; }
    },
  });
}

function createTunnelTerminal(): vscode.Terminal {
  if (process.platform !== "win32") {
    return vscode.window.createTerminal("Portal Tunnel");
  }

  return vscode.window.createTerminal({
    name: "Portal Tunnel",
    shellPath: "powershell.exe",
  });
}
