import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_TUNNEL_AUTH,
  validateTunnelAuth,
  type TunnelAuthMethod,
  type TunnelAuthOptions,
} from "@/lib/tunnelCommand";
import { AuthSection } from "./AuthSection";

function renderSection(method: TunnelAuthMethod, overrides: Partial<TunnelAuthOptions> = {}) {
  const auth = { ...DEFAULT_TUNNEL_AUTH, method, ...overrides };
  const onChange = vi.fn();
  render(
    <AuthSection
      auth={auth}
      onChange={onChange}
      issues={validateTunnelAuth(auth)}
      relayUrls={["https://relay.example"]}
      discovery
      name="demo"
      os="unix"
    />
  );
  return { auth, onChange };
}

describe("AuthSection fields", () => {
  it.each([
    ["oidc", "Client ID", "oidcClientId"],
    ["saml", "Identity provider metadata", "samlMetadataURL"],
    ["saml", "Entity ID (optional)", "samlEntityId"],
    ["email", "SMTP server", "emailSMTPAddr"],
    ["email", "Sender", "emailFrom"],
    ["email", "SMTP username (optional)", "emailSMTPUsername"],
  ] as const)("%s: typing in %s changes only %s", (method, label, key) => {
    const { auth, onChange } = renderSection(method);

    fireEvent.change(screen.getByLabelText(label), { target: { value: "typed" } });

    expect(onChange).toHaveBeenCalledWith({ ...auth, [key]: "typed" });
  });

  it("shows a field's issue next to that field", () => {
    renderSection("oidc", { oidcClientId: "" });
    expect(screen.getByText("Add the client ID")).toBeTruthy();
  });

  it("keeps the Google issuer read-only", () => {
    renderSection("oidc");
    expect(screen.getByLabelText("Issuer").hasAttribute("readonly")).toBe(true);
  });

  it("lists the redirect address of the short URL and the secret prompt", () => {
    renderSection("oidc");
    expect(screen.getByText("https://demo.relay.example/_portal/auth/callback")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy secret prompt" })).toBeTruthy();
  });

  it("asks for the SMTP password only with a username", () => {
    renderSection("email");
    expect(screen.queryByRole("button", { name: "Copy password prompt" })).toBeNull();
  });

  it("clears the allow list when the method changes", () => {
    const { auth, onChange } = renderSection("credential", { allow: ["alice"] });
    fireEvent.click(screen.getByRole("radio", { name: "No sign-in" }));
    expect(onChange).toHaveBeenCalledWith({ ...auth, method: "none", allow: [] });
  });
});
