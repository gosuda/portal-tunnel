import { act, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { APIClientError, apiClient } from "@/lib/apiClient";
import { ThemeProvider } from "@/components/ThemeProvider";
import { Admin } from "./Admin";

vi.mock("@ssgoi/react", () => ({
  SsgoiTransition: ({ children }: { children?: ReactNode }) => <>{children}</>,
}));

vi.mock("@/lib/apiClient", async () => {
  const actual = await vi.importActual<typeof import("@/lib/apiClient")>("@/lib/apiClient");
  return { ...actual, apiClient: { get: vi.fn(), post: vi.fn() } };
});

describe("Admin sign-in", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.mocked(apiClient.get).mockImplementation(async (path: string) => {
      if (path === RELAY_API_PATHS.policy.state) {
        return { leases: [], policy: { approval_mode: "auto", udp: { enabled: false, max_leases: 0 }, tcp_port: { enabled: false, max_leases: 0 } } } as never;
      }
      return {} as never;
    });
    vi.mocked(apiClient.post).mockResolvedValue({ access_token: "token" } as never);
  });

  it("shows the admin list after the header signs in, without asking the relay again", async () => {
    render(<ThemeProvider><Admin /></ThemeProvider>);
    await act(async () => {});
    expect(screen.getByText(/Enter the admin token/)).toBeTruthy();

    fireEvent.change(screen.getByPlaceholderText("Admin token"), { target: { value: "secret" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Login/ }));
    });

    expect(screen.queryByText(/Enter the admin token/)).toBeNull();
    expect(screen.getByText("No servers match these filters")).toBeTruthy();
    expect(vi.mocked(apiClient.get).mock.calls.map(([path]) => path)).not.toContain(RELAY_API_PATHS.admin.authStatus);
  });

  it("keeps pending requests and the approval form after an error and allows retry without reloading", async () => {
    const identityKey = "demo:0x1111111111111111111111111111111111111111";
    const state = {
      leases: [],
      pending: [{ identity_key: identityKey, expires_at: "2026-12-01T00:00:00Z" }],
      policy: { approval_mode: "manual", udp: { enabled: false, max_leases: 0 }, tcp_port: { enabled: false, max_leases: 0 } },
    };
    vi.mocked(apiClient.get).mockResolvedValue(state);
    render(<ThemeProvider><Admin /></ThemeProvider>);
    await act(async () => {});
    fireEvent.change(screen.getByPlaceholderText("Admin token"), { target: { value: "secret" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Login/ }));
    });

    fireEvent.change(screen.getByRole("textbox", { name: "Service identity key" }), { target: { value: "invalid-key" } });
    vi.mocked(apiClient.post).mockRejectedValueOnce(new APIClientError("Invalid identity key", 400));
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    });

    expect(screen.getByRole("alert").textContent).toContain("Invalid identity key");
    expect(screen.getByRole("region", { name: "Pending requests" }).textContent).toContain(identityKey);
    const input = screen.getByRole("textbox", { name: "Service identity key" }) as HTMLInputElement;
    expect(input.value).toBe("invalid-key");

    fireEvent.change(input, { target: { value: identityKey } });
    vi.mocked(apiClient.get).mockResolvedValue({ ...state, pending: [] });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    });

    expect(apiClient.post).toHaveBeenLastCalledWith(RELAY_API_PATHS.policy.leases, {
      identity_key: identityKey, is_approved: true,
    });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("region", { name: "Pending requests" })).toBeNull();
    expect(screen.getByText(`Saved approve for ${identityKey}.`)).toBeTruthy();
    expect(screen.getByRole("textbox", { name: "Service identity key" })).toBe(input);
  });

  it("does not show policy controls when the initial policy load fails", async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new Error("Could not load policy"));
    render(<ThemeProvider><Admin /></ThemeProvider>);
    await act(async () => {});
    fireEvent.change(screen.getByPlaceholderText("Admin token"), { target: { value: "secret" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Login/ }));
    });

    expect(screen.getByText("Error: Could not load policy")).toBeTruthy();
    expect(screen.queryByRole("textbox", { name: "Service identity key" })).toBeNull();
  });
});
