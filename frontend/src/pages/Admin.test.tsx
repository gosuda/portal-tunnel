import { act, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { apiClient } from "@/lib/apiClient";
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
});
