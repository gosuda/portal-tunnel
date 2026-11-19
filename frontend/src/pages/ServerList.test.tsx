import { act, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "@/lib/apiClient";
import { ThemeProvider } from "@/components/ThemeProvider";
import { ServerList } from "./ServerList";

vi.mock("@ssgoi/react", () => ({
  SsgoiTransition: ({ children }: { children?: ReactNode }) => <>{children}</>,
}));
vi.mock("@/lib/apiClient", () => ({
  apiClient: { get: vi.fn() },
  APIClientError: class extends Error {},
}));

const alpha = "0x1111111111111111111111111111111111111111";
const beta = "0x2222222222222222222222222222222222222222";

function BrowserHistory() {
  const navigate = useNavigate();
  const location = useLocation();
  return (
    <>
      <output aria-label="Address bar">{location.search}</output>
      <button onClick={() => navigate(-1)}>Back</button>
      <button onClick={() => navigate(1)}>Forward</button>
      <ServerList />
    </>
  );
}

function renderDirectory(path: string) {
  render(<MemoryRouter initialEntries={[path]}><ThemeProvider><BrowserHistory /></ThemeProvider></MemoryRouter>);
  return screen.getByRole<HTMLInputElement>("searchbox", { name: "Search apps" });
}

beforeEach(() => {
  vi.stubGlobal("IntersectionObserver", class {
    observe() {}
    unobserve() {}
    disconnect() {}
  });
  vi.mocked(apiClient.get).mockReset();
  vi.mocked(apiClient.get).mockImplementation(async (path) => {
    if (!path.startsWith("/api/services")) return { leases: [] };
    const address = new URL(path, "https://relay.example").searchParams.get("address");
    return {
      relays_checked: 1,
      relays_skipped: 0,
      partial: false,
      services: address ? [{
        address,
        name: address === alpha ? "Alpha app" : "Beta app",
        metadata: {},
        locations: [{
          relay_url: "https://remote.example",
          current_relay: false,
          reported_ready: true,
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          verification: "relay-reported",
        }],
      }] : [],
    };
  });
});

afterEach(() => vi.unstubAllGlobals());

describe("ServerList identity navigation", () => {
  it("keeps the URL, search input and directory aligned on Back and Forward", async () => {
    const search = renderDirectory("/");
    fireEvent.change(search, { target: { value: alpha } });
    expect(await screen.findByText("Alpha app")).toBeTruthy();
    fireEvent.change(search, { target: { value: beta } });
    expect(await screen.findByText("Beta app")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByLabelText("Address bar").textContent).toBe(`?identity=${alpha}`);
    expect(search.value).toBe(alpha);
    expect(await screen.findByText("Alpha app")).toBeTruthy();
    expect(screen.queryByText("Beta app")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Forward" }));
    expect(screen.getByLabelText("Address bar").textContent).toBe(`?identity=${beta}`);
    expect(search.value).toBe(beta);
    expect(await screen.findByText("Beta app")).toBeTruthy();
    expect(screen.queryByText("Alpha app")).toBeNull();
  });

  it("loads a direct identity URL and preserves ordinary text when removing identity", async () => {
    const search = renderDirectory(`/?identity=${alpha}&keep=1`);
    expect(search.value).toBe(alpha);
    expect(await screen.findByText("Alpha app")).toBeTruthy();

    await act(async () => fireEvent.change(search, { target: { value: "ordinary text" } }));
    expect(screen.getByLabelText("Address bar").textContent).toBe("?keep=1");
    expect(search.value).toBe("ordinary text");
    expect(screen.queryByText("Alpha app")).toBeNull();
  });
});
