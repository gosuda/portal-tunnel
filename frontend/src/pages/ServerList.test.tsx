import { act, fireEvent, render, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "@/lib/apiClient";
import type { ServiceDiscoveryResponse } from "@/types/api";
import { ThemeProvider } from "@/components/ThemeProvider";
import { ServerList } from "./ServerList";

vi.mock("@ssgoi/react", () => ({
  SsgoiTransition: ({ children }: { children?: ReactNode }) => <>{children}</>,
}));

vi.mock("@/lib/apiClient", () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
  },
  APIClientError: class extends Error {},
}));

const IDENTITY_A = "0x1111111111111111111111111111111111111111";
const IDENTITY_B = "0x2222222222222222222222222222222222222222";

function discoveryFor(address: string, serviceName: string): ServiceDiscoveryResponse {
  return {
    services: [
      {
        name: serviceName,
        address,
        metadata: { tags: ["network"] },
        locations: [
          {
            relay_url: "https://relay.example",
            url: `https://${serviceName}.relay.example/`,
            current_relay: false,
            reported_ready: true,
            observed_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 60_000).toISOString(),
            verification: "relay-reported",
          },
        ],
      },
    ],
  };
}

describe("ServerList active identity and URL synchronization", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    class MockIntersectionObserver {
      observe = vi.fn();
      unobserve = vi.fn();
      disconnect = vi.fn();
    }
    window.IntersectionObserver = MockIntersectionObserver as unknown as typeof IntersectionObserver;
    globalThis.IntersectionObserver = MockIntersectionObserver as unknown as typeof IntersectionObserver;
    vi.mocked(apiClient.get).mockImplementation(async (path) => {
      if (path === "/api/public/state") {
        return { leases: [] };
      }
      if (path.includes(IDENTITY_A)) {
        return discoveryFor(IDENTITY_A, "service-alpha");
      }
      if (path.includes(IDENTITY_B)) {
        return discoveryFor(IDENTITY_B, "service-beta");
      }
      return { partial: false, relays_checked: 0, relays_skipped: 0, services: [] };
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("direct load of ?identity=A: input and directory scope agree", async () => {
    const router = createMemoryRouter(
      [{ path: "/", element: <ServerList /> }],
      { initialEntries: [`/?identity=${IDENTITY_A}`] }
    );

    render(
      <ThemeProvider>
        <RouterProvider router={router} />
      </ThemeProvider>
    );
    await act(async () => {});

    const searchInput = screen.getByRole("searchbox", { name: /search apps/i }) as HTMLInputElement;
    expect(searchInput.value).toBe(IDENTITY_A);
    expect(screen.getByText("service-alpha")).toBeTruthy();
    expect(router.state.location.search).toBe(`?identity=${IDENTITY_A}`);
  });

  it("clears the identity when navigating through Favorites back to Home", async () => {
    const router = createMemoryRouter(
      [{ path: "/", element: <ServerList /> }],
      { initialEntries: [`/?identity=${IDENTITY_A}`] }
    );
    render(
      <ThemeProvider>
        <RouterProvider router={router} />
      </ThemeProvider>
    );
    await act(async () => {});

    fireEvent.click(within(screen.getByRole("complementary", { name: "Navigation" }))
      .getByRole("button", { name: /^Favorites/ }));
    await act(async () => {});
    expect(router.state.location.search).toBe("");
    expect((screen.getByRole("searchbox", { name: /search apps/i }) as HTMLInputElement).value).toBe("");

    fireEvent.click(within(screen.getByRole("complementary", { name: "Navigation" }))
      .getByRole("button", { name: "Home" }));
    await act(async () => {});
    expect(router.state.location.search).toBe("");
    expect(screen.queryByText("service-alpha")).toBeNull();
    expect(apiClient.get).toHaveBeenCalledWith("/api/services", expect.any(AbortSignal));
  });

  it("identity search -> ordinary text search: identity query param is removed without input being reset", async () => {
    const router = createMemoryRouter(
      [{ path: "/", element: <ServerList /> }],
      { initialEntries: [`/?identity=${IDENTITY_A}`] }
    );

    render(
      <ThemeProvider>
        <RouterProvider router={router} />
      </ThemeProvider>
    );
    await act(async () => {});

    const searchInput = screen.getByRole("searchbox", { name: /search apps/i }) as HTMLInputElement;
    expect(searchInput.value).toBe(IDENTITY_A);

    // User types normal text instead of hex address
    fireEvent.change(searchInput, { target: { value: "ordinary search" } });
    await act(async () => {});

    expect(searchInput.value).toBe("ordinary search");
    expect(router.state.location.search).toBe("");
  });

  it("A -> B -> browser Back -> Forward: URL, input, and discovered results agree", async () => {
    const router = createMemoryRouter(
      [{ path: "/", element: <ServerList /> }],
      { initialEntries: ["/"] }
    );

    render(
      <ThemeProvider>
        <RouterProvider router={router} />
      </ThemeProvider>
    );
    await act(async () => {});

    const searchInput = screen.getByRole("searchbox", { name: /search apps/i }) as HTMLInputElement;
    expect(searchInput.value).toBe("");

    // 1. Search identity A
    fireEvent.change(searchInput, { target: { value: IDENTITY_A } });
    await act(async () => {});

    expect(router.state.location.search).toBe(`?identity=${IDENTITY_A}`);
    expect(searchInput.value).toBe(IDENTITY_A);
    expect(screen.getByText("service-alpha")).toBeTruthy();

    // 2. Search identity B
    fireEvent.change(searchInput, { target: { value: IDENTITY_B } });
    await act(async () => {});

    expect(router.state.location.search).toBe(`?identity=${IDENTITY_B}`);
    expect(searchInput.value).toBe(IDENTITY_B);
    expect(screen.getByText("service-beta")).toBeTruthy();

    // 3. Navigate browser Back -> should restore identity A
    await act(async () => {
      await router.navigate(-1);
    });

    expect(router.state.location.search).toBe(`?identity=${IDENTITY_A}`);
    expect(searchInput.value).toBe(IDENTITY_A);
    expect(screen.getByText("service-alpha")).toBeTruthy();

    // 4. Navigate browser Forward -> should restore identity B
    await act(async () => {
      await router.navigate(1);
    });

    expect(router.state.location.search).toBe(`?identity=${IDENTITY_B}`);
    expect(searchInput.value).toBe(IDENTITY_B);
    expect(screen.getByText("service-beta")).toBeTruthy();
  });
});
