import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { Ssgoi } from "@ssgoi/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { openExternal } from "@/lib/navigate";
import { ServerDetail } from "./ServerDetail";

// jsdom's Location methods are legacy-unforgeable (non-configurable), so the
// redirect is observed through the openExternal seam instead of the real
// window.location.
vi.mock("@/lib/navigate", () => ({ openExternal: vi.fn() }));

const SERVER_URL = "https://minecraft.relay.example.com/";
const ACK_KEY = "portalReputationWarningAck:minecraft.relay.example.com";

const openExternalMock = vi.mocked(openExternal);

function detailState(overrides?: Record<string, unknown>) {
  return {
    id: "minecraft.relay.example.com",
    name: "minecraft",
    description: "",
    tags: [],
    thumbnail: "",
    owner: "",
    online: true,
    serverUrl: SERVER_URL,
    ...overrides,
  };
}

function reputationFixture(overrides?: Record<string, unknown>) {
  return {
    up: 2,
    down: 8,
    total: 10,
    down_ratio: 0.8,
    warning: true,
    viewer_vote: "",
    is_new: false,
    identity_changed_recently: false,
    first_seen_at: "2026-09-01T00:00:00Z",
    ...overrides,
  };
}

function renderDetail(state: unknown) {
  let pathname = "/";
  function LocationProbe() {
    const location = useLocation();
    pathname = location.pathname;
    return null;
  }

  render(
    <Ssgoi config={{ transitions: [] }}>
      <MemoryRouter
        initialEntries={[
          "/",
          { pathname: "/server/srv-1", state },
        ]}
        initialIndex={1}
      >
        <Routes>
          <Route path="/" element={<p>list page</p>} />
          <Route path="/server/:id" element={<ServerDetail />} />
        </Routes>
        <LocationProbe />
      </MemoryRouter>
    </Ssgoi>
  );

  return { pathname: () => pathname };
}

describe("ServerDetail reputation gate", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    localStorage.clear();
    sessionStorage.clear();
    openExternalMock.mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps the 500ms auto-open for a service without reputation data", () => {
    renderDetail(detailState());

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(openExternalMock).toHaveBeenCalledTimes(1);
    expect(openExternalMock).toHaveBeenCalledWith(SERVER_URL);
  });

  it("keeps the 500ms auto-open for a service below the warning thresholds", () => {
    renderDetail(
      detailState({ reputation: reputationFixture({ warning: false }) })
    );

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(openExternalMock).toHaveBeenCalledWith(SERVER_URL);
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("holds a flagged service behind the interstitial instead of auto-opening", () => {
    renderDetail(detailState({ reputation: reputationFixture() }));

    act(() => {
      vi.advanceTimersByTime(1000);
    });

    expect(openExternalMock).not.toHaveBeenCalled();
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    const counts = within(screen.getByTestId("reputation-counts"));
    expect(counts.getByText("2")).toBeTruthy();
    expect(counts.getByText("8")).toBeTruthy();
    expect(counts.getByText("10")).toBeTruthy();
  });

  it("opens only after Open anyway and remembers the acknowledgement", () => {
    renderDetail(detailState({ reputation: reputationFixture() }));

    fireEvent.click(screen.getByRole("button", { name: "Open anyway" }));

    expect(openExternalMock).toHaveBeenCalledTimes(1);
    expect(openExternalMock).toHaveBeenCalledWith(SERVER_URL);
    expect(sessionStorage.getItem(ACK_KEY)).toBe("1");
  });

  it("auto-opens an acknowledged warning later in the same session", () => {
    sessionStorage.setItem(ACK_KEY, "1");
    renderDetail(detailState({ reputation: reputationFixture() }));

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(openExternalMock).toHaveBeenCalledWith(SERVER_URL);
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("returns to the directory from the interstitial via Back", () => {
    const { pathname } = renderDetail(
      detailState({ reputation: reputationFixture() })
    );

    fireEvent.click(screen.getByRole("button", { name: "Back" }));

    expect(pathname()).toBe("/");
    expect(openExternalMock).not.toHaveBeenCalled();
  });

  it("notes an identity change on the interstitial", () => {
    renderDetail(
      detailState({
        reputation: reputationFixture({ identity_changed_recently: true }),
      })
    );

    expect(
      screen.getByText(/recently changed its identity/i)
    ).toBeTruthy();
  });

  it("adds no reputation fetch to the open path", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    renderDetail(detailState());

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(openExternalMock).toHaveBeenCalledWith(SERVER_URL);
  });
});
