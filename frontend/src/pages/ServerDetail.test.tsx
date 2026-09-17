import { act, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { isReputationWarning, openAnywaySessionKey } from "@/hooks/useReputation";
import type { ReputationSummary } from "@/types/api";
import { openExternal } from "@/lib/navigate";
import { ServerDetail } from "./ServerDetail";

vi.mock("@/lib/navigate", () => ({ openExternal: vi.fn() }));

// The gate behavior is what matters here; the transition wrapper is a
// passthrough so tests do not depend on ssgoi's browser internals.
vi.mock("@ssgoi/react", () => ({
  SsgoiTransition: ({ children }: { children?: ReactNode }) => <>{children}</>,
}));

const FLAGGED: ReputationSummary = {
  hostname: "svc.example.com",
  up: 1,
  down: 9,
  total: 10,
  viewer_vote: "",
};

const UNFLAGGED: ReputationSummary = {
  ...FLAGGED,
  up: 9,
  down: 1,
};

const SERVER_STATE = {
  id: "svc.example.com",
  name: "svc",
  description: "a service",
  tags: [],
  thumbnail: "",
  owner: "",
  online: true,
  serverUrl: "https://svc.example.com/",
};

function renderDetail(reputation?: ReputationSummary) {
  return render(
    <MemoryRouter
      initialEntries={[
        "/",
        {
          pathname: "/server/svc.example.com",
          state: { ...SERVER_STATE, reputation },
        },
      ]}
      initialIndex={1}
    >
      <Routes>
        <Route path="/" element={<div>directory</div>} />
        <Route path="/server/:id" element={<ServerDetail />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("ServerDetail reputation gate", () => {
  let assignMock: Mock;

  beforeEach(() => {
    vi.useFakeTimers();
    assignMock = vi.mocked(openExternal);
    assignMock.mockClear();
    localStorage.clear();
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps the automatic open for unflagged services", () => {
    renderDetail(UNFLAGGED);

    act(() => {
      vi.advanceTimersByTime(700);
    });

    expect(assignMock).toHaveBeenCalledWith("https://svc.example.com/");
  });

  it("suppresses the automatic open for flagged services", () => {
    renderDetail(FLAGGED);

    act(() => {
      vi.advanceTimersByTime(1500);
    });

    expect(assignMock).not.toHaveBeenCalled();
    expect(screen.getByText(/negative community ratings/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /open anyway/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^back$/i })).toBeTruthy();
  });

  it("redirects on Open anyway and remembers it for the session", () => {
    renderDetail(FLAGGED);

    fireEvent.click(screen.getByRole("button", { name: /open anyway/i }));

    expect(assignMock).toHaveBeenCalledWith("https://svc.example.com/");
    expect(
      sessionStorage.getItem(openAnywaySessionKey("svc.example.com"))
    ).toBe("1");
  });

  it("auto-opens a flagged service already opened this session", () => {
    sessionStorage.setItem(openAnywaySessionKey("svc.example.com"), "1");

    renderDetail(FLAGGED);

    act(() => {
      vi.advanceTimersByTime(700);
    });

    expect(assignMock).toHaveBeenCalledWith("https://svc.example.com/");
  });

  it("returns to the directory on Back", () => {
    renderDetail(FLAGGED);

    fireEvent.click(screen.getByRole("button", { name: /^back$/i }));

    expect(screen.getByText("directory")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /open anyway/i })).toBeNull();
  });
});

describe("directory warning policy", () => {
  it("changes at the vote thresholds", () => {
    expect(isReputationWarning({ ...FLAGGED, up: 2, down: 3, total: 5 })).toBe(false);
    expect(isReputationWarning({ ...FLAGGED, up: 1, down: 4, total: 5 })).toBe(true);
    expect(isReputationWarning({ ...FLAGGED, up: 2, down: 5, total: 7 })).toBe(true);
    expect(isReputationWarning({ ...FLAGGED, up: 3, down: 5, total: 8 })).toBe(false);
  });
});
