import { act, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReputationSummary } from "@/types/api";
import { ServerDetail } from "./ServerDetail";

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
  beforeEach(() => {
    vi.useFakeTimers();
    localStorage.clear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders the warning gate for flagged services instead of auto-opening", () => {
    renderDetail(FLAGGED);

    act(() => {
      vi.advanceTimersByTime(1500);
    });

    // The auto-open writes this flag right before navigating; it must
    // stay unset while the gate holds the visitor.
    expect(localStorage.getItem("isPush")).toBeNull();
    expect(screen.getByText(/negative community ratings/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /open anyway/i })).toBeTruthy();
  });

  it("records its navigation bookkeeping on Open anyway", () => {
    renderDetail(FLAGGED);

    fireEvent.click(screen.getByRole("button", { name: /open anyway/i }));

    expect(localStorage.getItem("isPush")).toBe("true");
  });
});
