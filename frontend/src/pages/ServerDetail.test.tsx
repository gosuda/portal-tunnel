import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ThemeProvider } from "@/components/ThemeProvider";
import type { ReputationSummary } from "@/types/api";
import { ServerDetail } from "./ServerDetail";

const LEFT_FOR_SERVICE_KEY = "isPush";

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
  dns: "svc.example.com",
  link: "https://svc.example.com/",
};

function renderDetail(reputation?: ReputationSummary) {
  return render(
    <ThemeProvider>
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
    </ThemeProvider>
  );
}

describe("ServerDetail reputation gate", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    sessionStorage.clear();
    localStorage.clear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders the warning gate for flagged services without leaving for the service", () => {
    renderDetail(FLAGGED);

    act(() => {
      vi.advanceTimersByTime(1500);
    });

    expect(sessionStorage.getItem(LEFT_FOR_SERVICE_KEY)).toBeNull();
    expect(screen.getByText(/negative community ratings/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /open anyway/i })).toBeTruthy();
  });

  it("records its navigation bookkeeping on Open anyway", () => {
    renderDetail(FLAGGED);

    fireEvent.click(screen.getByRole("button", { name: /open anyway/i }));

    expect(sessionStorage.getItem(LEFT_FOR_SERVICE_KEY)).toBe("true");
    expect(localStorage.getItem(LEFT_FOR_SERVICE_KEY)).toBeNull();
  });

  it("returns to the directory when this tab already left for the service", () => {
    sessionStorage.setItem(LEFT_FOR_SERVICE_KEY, "true");
    renderDetail();

    expect(screen.getByText("directory")).toBeTruthy();
    expect(sessionStorage.getItem(LEFT_FOR_SERVICE_KEY)).toBeNull();
  });

  it("ignores a flag left in local storage by another tab", () => {
    localStorage.setItem(LEFT_FOR_SERVICE_KEY, "true");
    renderDetail(FLAGGED);

    expect(screen.getByRole("button", { name: /open anyway/i })).toBeTruthy();
  });
});
