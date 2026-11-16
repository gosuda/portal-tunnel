import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ServiceRelaysPanel } from "./ServiceRelaysPanel";
import type { BaseServer } from "@/lib/server";
import type { ServiceLocation } from "@/types/api";

const server: BaseServer = {
  id: "blog.local.example", name: "blog", serviceName: "blog",
  address: "0x1111111111111111111111111111111111111111",
  description: "", tags: [], thumbnail: "", owner: "", online: true,
  dns: "blog.local.example", link: "https://blog.local.example/",
};

const observation: ServiceLocation = {
  relay_url: "https://remote.example",
  url: "https://blog.remote.example/",
  current_relay: false,
  reported_ready: true,
  verification: "relay-reported",
  observed_at: "2026-11-16T00:00:00Z",
  expires_at: "2026-11-16T00:00:30Z",
};

describe("relay selection", () => {
  it("shows distinct origins as explicit external links with unverified observations", () => {
    const address = "0x1111111111111111111111111111111111111111";
    const checkMore = vi.fn();
    render(<ServiceRelaysPanel
      server={{ id: "blog.local.example", name: "blog", serviceName: "blog", address, description: "", tags: [], thumbnail: "", owner: "", online: true, dns: "blog.local.example", link: "https://blog.local.example/" }}
      loading={false}
      onCheckMore={checkMore}
      onClose={vi.fn()}
      response={{ partial: true, relays_checked: 2, relays_skipped: 1, services: [{ name: "blog", address, metadata: {}, locations: [
        { relay_url: "https://remote.example", url: "https://blog.remote.example/", current_relay: false, reported_ready: true, verification: "relay-reported", observed_at: "2026-11-16T00:00:00Z", expires_at: "2026-11-16T00:00:30Z" },
      ] }] }}
    />);
    expect(screen.getByText(/without independent proof/)).toBeDefined();
    expect(screen.getByText(/Other relay locations may exist/)).toBeDefined();
    expect(checkMore).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Check more relays" }));
    expect(checkMore).toHaveBeenCalledTimes(1);
    const remote = screen.getByRole("link", { name: "https://blog.remote.example/" });
    expect(remote.getAttribute("href")).toBe("https://blog.remote.example/");
    expect(remote.getAttribute("target")).toBe("_blank");
    expect(remote.getAttribute("rel")).toContain("noreferrer");
    expect(screen.getByRole("link", { name: /Open current relay/ }).getAttribute("href")).toBe("https://blog.local.example/");
  });
  it("totals only known sources, preserves attribution, and treats an actual zero as reported", () => {
    const locations = [
      { ...observation, relay_url: "https://local.example", current_relay: true },
      { ...observation, reputation: { up: 3, down: 2 } },
      { ...observation, relay_url: "https://old.example", url: undefined },
      { ...observation, relay_url: "https://invalid.example", reputation: { up: -1, down: 2 } },
    ];
    render(<ServiceRelaysPanel
      server={{ ...server, locations }}
      localReputation={{ up: 0, down: 0 }}
      loading={false}
      onCheckMore={vi.fn()}
      onClose={vi.fn()}
      response={{ partial: true, relays_checked: 4, relays_skipped: 1, services: [] }}
    />);

    const aggregate = screen.getByRole("region", { name: "Observed reputation" });
    expect(within(aggregate).getByText("3 up · 2 down across 2 of 4 shown relays")).toBeDefined();
    expect(within(aggregate).getByText(/not unique voters or a global score/)).toBeDefined();
    const rows = screen.getAllByRole("listitem");
    expect(within(rows[0]).getByText("Reputation: 0 up · 0 down")).toBeDefined();
    expect(within(rows[1]).getByText("Reputation: 3 up · 2 down")).toBeDefined();
    expect(within(rows[2]).getByText("Reputation: not reported")).toBeDefined();
    expect(within(rows[3]).getByText("Reputation: not reported")).toBeDefined();
  });

  it("does not count a local voter's fallback zero or create a local source for remote-only services", () => {
    const { rerender } = render(<ServiceRelaysPanel
      server={{ ...server, reputation: { hostname: server.id, up: 0, down: 0, total: 0, viewer_vote: "" } }}
      loading={false}
      onCheckMore={vi.fn()}
      onClose={vi.fn()}
    />);
    expect(screen.getByText("No reputation counts were observed.")).toBeDefined();
    expect(screen.getByText("This relay: reputation not reported")).toBeDefined();

    rerender(<ServiceRelaysPanel
      server={{ ...server, remoteOnly: true, link: "", locations: [{ ...observation, reputation: { up: 2, down: 1 } }] }}
      loading={false}
      onCheckMore={vi.fn()}
      onClose={vi.fn()}
      response={{ partial: false, relays_checked: 2, relays_skipped: 0, services: [] }}
    />);
    expect(screen.getByText("2 up · 1 down across 1 of 1 shown relays")).toBeDefined();
    expect(screen.queryByText(/This relay:/)).toBeNull();
  });

});
