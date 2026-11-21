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
  it("shows other relay origins as explicit external links", () => {
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
    expect(checkMore).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Check more relays" }));
    expect(checkMore).toHaveBeenCalledTimes(1);
    const remote = screen.getByRole("link", { name: /blog\.remote\.example/ });
    expect(remote.getAttribute("href")).toBe("https://blog.remote.example/");
    expect(remote.getAttribute("target")).toBe("_blank");
    expect(remote.getAttribute("rel")).toContain("noreferrer");
  });

  it("displays both current and remote relays with badges and reputation", () => {
    const locations = [
      { ...observation, relay_url: "https://local.example", url: "https://blog.local.example/", current_relay: true },
      { ...observation, relay_url: "https://remote2.example", url: "https://blog.remote2.example/", reputation: { up: 10, down: 2 } },
      { ...observation, relay_url: "https://remote3.example", url: "", reputation: { up: 0, down: 0 } },
    ];
    render(<ServiceRelaysPanel
      server={{ ...server, locations }}
      localReputation={{ up: 5, down: 1 }}
      loading={false}
      onCheckMore={vi.fn()}
      onClose={vi.fn()}
    />);

    expect(screen.getByText("blog.local.example")).toBeDefined();
    expect(screen.getByText("Current")).toBeDefined();
    expect(within(screen.getByRole("link", { name: /blog\.local\.example/ })).getByText("+5/-1")).toBeDefined();
    expect(screen.getByText("blog.remote2.example")).toBeDefined();
    expect(within(screen.getByRole("link", { name: /blog\.remote2\.example/ })).getByText("+10/-2")).toBeDefined();
    expect(screen.getByText("remote3.example")).toBeDefined();
    expect(screen.getByText("+0/-0")).toBeDefined();
    expect(screen.getByText("Unavailable")).toBeDefined();
  });

  it("shows unknown for missing local and remote observations despite a local vote fallback", () => {
    render(<ServiceRelaysPanel
      server={{
        ...server,
        reputation: { hostname: server.id, up: 0, down: 0, total: 0, viewer_vote: "" },
        locations: [observation],
      }}
      loading={false}
      onCheckMore={vi.fn()}
      onClose={vi.fn()}
    />);

    expect(within(screen.getByRole("link", { name: /blog\.local\.example/ })).getByText("Unknown")).toBeDefined();
    expect(within(screen.getByRole("link", { name: /blog\.remote\.example/ })).getByText("Unknown")).toBeDefined();
    expect(screen.queryByText("+0/-0")).toBeNull();
  });

  it("shows an observed local zero tally", () => {
    render(<ServiceRelaysPanel
      server={server}
      localReputation={{ up: 0, down: 0 }}
      loading={false}
      onCheckMore={vi.fn()}
      onClose={vi.fn()}
    />);

    expect(within(screen.getByRole("link", { name: /blog\.local\.example/ })).getByText("+0/-0")).toBeDefined();
    expect(screen.queryByText("Unknown")).toBeNull();
  });

  it("shows empty state when no relays exist for remote-only server with no locations", () => {
    render(<ServiceRelaysPanel
      server={{ ...server, remoteOnly: true, link: "", locations: [] }}
      loading={false}
      onCheckMore={vi.fn()}
      onClose={vi.fn()}
    />);

    expect(screen.getByText("No relays connected.")).toBeDefined();
  });
});
