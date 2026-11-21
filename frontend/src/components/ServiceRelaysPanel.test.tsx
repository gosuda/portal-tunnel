import { render, screen } from "@testing-library/react";
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
  observed_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 60_000).toISOString(),
};

describe("relay selection", () => {
  it("shows other relay origins as explicit external links", () => {
    const address = "0x1111111111111111111111111111111111111111";
    render(<ServiceRelaysPanel
      server={{ id: "blog.local.example", name: "blog", serviceName: "blog", address, description: "", tags: [], thumbnail: "", owner: "", online: true, dns: "blog.local.example", link: "https://blog.local.example/" }}
      loading={false}
      onClose={vi.fn()}
      response={{ partial: true, relays_checked: 3, relays_skipped: 1, services: [{ name: "blog", address, metadata: {}, locations: [
        { ...observation, relay_url: "https://remote.example", url: "https://blog.remote.example/" },
        { ...observation, relay_url: "https://older.example", url: undefined },
      ] }] }}
    />);
    expect(screen.queryByRole("button", { name: "Check more relays" })).toBeNull();
    const remote = screen.getByRole("link", { name: /blog\.remote\.example/ });
    expect(remote.getAttribute("href")).toBe("https://blog.remote.example/");
    expect(remote.getAttribute("target")).toBe("_blank");
    expect(remote.getAttribute("rel")).toContain("noreferrer");
  });

  it("displays both current and remote relays with badges", () => {
    const locations = [
      { ...observation, relay_url: "https://local.example", url: "https://blog.local.example/", current_relay: true },
      { ...observation, relay_url: "https://remote2.example", url: "https://blog.remote2.example/" },
      { ...observation, relay_url: "https://remote3.example", url: "" },
    ];
    render(<ServiceRelaysPanel
      server={{ ...server, locations }}
      loading={false}
      onClose={vi.fn()}
    />);

    expect(screen.getByText("blog.local.example")).toBeDefined();
    expect(screen.getByText("Current")).toBeDefined();
    expect(screen.getByText("blog.remote2.example")).toBeDefined();
    expect(screen.getByText("remote3.example")).toBeDefined();
    expect(screen.getByText("Unavailable")).toBeDefined();
    expect(screen.queryByText("+0/-0")).toBeNull();
    expect(screen.queryByText("Unknown")).toBeNull();
  });

  it("lists expired, not-ready, and non-HTTPS relays without links", () => {
    const locations = [
      { ...observation, relay_url: "https://stale.example", url: "https://blog.stale.example/", expires_at: new Date(Date.now() - 1).toISOString() },
      { ...observation, relay_url: "https://down.example", url: "https://blog.down.example/", reported_ready: false },
      { ...observation, relay_url: "https://plain.example", url: "http://blog.plain.example/" },
      { ...observation, relay_url: "https://live.example", url: "https://blog.live.example/" },
    ];
    render(<ServiceRelaysPanel
      server={{ ...server, remoteOnly: true, link: "", locations }}
      loading={false}
      onClose={vi.fn()}
    />);

    const links = screen.getAllByRole("link");
    expect(links.map((link) => link.getAttribute("href"))).toEqual(["https://blog.live.example/"]);
    expect(screen.getByText("blog.stale.example")).toBeDefined();
    expect(screen.getByText("blog.down.example")).toBeDefined();
    expect(screen.getByText("blog.plain.example")).toBeDefined();
    expect(screen.getAllByText("Unavailable")).toHaveLength(3);
  });

  it("shows empty state when no relays exist for remote-only server with no locations", () => {
    render(<ServiceRelaysPanel
      server={{ ...server, remoteOnly: true, link: "", locations: [] }}
      loading={false}
      onClose={vi.fn()}
    />);

    expect(screen.getByText("No relays connected.")).toBeDefined();
  });

  it("disables links for TCP/UDP transport services in relays panel", () => {
    render(<ServiceRelaysPanel
      server={{
        ...server,
        tcpAddr: "relay.local.example:50000",
        locations: [
          { ...observation, relay_url: "https://remote.example", url: "https://blog.remote.example/" },
        ],
      }}
      loading={false}
      onClose={vi.fn()}
    />);

    expect(screen.queryByRole("link", { name: /blog\.remote\.example/ })).toBeNull();
    expect(screen.queryByText("blog.remote.example")).toBeNull();
    expect(screen.getByText("remote.example")).toBeDefined();
    expect(screen.getAllByText("TCP").length).toBeGreaterThanOrEqual(1);
  });
});
