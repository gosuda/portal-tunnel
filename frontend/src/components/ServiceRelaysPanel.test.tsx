import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ServiceRelaysPanel } from "./ServiceRelaysPanel";
import { mergeDiscoveredServices, type BaseServer } from "@/lib/server";
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
  it.each([true, false])("uses local service readiness for transport availability (online=%s)", (online) => {
    render(<ServiceRelaysPanel
      server={{ ...server, online, tcpAddr: "relay.local.example:50000" }}
      loading={false}
      onClose={vi.fn()}
    />);

    expect(screen.getByText("Current")).toBeDefined();
    if (online) {
      expect(screen.getByText("TCP")).toBeDefined();
      expect(screen.queryByText("Unavailable")).toBeNull();
    } else {
      expect(screen.getByText("Unavailable")).toBeDefined();
      expect(screen.queryByText("TCP")).toBeNull();
    }
  });

  it("shows other relay origins as explicit external links", () => {
    const address = "0x1111111111111111111111111111111111111111";
    render(<ServiceRelaysPanel
      server={{ id: "blog.local.example", name: "blog", serviceName: "blog", address, description: "", tags: [], thumbnail: "", owner: "", online: true, dns: "blog.local.example", link: "https://blog.local.example/" }}
      loading={false}
      onClose={vi.fn()}
      response={{ services: [{ name: "blog", address, metadata: {}, locations: [
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

    expect(screen.getByText("No relays found.")).toBeDefined();
  });

  it("shows each relay's own protocol and copies its own address", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    render(<ServiceRelaysPanel
      server={{
        ...server,
        remoteOnly: true,
        link: "",
        tcpAddr: "a.example:40000",
        locations: [
          { ...observation, relay_url: "https://a.example", url: undefined, tcp_addr: "a.example:40000" },
          { ...observation, relay_url: "https://b.example", url: undefined, udp_addr: "b.example:40001" },
          { ...observation, relay_url: "https://c.example", url: "https://blog.c.example/" },
        ],
      }}
      loading={false}
      onClose={vi.fn()}
    />);

    const tcp = screen.getAllByRole("button", { name: /^Copy TCP / });
    const udp = screen.getAllByRole("button", { name: /^Copy UDP / });
    expect(tcp.map((button) => button.getAttribute("aria-label"))).toEqual(["Copy TCP a.example:40000"]);
    expect(udp.map((button) => button.getAttribute("aria-label"))).toEqual(["Copy UDP b.example:40001"]);
    expect(screen.getByRole("link", { name: /blog\.c\.example/ }).getAttribute("href")).toBe("https://blog.c.example/");

    fireEvent.click(udp[0]);
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("b.example:40001"));
    expect(await screen.findByText("Copied!")).toBeDefined();
  });

  it("does not show a remote TCP address on the current relay row", () => {
    const local = { id: "game.local.example", name: "game", serviceName: "game", address: server.address, description: "", tags: [], thumbnail: "", owner: "", online: true, dns: "game.local.example", link: "https://game.local.example/" };
    const [merged] = mergeDiscoveredServices([local], [{
      name: "game", address: server.address!, metadata: {}, locations: [
        { ...observation, relay_url: "https://b.example", url: undefined, tcp_addr: "b.example:40000" },
      ],
    }], server.address);
    render(<ServiceRelaysPanel server={merged} loading={false} onClose={vi.fn()} />);

    expect(screen.getByRole("link", { name: /game\.local\.example/ }).getAttribute("href")).toBe("https://game.local.example/");
    expect(screen.getAllByRole("button", { name: /^Copy TCP / }).map((button) => button.getAttribute("aria-label"))).toEqual(["Copy TCP b.example:40000"]);
  });

  it("keeps an expired transport relay unavailable and not copyable", () => {
    render(<ServiceRelaysPanel
      server={{
        ...server,
        remoteOnly: true,
        link: "",
        locations: [{ ...observation, relay_url: "https://a.example", url: undefined, tcp_addr: "a.example:40000", expires_at: new Date(Date.now() - 1).toISOString() }],
      }}
      loading={false}
      onClose={vi.fn()}
    />);

    expect(screen.getByText("Unavailable")).toBeDefined();
    expect(screen.queryByRole("button", { name: /^Copy / })).toBeNull();
  });
});
