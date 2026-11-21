import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { Mock } from "vitest";
import { describe, expect, it, vi } from "vitest";
import type { ReputationSummary } from "@/types/api";
import { leaseToServer, mergeDiscoveredServices } from "@/lib/server";
import { ServerCard } from "./ServerCard";
import { createConstellationData } from "./constellation";

const TCP = "minecraft.relay.example.com:50000";
const UDP = "minecraft.relay.example.com:50001";

function renderCard(props: { tcpAddr?: string; udpAddr?: string }) {
  return render(
    <MemoryRouter>
      <ServerCard
        server={{
          id: "srv-1",
          name: "minecraft",
          description: "",
          tags: [],
          thumbnail: "",
          owner: "",
          online: true,
          dns: "minecraft.relay.example.com",
          link: "/server/srv-1",
          ...props,
        }}
      />
    </MemoryRouter>
  );
}

function stubClipboard(writeText: Mock) {
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
}
function copyButton(address: string) {
  const row = screen.getByText(address).parentElement;
  if (!row) {
    throw new Error(`no endpoint row rendered for ${address}`);
  }
  return within(row).getByRole("button");
}

async function clickCopy(address: string) {
  await act(async () => {
    fireEvent.click(copyButton(address));
  });
}

describe("ServerCard raw transport endpoints", () => {
  it("copies each endpoint from its own control", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    stubClipboard(writeText);
    renderCard({ tcpAddr: TCP, udpAddr: UDP });

    await clickCopy(UDP);
    expect(writeText).toHaveBeenCalledWith(UDP);

    await clickCopy(TCP);
    expect(writeText).toHaveBeenCalledWith(TCP);
  });

  it("confirms only the endpoint that was copied", async () => {
    stubClipboard(vi.fn().mockResolvedValue(undefined));
    renderCard({ tcpAddr: TCP, udpAddr: UDP });

    await clickCopy(UDP);

    expect(copyButton(UDP).textContent).toBe("Copied!");
    expect(copyButton(TCP).textContent).toBe("Copy TCP");
  });

  it("does not claim success when the clipboard rejects", async () => {
    stubClipboard(vi.fn().mockRejectedValue(new Error("denied")));
    renderCard({ tcpAddr: TCP });

    await clickCopy(TCP);

    expect(copyButton(TCP).textContent).toBe("Copy TCP");
  });

  it("keeps a plain service navigable instead of copyable", () => {
    renderCard({});

    expect(screen.queryByRole("button", { name: /^Copy / })).toBeNull();
    for (const link of screen.getAllByRole("link", { name: "Open minecraft" })) {
      expect(link.getAttribute("href")).toBe("/server/srv-1");
    }
  });

  it("keeps every copy control keyboard reachable and outside a link", () => {
    renderCard({ tcpAddr: TCP, udpAddr: UDP });

    for (const address of [TCP, UDP]) {
      const button = copyButton(address);
      button.focus();
      expect(document.activeElement).toBe(button);
      expect(button.closest("a")).toBeNull();
    }
  });
});

const REPUTATION: ReputationSummary = {
  hostname: "minecraft.relay.example.com",
  up: 12,
  down: 8,
  total: 20,
  viewer_vote: "",
  comments: 5,
};

function renderCardWithComments() {
  const onOpenComments = vi.fn();
  render(
    <MemoryRouter initialEntries={["/"]}>
      <Routes>
        <Route
          path="/"
          element={
            <>
              <div>directory</div>
              <ServerCard
                server={{
                  id: "srv-1",
                  name: "minecraft",
                  description: "A cool sandbox game",
                  tags: ["game"],
                  thumbnail: "",
                  owner: "notch",
                  online: true,
                  dns: "minecraft.relay.example.com",
                  link: "/server/srv-1",
                  reputation: REPUTATION,
                }}
                onOpenComments={onOpenComments}
              />
            </>
          }
        />
        <Route path="/server/srv-1" element={<div>service detail</div>} />
      </Routes>
    </MemoryRouter>
  );
  return { onOpenComments };
}

describe("ServerCard comments interaction", () => {
  it("displays remote observations without local vote controls or moderation labels", () => {
    render(
      <MemoryRouter>
        <ServerCard server={{
          id: "service:blog:owner", name: "blog", description: "", tags: [],
          thumbnail: "", owner: "", online: true, dns: "", link: "",
          remoteOnly: true, observedReputation: { up: 0, down: 10 },
        }} />
      </MemoryRouter>
    );
    expect(screen.getByText("Observed +0/−10")).toBeTruthy();
    expect(screen.queryByText("Hidden by downvotes")).toBeNull();
    expect(screen.queryByRole("button", { name: "Recommend app" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Do not recommend app" })).toBeNull();
  });

  it("opens the app's comments without navigating into the service", () => {
    const { onOpenComments } = renderCardWithComments();
    fireEvent.click(screen.getByRole("button", { name: "Comments" }));

    expect(onOpenComments).toHaveBeenCalledWith(expect.objectContaining({ id: "srv-1" }));
    expect(screen.getByText("directory")).toBeTruthy();
    expect(screen.queryByText("service detail")).toBeNull();
  });

  it("displays upvotes, downvotes, and comment counts", () => {
    renderCardWithComments();

    expect(screen.getByTitle("Recommend: 12")).toBeTruthy();
    expect(screen.getByTitle("Do not recommend: 8")).toBeTruthy();
    expect(screen.getByTitle("Comments: 5")).toBeTruthy();
    expect(screen.getByText("12")).toBeTruthy();
    expect(screen.getByText("8")).toBeTruthy();
    expect(screen.getByText("5")).toBeTruthy();
  });

  it("renders description in hover overlay and removes hamburger details menu", () => {
    renderCardWithComments();

    expect(screen.getByText("A cool sandbox game")).toBeTruthy();
    expect(screen.queryByLabelText(/Actions for/i)).toBeNull();
  });

  it("navigates to /server/:id route when app has reputation warning", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route
            path="/"
            element={
              <ServerCard
                server={{
                  id: "cool-app",
                  name: "Cool App",
                  description: "A secure app",
                  tags: [],
                  thumbnail: "",
                  owner: "alice",
                  online: true,
                  dns: "cool.relay.example.com",
                  link: "https://cool.relay.example.com/",
                  reputation: {
                    hostname: "cool.relay.example.com",
                    up: 1,
                    down: 5,
                    total: 6,
                    viewer_vote: "",
                    comments: 0,
                  },
                }}
              />
            }
          />
          <Route path="/server/cool-app" element={<div>reputation gate page</div>} />
        </Routes>
      </MemoryRouter>
    );

    for (const link of screen.getAllByRole("link", { name: "Open Cool App" })) {
      expect(link.getAttribute("href")).toBe("/server/cool-app");
    }
    fireEvent.click(screen.getByText("Cool App"));
    expect(screen.getByText("reputation gate page")).toBeTruthy();
  });

  it("links directly to server.link when app has no reputation warning", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <ServerCard
          server={{
            id: "cool-app",
            name: "Cool App",
            description: "A secure app",
            tags: [],
            thumbnail: "",
            owner: "alice",
            online: true,
            dns: "cool.relay.example.com",
            link: "https://cool.relay.example.com/",
            reputation: REPUTATION,
          }}
        />
      </MemoryRouter>
    );

    for (const link of screen.getAllByRole("link", { name: "Open Cool App" })) {
      expect(link.getAttribute("href")).toBe("https://cool.relay.example.com/");
    }
  });

  it("lists a legacy HTTP lease with no link to open", () => {
    const address = "0x1111111111111111111111111111111111111111";
    const server = leaseToServer({
      name: "blog", address, hostname: "", canonical_hostname: `blog-${address.slice(2)}.relay.example`,
      first_seen_at: "", last_seen_at: "", expires_at: "", metadata: {}, ready: 1,
    });
    render(<MemoryRouter><ServerCard server={server} onOpenRelays={vi.fn()} /></MemoryRouter>);

    expect(screen.getByRole("heading", { name: "blog" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Open blog" })).toBeNull();
    expect(screen.getByRole("button", { name: /1 relay connected/ })).toBeTruthy();
  });

  it("shows an unnamed remote service with only a relay observation", () => {
    const address = "0x1111111111111111111111111111111111111111";
    const [server] = mergeDiscoveredServices([], [{
      name: "", address, metadata: {}, locations: [{
        relay_url: "https://older.example", current_relay: false, reported_ready: true,
        observed_at: "2026-11-16T00:00:00Z", expires_at: "2026-11-16T00:00:30Z", verification: "relay-reported",
      }],
    }], address);
    const openRelays = vi.fn();
    render(<MemoryRouter><ServerCard server={server} onOpenRelays={openRelays} /></MemoryRouter>);

    expect(screen.getByRole("heading", { name: "(unnamed)" })).toBeTruthy();
    expect(screen.getByText(/No HTTP URL available/)).toBeTruthy();
    expect(screen.queryByRole("link", { name: /^Open / })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /1 relay connected/ }));
    expect(openRelays).toHaveBeenCalledWith(server);
  });

  it("renders description and tags in overlay alongside transport endpoints", () => {
    render(
      <MemoryRouter>
        <ServerCard
          server={{
            id: "tcp-srv",
            name: "TCP Srv",
            description: "Dedicated TCP game server",
            tags: ["game"],
            thumbnail: "",
            owner: "admin",
            online: true,
            dns: "tcp.relay.example.com",
            link: "",
            tcpAddr: "tcp.relay.example.com:40000",
          }}
        />
      </MemoryRouter>
    );

    expect(screen.getByTitle("tcp.relay.example.com:40000")).toBeTruthy();
    expect(screen.getByText("Dedicated TCP game server")).toBeTruthy();
    expect(screen.getByText("#game")).toBeTruthy();
    expect(screen.getByText("tcp.relay.example.com:40000")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy TCP" })).toBeTruthy();
  });

  it("allows direct voting from the card without navigating into the service", async () => {
    const onVote = vi.fn().mockResolvedValue(undefined);
    render(
      <MemoryRouter>
        <ServerCard
          server={{
            id: "srv-1",
            name: "minecraft",
            description: "",
            tags: [],
            thumbnail: "",
            owner: "",
            online: true,
            dns: "minecraft.relay.example.com",
            link: "/server/srv-1",
            reputation: REPUTATION,
          }}
          onVote={onVote}
        />
      </MemoryRouter>
    );

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Recommend app" }));
    });
    expect(onVote).toHaveBeenCalledWith("srv-1", "up");

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Do not recommend app" }));
    });
    expect(onVote).toHaveBeenCalledWith("srv-1", "down");
  });

  it("does not render rating or comment controls when in admin mode or actions are omitted", () => {
    render(
      <MemoryRouter>
        <ServerCard
          server={{
            id: "srv-admin",
            name: "admin-app",
            description: "",
            tags: [],
            thumbnail: "",
            owner: "",
            online: true,
            dns: "admin.relay.example.com",
            link: "/server/srv-admin",
          }}
        >
          <div>admin controls</div>
        </ServerCard>
      </MemoryRouter>
    );

    expect(screen.queryByLabelText("Recommend app")).toBeNull();
    expect(screen.queryByLabelText("Do not recommend app")).toBeNull();
    expect(screen.queryByLabelText("Comments")).toBeNull();
    expect(screen.getByText("admin-app")).toBeTruthy();
    expect(screen.getByText("admin controls")).toBeTruthy();
  });

  it("opens local apps in the same tab", () => {
    render(
      <MemoryRouter>
        <ServerCard server={leaseToServer({
          name: "local-app", address: "", hostname: "local-app.relay.example.com", canonical_hostname: "",
          first_seen_at: "", last_seen_at: "", expires_at: "", metadata: {}, ready: 1,
        })} />
      </MemoryRouter>
    );

    const links = screen.getAllByRole("link", { name: "Open local-app" });
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(link.getAttribute("href")).toBe("https://local-app.relay.example.com/");
      expect(link.getAttribute("target")).toBeNull();
    }
  });

  it("navigates remote services directly using an available relay location", () => {
    const address = "0x1111111111111111111111111111111111111111";
    const live = {
      current_relay: false,
      reported_ready: true,
      observed_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 30_000).toISOString(),
      verification: "relay-reported",
    } as const;
    const [server] = mergeDiscoveredServices([], [{
      name: "remote-app", address, metadata: {}, locations: [
        { ...live, relay_url: "https://stale.example.com", url: "https://remote-app.stale.example.com/", expires_at: new Date(Date.now() - 1).toISOString() },
        { ...live, relay_url: "https://down.example.com", url: "https://remote-app.down.example.com/", reported_ready: false },
        { ...live, relay_url: "https://plain.example.com", url: "http://remote-app.plain.example.com/" },
        { ...live, relay_url: "https://relay2.example.com", url: "https://remote-app.relay2.example.com/" },
      ],
    }], address);

    render(
      <MemoryRouter>
        <ServerCard server={server} />
      </MemoryRouter>
    );

    const links = screen.getAllByRole("link", { name: "Open remote-app" });
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(link.getAttribute("href")).toBe("https://remote-app.relay2.example.com/");
      expect(link.getAttribute("target")).toBe("_blank");
    }
  });

  it("lists a remote service without a link when no relay is available", () => {
    const address = "0x1111111111111111111111111111111111111111";
    const [server] = mergeDiscoveredServices([], [{
      name: "remote-app", address, metadata: {}, locations: [
        {
          relay_url: "https://stale.example.com", url: "https://remote-app.stale.example.com/",
          current_relay: false, reported_ready: true, verification: "relay-reported",
          observed_at: "2026-11-16T00:00:00Z", expires_at: "2026-11-16T00:00:30Z",
        },
        {
          relay_url: "https://down.example.com", url: "https://remote-app.down.example.com/",
          current_relay: false, reported_ready: false, verification: "relay-reported",
          observed_at: new Date().toISOString(), expires_at: new Date(Date.now() + 30_000).toISOString(),
        },
      ],
    }], address);

    render(<MemoryRouter><ServerCard server={server} onOpenRelays={vi.fn()} /></MemoryRouter>);

    expect(screen.getByRole("heading", { name: "remote-app" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Open remote-app" })).toBeNull();
    expect(screen.getByText(/No relay available now/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /2 relays connected/ })).toBeTruthy();
  });

  it("uses relay hostname for endpoint address when host is localhost or empty", () => {
    render(
      <MemoryRouter>
        <ServerCard
          server={{
            id: "tcp-srv",
            name: "TCP Srv",
            description: "",
            tags: [],
            thumbnail: "",
            owner: "",
            online: true,
            dns: "",
            link: "",
            tcpAddr: ":45000",
            locations: [{
              relay_url: "https://relay.portal.example.com",
              url: "",
              current_relay: true,
              reported_ready: true,
              observed_at: "",
              expires_at: "",
              verification: "relay-reported",
            }],
          }}
        />
      </MemoryRouter>
    );

    expect(screen.getByText("relay.portal.example.com:45000")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy TCP" })).toBeTruthy();
  });
});

describe("createConstellationData determinism", () => {
  it("renders the same sky for the same seed on every call", () => {
    const first = createConstellationData("portal");
    expect(createConstellationData("portal")).toEqual(first);
    expect(createConstellationData("  PORTAL  ")).toEqual(first);
  });
});
