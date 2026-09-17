import { useEffect } from "react";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import type { Mock } from "vitest";
import { describe, expect, it, vi } from "vitest";
import { ServerCard } from "./ServerCard";
import type { ReputationSummary } from "@/types/api";

const TCP = "minecraft.relay.example.com:50000";
const UDP = "minecraft.relay.example.com:50001";

function renderCard(props: { tcpAddr?: string; udpAddr?: string }) {
  return render(
    <MemoryRouter>
      <ServerCard
        serverId="srv-1"
        name="minecraft"
        description=""
        tags={[]}
        thumbnail=""
        owner=""
        online
        dns="minecraft.relay.example.com"
        navigationPath="/server/srv-1"
        navigationState={null}
        {...props}
      />
    </MemoryRouter>
  );
}

function stubClipboard(writeText: Mock) {
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
}
// Their markup renders one row per endpoint: the address in a <code>, the copy
// control beside it. Scope by address, because a copied button's label drops
// the protocol and would otherwise match its sibling.
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
    expect(screen.getByRole("link")).toBeTruthy();
  });

  // The card once made the whole surface a <div onClick>, which no keyboard
  // could reach. Wrapping these buttons back in a <Link> would nest
  // interactive content instead, so pin both halves: reachable, not nested.
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

describe("ServerCard public card height", () => {
  // A public card (non-admin, no transport) must not clip content when it shows
  // the full set: name + description + tags + reputation row + owner + favorite.
  // This is the "name+desc+tags+reputation+vote" path that was reported as clipped.
  it("does not clip content in a full-featured public card", () => {
    const onVote = vi.fn();
    render(
      <MemoryRouter>
        <ServerCard
          serverId="full-card-srv"
          name="Minecraft Relay"
          description="A great Minecraft server"
          tags={["gaming", "minecraft", "creative"]}
          thumbnail=""
          owner="ExampleOwner"
          online
          dns="mc.example.com"
          navigationPath="/server/full-card-srv"
          navigationState={null}
          reputation={{
            up: 10,
            down: 2,
            total: 12,
            down_ratio: 0.17,
            warning: false,
            viewer_vote: "up",
            is_new: false,
            identity_changed_recently: false,
          }}
          onVote={onVote}
        />
      </MemoryRouter>
    );

    // All content must be visible — none clipped by overflow:hidden on the card.
    expect(screen.getByRole("heading", { name: /Minecraft Relay/i })).toBeTruthy();
    expect(screen.getByText("A great Minecraft server")).toBeTruthy();
    expect(screen.getByText("by ExampleOwner")).toBeTruthy();
    // Tags
    expect(screen.getByText("#gaming")).toBeTruthy();
    expect(screen.getByText("#minecraft")).toBeTruthy();
    // Vote row
    expect(screen.getByRole("button", { name: /upvote/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /downvote/i })).toBeTruthy();
    // The article element has data-hero-key="server-bg-{serverId}"; verify it renders.
    const card = document.querySelector("[data-hero-key='server-bg-full-card-srv']");
    expect(card).toBeTruthy();
    expect(card?.tagName).toBe("ARTICLE");
  });

  it("keeps vote counts visible when description is long", () => {
    const onVote = vi.fn();
    render(
      <MemoryRouter>
        <ServerCard
          serverId="long-desc"
          name="Relay"
          description="This is a very long description that could cause clipping if the card height is too constrained for all the content to fit"
          tags={["tag1", "tag2", "tag3", "tag4", "tag5"]}
          thumbnail=""
          owner="Owner"
          online
          dns="relay.example.com"
          navigationPath="/server/long-desc"
          navigationState={null}
          reputation={{
            up: 5,
            down: 1,
            total: 6,
            down_ratio: 0.17,
            warning: false,
            viewer_vote: "",
            is_new: true,
            identity_changed_recently: false,
          }}
          onVote={onVote}
        />
      </MemoryRouter>
    );

    // Vote counts must be present (not clipped off)
    expect(screen.getByRole("button", { name: /upvote/i }).textContent).toContain("5");
    expect(screen.getByRole("button", { name: /downvote/i }).textContent).toContain("1");
  });
});

describe("ServerCard reputation", () => {
  const HOSTNAME = "minecraft.relay.example.com";

  function reputationFixture(overrides?: Partial<ReputationSummary>) {
    return {
      up: 3,
      down: 7,
      total: 10,
      down_ratio: 0.7,
      warning: true,
      viewer_vote: "",
      is_new: true,
      identity_changed_recently: false,
      first_seen_at: "2026-09-01T00:00:00Z",
      ...overrides,
    } satisfies ReputationSummary;
  }

  // The public directory wraps non-transport cards in a <Link>, so a vote
  // click that leaks would navigate. The location probe observes the real
  // router instead of trusting the mock.
  function renderRoutedCard(props?: {
    reputation?: ReputationSummary;
    onVote?: (hostname: string, vote: "up" | "down") => void;
  }) {
    let pathname = "/list";
    function LocationProbe() {
      const location = useLocation();
      // Captured in an effect: writing an outer variable during render tears
      // under concurrent mode and trips react-hooks/globals.
      useEffect(() => {
        pathname = location.pathname;
      }, [location.pathname]);
      return null;
    }
    render(
      <MemoryRouter initialEntries={["/list"]}>
        <Routes>
          <Route
            path="/list"
            element={
              <ServerCard
                serverId={HOSTNAME}
                name="minecraft"
                description=""
                tags={[]}
                thumbnail=""
                owner=""
                online
                dns={HOSTNAME}
                navigationPath={`/server/${HOSTNAME}`}
                navigationState={null}
                reputation={props?.reputation}
                onVote={props?.onVote}
              />
            }
          />
          <Route path={`/server/${HOSTNAME}`} element={<p>detail page</p>} />
        </Routes>
        <LocationProbe />
      </MemoryRouter>
    );
    return { pathname: () => pathname };
  }

  it("renders vote counts, viewer highlight, and the new badge", () => {
    renderRoutedCard({
      reputation: reputationFixture({ viewer_vote: "up" }),
      onVote: vi.fn(),
    });

    expect(screen.getByText("New")).toBeTruthy();
    expect(
      screen
        .getByRole("button", { name: "Upvote this service" })
        .getAttribute("aria-pressed")
    ).toBe("true");
    expect(
      screen
        .getByRole("button", { name: "Downvote this service" })
        .getAttribute("aria-pressed")
    ).toBe("false");
    expect(screen.getByRole("button", { name: "Upvote this service" }).textContent).toContain("3");
    expect(screen.getByRole("button", { name: "Downvote this service" }).textContent).toContain("7");
  });

  it("votes with the hostname without navigating off the card", async () => {
    const onVote = vi.fn();
    const { pathname } = renderRoutedCard({
      reputation: reputationFixture(),
      onVote,
    });

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Downvote this service" }));
    });

    expect(onVote).toHaveBeenCalledWith(HOSTNAME, "down");
    expect(pathname()).toBe("/list");
  });

  it("renders no vote row when voting is unavailable", () => {
    renderRoutedCard({ reputation: reputationFixture() });

    expect(screen.queryByRole("button", { name: "Upvote this service" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Downvote this service" })).toBeNull();
    expect(screen.getByText("New")).toBeTruthy();
  });

  it("toggles the pressed highlight when the viewer's own vote changes", () => {
    renderRoutedCard({
      reputation: reputationFixture({ viewer_vote: "down" }),
      onVote: vi.fn(),
    });

    expect(
      screen
        .getByRole("button", { name: "Downvote this service" })
        .getAttribute("aria-pressed")
    ).toBe("true");
    expect(
      screen
        .getByRole("button", { name: "Upvote this service" })
        .getAttribute("aria-pressed")
    ).toBe("false");
  });
});
