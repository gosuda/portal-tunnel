import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { Mock } from "vitest";
import { describe, expect, it, vi } from "vitest";
import type { ReputationSummary } from "@/types/api";
import { ServerCard } from "./ServerCard";

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

const REPUTATION: ReputationSummary = {
  hostname: "minecraft.relay.example.com",
  up: 12,
  down: 8,
  total: 20,
  viewer_vote: "",
  comments: 5,
};

// Routes probe: the card sits on the directory route; navigation into
// /server/srv-1 would swap in the "service detail" marker.
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

  it("navigates to /server/:id route even when server.link is an external URL", () => {
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
                  reputation: REPUTATION,
                }}
              />
            }
          />
          <Route path="/server/cool-app" element={<div>reputation gate page</div>} />
        </Routes>
      </MemoryRouter>
    );

    const openLink = screen.getByRole("link", { name: "Open Cool App" });
    expect(openLink.getAttribute("href")).toBe("/server/cool-app");
    fireEvent.click(openLink);
    expect(screen.getByText("reputation gate page")).toBeTruthy();
  });

  it("toggles description disclosure via touch-accessible Info button without navigating", () => {
    const { onOpenComments } = renderCardWithComments();
    const infoButton = screen.getByRole("button", { name: "Show description" });
    expect(infoButton.getAttribute("aria-expanded")).toBe("false");

    // Open disclosure
    fireEvent.click(infoButton);
    expect(screen.getByRole("button", { name: "Hide description" })).toBeTruthy();
    expect(screen.getByText("Tap to close")).toBeTruthy();
    expect(screen.getByText("directory")).toBeTruthy();
    expect(screen.queryByText("service detail")).toBeNull();

    // Close disclosure by clicking X button
    fireEvent.click(screen.getByRole("button", { name: "Hide description" }));
    expect(screen.getByRole("button", { name: "Show description" })).toBeTruthy();
    expect(screen.queryByText("Tap to close")).toBeNull();
  });

  it("closes description disclosure when tapping directly on the overlay without navigating into the app", () => {
    renderCardWithComments();
    const infoButton = screen.getByRole("button", { name: "Show description" });

    // Open disclosure
    fireEvent.click(infoButton);
    expect(screen.getByText("Tap to close")).toBeTruthy();
    expect(screen.queryByText("service detail")).toBeNull();

    // Directly tap on the overlay ("Tap to close" text)
    fireEvent.click(screen.getByText("Tap to close"));
    expect(screen.queryByText("Tap to close")).toBeNull();
    expect(screen.getByRole("button", { name: "Show description" })).toBeTruthy();
    expect(screen.getByText("directory")).toBeTruthy();
    expect(screen.queryByText("service detail")).toBeNull();

    // Re-open and tap on the description paragraph text
    fireEvent.click(screen.getByRole("button", { name: "Show description" }));
    expect(screen.getByText("Tap to close")).toBeTruthy();

    fireEvent.click(screen.getByText("A cool sandbox game"));
    expect(screen.queryByText("Tap to close")).toBeNull();
    expect(screen.getByRole("button", { name: "Show description" })).toBeTruthy();
    expect(screen.getByText("directory")).toBeTruthy();
    expect(screen.queryByText("service detail")).toBeNull();
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
});
