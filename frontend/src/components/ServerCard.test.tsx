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

const REPUTATION: ReputationSummary = {
  hostname: "minecraft.relay.example.com",
  up: 12,
  down: 8,
  total: 20,
  viewer_vote: "",
};

// Routes probe: the card sits on the directory route; navigation into
// /server/srv-1 would swap in the "service detail" marker.
function renderVotingCard() {
  const onVote = vi.fn();
  render(
    <MemoryRouter initialEntries={["/"]}>
      <Routes>
        <Route
          path="/"
          element={
            <>
              <div>directory</div>
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
                reputation={REPUTATION}
                onVote={onVote}
              />
            </>
          }
        />
        <Route path="/server/srv-1" element={<div>service detail</div>} />
      </Routes>
    </MemoryRouter>
  );
  return onVote;
}

describe("ServerCard community reputation votes", () => {
  it("renders counts and votes without navigating the card", async () => {
    const onVote = renderVotingCard();

    expect(screen.getByText("12")).toBeTruthy();
    expect(screen.getByText("8")).toBeTruthy();

    await act(async () => fireEvent.click(screen.getByRole("button", { name: "Recommend" })));
    expect(onVote).toHaveBeenCalledWith("minecraft.relay.example.com", "up");

    await act(async () => fireEvent.click(screen.getByRole("button", { name: "Not recommend" })));
    expect(onVote).toHaveBeenCalledWith("minecraft.relay.example.com", "down");

    expect(screen.getByText("directory")).toBeTruthy();
    expect(screen.queryByText("service detail")).toBeNull();
  });

  it("keeps vote controls keyboard reachable without navigating", async () => {
    const onVote = renderVotingCard();

    for (const name of ["Recommend", "Not recommend"]) {
      const button = screen.getByRole("button", { name });
      button.focus();
      expect(document.activeElement).toBe(button);
    }

    await act(async () => fireEvent.click(screen.getByRole("button", { name: "Recommend" })));
    expect(onVote).toHaveBeenCalledWith("minecraft.relay.example.com", "up");
    expect(screen.getByText("directory")).toBeTruthy();
    expect(screen.queryByText("service detail")).toBeNull();
  });
});
