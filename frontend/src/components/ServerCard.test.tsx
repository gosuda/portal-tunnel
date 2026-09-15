import { act, fireEvent, render, screen, within } from "@testing-library/react";
import type { Mock } from "vitest";
import { describe, expect, it, vi } from "vitest";
import { ServerCard } from "./ServerCard";
import type { BaseServer } from "@/hooks/useList";

const TCP = "minecraft.relay.example.com:50000";
const UDP = "minecraft.relay.example.com:50001";

function makeServer(overrides: Partial<BaseServer> = {}): BaseServer {
  return {
    id: "srv-1",
    name: "minecraft",
    description: "",
    tags: [],
    thumbnail: "",
    owner: "",
    online: true,
    dns: "minecraft.relay.example.com",
    link: "https://minecraft.relay.example.com/",
    ...overrides,
  };
}

function renderCard(overrides: Partial<BaseServer> = {}) {
  return render(
    <ServerCard
      server={makeServer(overrides)}
      isFavorite={false}
      onToggleFavorite={vi.fn()}
    />,
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
    renderCard({ tcpAddr: TCP, udpAddr: UDP, link: "" });

    await clickCopy(UDP);
    expect(writeText).toHaveBeenCalledWith(UDP);

    await clickCopy(TCP);
    expect(writeText).toHaveBeenCalledWith(TCP);
  });

  it("confirms only the endpoint that was copied", async () => {
    stubClipboard(vi.fn().mockResolvedValue(undefined));
    renderCard({ tcpAddr: TCP, udpAddr: UDP, link: "" });

    await clickCopy(UDP);

    expect(copyButton(UDP).textContent).toBe("Copied!");
    expect(copyButton(TCP).textContent).toBe("Copy TCP");
  });

  it("does not claim success when the clipboard rejects", async () => {
    stubClipboard(vi.fn().mockRejectedValue(new Error("denied")));
    renderCard({ tcpAddr: TCP, link: "" });

    await clickCopy(TCP);

    expect(copyButton(TCP).textContent).toBe("Copy TCP");
  });

  it("keeps a plain service navigable instead of copyable", () => {
    renderCard();

    expect(screen.queryByRole("button", { name: /^Copy / })).toBeNull();
    expect(screen.getByRole("link")).toBeTruthy();
  });

  // The card once made the whole surface a <div onClick>, which no keyboard
  // could reach. Wrapping these buttons back in a <Link> would nest
  // interactive content instead, so pin both halves: reachable, not nested.
  it("keeps every copy control keyboard reachable and outside a link", () => {
    renderCard({ tcpAddr: TCP, udpAddr: UDP, link: "" });

    for (const address of [TCP, UDP]) {
      const button = copyButton(address);
      button.focus();
      expect(document.activeElement).toBe(button);
      expect(button.closest("a")).toBeNull();
    }
  });
});

describe("ServerCard payment badge", () => {
  // payment_enabled is the explicit capability flag; a leftover label alone
  // must not re-enable the badge or disagree with the page-level paid count.
  it("shows the badge for paymentEnabled with the default label fallback", () => {
    renderCard({ paymentEnabled: true });

    expect(screen.getByText("Paid app")).toBeTruthy();
  });

  it("shows the declared label when payment is enabled", () => {
    renderCard({ paymentEnabled: true, paymentLabel: "x402 USDC" });

    expect(screen.getByText("x402 USDC")).toBeTruthy();
  });

  it("does not show a badge from a payment label without paymentEnabled", () => {
    renderCard({ paymentEnabled: false, paymentLabel: "x402 USDC" });

    expect(screen.queryByText("x402 USDC")).toBeNull();
    expect(screen.queryByText("Paid app")).toBeNull();
  });
});
