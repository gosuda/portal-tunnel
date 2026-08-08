import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { Mock } from "vitest";
import { describe, expect, it, vi } from "vitest";
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
});
