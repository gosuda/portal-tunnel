import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AdminServerCard } from "./AdminServerCard";
import type { AdminServer } from "@/hooks/useAdmin";

// Regression pin: the slider-index initializer used to read the BPS step
// table before its declaration, so rendering any lease with bps > 0 threw
// "Cannot access 'bpsSteps' before initialization". Render a positive BPS
// lease and keep it throwing-free.
function makeAdminServer(overrides: Partial<AdminServer> = {}): AdminServer {
  return {
    id: "paid.relay.example.com",
    name: "paid",
    description: "paid app lease",
    tags: ["payment"],
    thumbnail: "",
    owner: "operator",
    online: true,
    dns: "paid.relay.example.com",
    link: "",
    tcpAddr: undefined,
    udpAddr: undefined,
    lastUpdated: undefined,
    firstSeen: undefined,
    paymentEnabled: true,
    paymentLabel: "x402 USDC",
    identityKey: "relay-1:0x00000000000000000000000000000000000000a1",
    address: "0x00000000000000000000000000000000000000a1",
    isBanned: false,
    bps: 4096,
    isApproved: true,
    isDenied: false,
    ip: "203.0.113.10",
    displayIP: "203.0.113.10",
    isIPBanned: false,
    ...overrides,
  };
}

function renderAdminCard(overrides: Partial<AdminServer> = {}) {
  return render(
    <AdminServerCard
      server={makeAdminServer(overrides)}
      isSelected={false}
      onToggleSelect={vi.fn()}
      onBanStatusChange={vi.fn()}
      onBPSChange={vi.fn()}
      onApproveStatusChange={vi.fn()}
      onDenyStatusChange={vi.fn()}
      onIPBanStatusChange={vi.fn()}
    />,
  );
}

describe("AdminServerCard render", () => {
  it("renders a lease with a positive BPS limit without throwing", () => {
    renderAdminCard({ bps: 4096 });

    expect(screen.getByText("paid")).toBeTruthy();
    expect(screen.getByText("BPS:")).toBeTruthy();
    expect(screen.getByText("4.1 KB/s")).toBeTruthy();
  });

  it("renders an unlimited BPS lease", () => {
    renderAdminCard({ bps: 0 });

    expect(screen.getByText("Unlimited")).toBeTruthy();
  });
});
