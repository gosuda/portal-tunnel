import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ServiceRelaysPanel } from "./ServiceRelaysPanel";

describe("relay selection", () => {
  it("shows distinct origins as explicit external links with unverified observations", () => {
    const address = "0x1111111111111111111111111111111111111111";
    render(<ServiceRelaysPanel
      server={{ id: "blog.local.example", name: "blog", serviceName: "blog", address, description: "", tags: [], thumbnail: "", owner: "", online: true, dns: "blog.local.example", link: "https://blog.local.example/" }}
      loading={false}
      onClose={vi.fn()}
      response={{ partial: true, relays_checked: 2, relays_skipped: 1, services: [{ name: "blog", address, metadata: {}, locations: [
        { relay_url: "https://remote.example", url: "https://blog.remote.example/", current_relay: false, reported_ready: true, verification: "relay-reported", observed_at: "2026-11-16T00:00:00Z", expires_at: "2026-11-16T00:00:30Z" },
      ] }] }}
    />);
    expect(screen.getByText(/without independent proof/)).toBeDefined();
    expect(screen.getByText(/Other relay locations may exist/)).toBeDefined();
    const remote = screen.getByRole("link", { name: "https://blog.remote.example/" });
    expect(remote.getAttribute("href")).toBe("https://blog.remote.example/");
    expect(remote.getAttribute("target")).toBe("_blank");
    expect(remote.getAttribute("rel")).toContain("noreferrer");
    expect(screen.getByRole("link", { name: /Open current relay/ }).getAttribute("href")).toBe("https://blog.local.example/");
  });
});
