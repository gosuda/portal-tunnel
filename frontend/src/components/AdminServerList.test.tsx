import type { ComponentProps } from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AdminServerList } from "./AdminServerList";

vi.mock("@/components/Header", () => ({ Header: () => null }));

function listProps(): ComponentProps<typeof AdminServerList> {
  return {
    searchQuery: "", status: "all", sortBy: "default",
    selectedTags: [], availableTags: [], filteredServers: [],
    banFilter: "all", approvalMode: "auto", landingPageEnabled: false,
    policySaving: false, error: "",
    udpSettings: { enabled: false, maxLeases: 0 },
    tcpPortSettings: { enabled: false, maxLeases: 0 },
    onSearchChange: vi.fn(), onStatusChange: vi.fn(), onSortByChange: vi.fn(),
    onTagToggle: vi.fn(), onBanFilterChange: vi.fn(), onBanStatusChange: vi.fn(),
    onBPSChange: vi.fn(), onApprovalModeChange: vi.fn(),
    onLandingPageEnabledChange: vi.fn(), onUDPSettingsChange: vi.fn(),
    onTCPPortSettingsChange: vi.fn(), onApproveStatusChange: vi.fn(),
    onDenyStatusChange: vi.fn(), onIPBanStatusChange: vi.fn(),
    onBulkApprove: vi.fn(), onBulkDeny: vi.fn(), onBulkBan: vi.fn(),
  };
}

describe("AdminServerList policy controls", () => {
  it("makes UDP and TCP toggles and lease limits available in the mobile settings dialog", () => {
    const props = listProps();
    render(<AdminServerList {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Filter settings" }));
    const dialog = within(screen.getByRole("dialog", { name: "Filters and policy" }));

    fireEvent.click(within(dialog.getByRole("group", { name: "UDP" })).getByText("Enabled"));
    expect(props.onUDPSettingsChange).toHaveBeenCalledWith({ enabled: true, maxLeases: 0 });
    fireEvent.change(dialog.getByRole("spinbutton", { name: "Max UDP leases" }), { target: { value: "12" } });
    fireEvent.click(dialog.getByRole("button", { name: "Save max UDP leases" }));
    expect(props.onUDPSettingsChange).toHaveBeenCalledWith({ enabled: false, maxLeases: 12 });

    fireEvent.click(within(dialog.getByRole("group", { name: "TCP" })).getByText("Enabled"));
    expect(props.onTCPPortSettingsChange).toHaveBeenCalledWith({ enabled: true, maxLeases: 0 });
    fireEvent.change(dialog.getByRole("spinbutton", { name: "Max TCP leases" }), { target: { value: "24" } });
    fireEvent.keyDown(dialog.getByRole("spinbutton", { name: "Max TCP leases" }), { key: "Enter" });
    expect(props.onTCPPortSettingsChange).toHaveBeenCalledWith({ enabled: false, maxLeases: 24 });
  });

  it("disables every policy control while saving, keeps filters usable, and displays errors", () => {
    const props = listProps();
    const { rerender } = render(<AdminServerList {...props} policySaving />);
    const desktopPolicy = screen.getByRole("group", { name: "Relay policy" });
    fireEvent.click(screen.getByRole("button", { name: "Filter settings" }));
    const dialog = within(screen.getByRole("dialog"));
    const mobilePolicy = dialog.getByRole("group", { name: "Relay policy" });

    for (const policy of [desktopPolicy, mobilePolicy]) {
      const controls = policy.querySelectorAll("button, input");
      expect(controls.length).toBeGreaterThan(0);
      for (const control of controls) expect(control.matches(":disabled")).toBe(true);
    }
    for (const filter of dialog.getAllByRole("combobox")) {
      expect(filter.matches(":disabled")).toBe(false);
    }

    rerender(<AdminServerList {...props} error="Unable to save policy" />);
    expect(dialog.getByRole("alert").textContent).toBe("Unable to save policy");
    expect(dialog.getByRole("button", { name: "Manual" }).matches(":disabled")).toBe(false);
  });
});
