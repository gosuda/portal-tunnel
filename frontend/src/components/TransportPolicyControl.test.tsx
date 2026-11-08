import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { TransportPolicyControl } from "./TransportPolicyControl";

describe("TransportPolicyControl", () => {
  it("saves a clamped lease limit and keeps the enabled state", () => {
    const onChange = vi.fn();
    render(<TransportPolicyControl label="UDP" settings={{ enabled: true, maxLeases: 4 }} disabled={false} onChange={onChange} />);

    const input = screen.getByLabelText("Max UDP leases");
    fireEvent.change(input, { target: { value: "-3" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(onChange).toHaveBeenCalledWith({ enabled: true, maxLeases: 0 });
    expect((input as HTMLInputElement).value).toBe("0");
  });

  it("toggles the transport without touching the limit", () => {
    const onChange = vi.fn();
    render(<TransportPolicyControl label="TCP" settings={{ enabled: false, maxLeases: 7 }} disabled={false} onChange={onChange} />);

    fireEvent.click(screen.getByRole("button", { name: "Enabled" }));

    expect(onChange).toHaveBeenCalledWith({ enabled: true, maxLeases: 7 });
  });

  it("shows a limit the relay reports after the first render", () => {
    const { rerender } = render(
      <TransportPolicyControl label="UDP" settings={{ enabled: true, maxLeases: 1 }} disabled={false} onChange={vi.fn()} />
    );
    rerender(<TransportPolicyControl label="UDP" settings={{ enabled: true, maxLeases: 9 }} disabled={false} onChange={vi.fn()} />);

    expect((screen.getByLabelText("Max UDP leases") as HTMLInputElement).value).toBe("9");
  });
});
