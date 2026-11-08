import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { PublicRelaysSection } from "./PublicRelaysSection";

describe("PublicRelaysSection", () => {
  const relays = [
    { relayURL: "https://relay-1.example", isCurrent: true },
    { relayURL: "https://relay-2.example", isCurrent: false, protocolVersion: "9" },
  ];
  const releases = {
    discovery: { release_version: "v2.7.0" },
    versions: { "https://relay-1.example": "v2.7.3" },
  };

  const renderSection = (onCopyURL = vi.fn()) =>
    render(
      <PublicRelaysSection
        knownRelays={relays}
        relayReleases={releases}
        loading={false}
        copiedURL={null}
        onCopyURL={onCopyURL}
      />
    );

  it("lists relays, flags incompatible ones and filters by query", () => {
    renderSection();

    expect(screen.getByText("https://relay-1.example")).toBeTruthy();
    expect(screen.getByText("https://relay-2.example")).toBeTruthy();
    expect(screen.getByText("Incompatible")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Search relays"), { target: { value: "relay-1" } });

    expect(screen.getByText("https://relay-1.example")).toBeTruthy();
    expect(screen.queryByText("https://relay-2.example")).toBeNull();
  });

  it("triggers copy callback when clicking copy button", () => {
    const onCopyURL = vi.fn();
    renderSection(onCopyURL);

    fireEvent.click(screen.getByLabelText("Copy https://relay-1.example"));
    expect(onCopyURL).toHaveBeenCalledWith("https://relay-1.example", "https://relay-1.example");
  });
});
