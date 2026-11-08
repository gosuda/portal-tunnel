import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { PublicRelaysSection } from "./PublicRelaysSection";

describe("PublicRelaysSection", () => {
  const relays = [
    { relayURL: "https://relay-1.example", isCurrent: true },
    { relayURL: "https://relay-2.example", isCurrent: false },
  ];
  const releases = {
    discovery: { release_version: "v2.7.0" },
    versions: { "https://relay-1.example": "v2.7.3" },
  };

  it("renders relay cards and filters them by query", () => {
    const onCopyURL = vi.fn();
    render(
      <PublicRelaysSection
        knownRelays={relays}
        relayReleases={releases}
        loading={false}
        copiedURL={null}
        onCopyURL={onCopyURL}
      />
    );

    expect(screen.getByText("https://relay-1.example")).toBeTruthy();
    expect(screen.getByText("https://relay-2.example")).toBeTruthy();

    const searchInput = screen.getByLabelText("Search relays");
    fireEvent.change(searchInput, { target: { value: "relay-1" } });

    expect(screen.getByText("https://relay-1.example")).toBeTruthy();
    expect(screen.queryByText("https://relay-2.example")).toBeNull();
  });

  it("triggers copy callback when clicking copy button", () => {
    const onCopyURL = vi.fn();
    render(
      <PublicRelaysSection
        knownRelays={relays}
        relayReleases={releases}
        loading={false}
        copiedURL={null}
        onCopyURL={onCopyURL}
      />
    );

    const copyBtn = screen.getByLabelText("Copy https://relay-1.example");
    fireEvent.click(copyBtn);
    expect(onCopyURL).toHaveBeenCalledWith(
      "https://relay-1.example",
      "https://relay-1.example"
    );
  });
});
