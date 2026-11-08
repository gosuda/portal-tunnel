import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DEFAULT_SORT } from "@/types/filters";
import { SidebarNav, type SidebarNavProps, type SidebarVariant } from "./SidebarNav";

vi.mock("@/components/TunnelCommandModal", () => ({
  TunnelCommandModal: ({ trigger }: { trigger: React.ReactNode }) => <>{trigger}</>,
}));

function renderNav(variant: SidebarVariant, overrides: Partial<SidebarNavProps> = {}) {
  const props: SidebarNavProps = {
    variant,
    browseView: "home",
    sortBy: DEFAULT_SORT,
    favorites: 3,
    onBrowseViewChange: vi.fn(),
    onSortByChange: vi.fn(),
    ...overrides,
  };
  render(<SidebarNav {...props} />);
  return props;
}

describe("SidebarNav", () => {
  it.each<SidebarVariant>(["full", "mini"])("%s variant names every entry by its full label", (variant) => {
    renderNav(variant);
    for (const name of ["Home", "Most recommended", "Favorites", "Launch App", "Public relays"]) {
      expect(screen.getByRole("button", { name: new RegExp(`^${name}`) })).toBeTruthy();
    }
    for (const name of ["Documentation", "GitHub", "Admin"]) {
      expect(screen.getByRole("link", { name: new RegExp(`^${name}`) })).toBeTruthy();
    }
  });

  it.each<SidebarVariant>(["full", "mini"])("%s variant marks the current view and opens the recommended order", (variant) => {
    const props = renderNav(variant, { sortBy: "recommended" });
    expect(screen.getByRole("button", { name: /^Most recommended/ }).getAttribute("aria-current")).toBe("page");
    expect(screen.getByRole("button", { name: /^Home/ }).getAttribute("aria-current")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: /^Most recommended/ }));
    expect(props.onBrowseViewChange).toHaveBeenCalledWith("home");
    expect(props.onSortByChange).toHaveBeenCalledWith("recommended");
  });
  it("marks Home current on the first load", () => {
    renderNav("full");
    expect(screen.getByRole("button", { name: /^Home/ }).getAttribute("aria-current")).toBe("page");
  });
});
