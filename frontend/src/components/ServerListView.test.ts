import { describe, expect, it } from "vitest";
import { appListTitle, emptyListMessage } from "./ServerListView";

describe("appListTitle", () => {
  it("names the view first, then a search, then the order", () => {
    expect(appListTitle("favorites", "chat", "recommended")).toBe("Favorites");
    expect(appListTitle("home", " chat ", "recommended")).toBe("Results for  chat ");
    expect(appListTitle("home", " ", "recommended")).toBe("Most recommended");
    expect(appListTitle("home", "0x305eaaF6e9Ed8800B7D4b0bB9b8259ab07F72Bc6", "duration")).toBe("Home");
    expect(appListTitle("home", "", "duration")).toBe("Home");
  });
});

describe("emptyListMessage", () => {
  it("prefers connecting, then filters, then the view", () => {
    expect(emptyListMessage("favorites", true, true).title).toBe("Finding live apps");
    expect(emptyListMessage("favorites", false, true).title).toBe("No results found");
    expect(emptyListMessage("favorites", false, false).title).toBe("Keep your favorite apps here");
    expect(emptyListMessage("home", false, false).title).toBe("No apps are live yet");
  });
});
