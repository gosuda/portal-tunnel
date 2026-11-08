import { describe, expect, it } from "vitest";
import { appListTitle, emptyListMessage } from "./listMessages";

describe("appListTitle", () => {
  it("names the view first, then a search, then the order", () => {
    expect(appListTitle("favorites", "chat", "recommended")).toBe("Favorites");
    expect(appListTitle("home", " chat ", "recommended")).toBe("Results for  chat ");
    expect(appListTitle("home", " ", "recommended")).toBe("Most recommended");
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
