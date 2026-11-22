import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ComponentProps } from "react";
import { ServerCommentsPanel } from "./ServerCommentsPanel";

const address = "0x1111111111111111111111111111111111111111";
const stamp = "2026-11-01T00:00:00Z";

function props(): ComponentProps<typeof ServerCommentsPanel> {
  return {
    server: {
      id: "blog.local.example", name: "Blog", address, serviceName: "blog", description: "",
      tags: [], thumbnail: "", owner: "", online: true, dns: "blog.local.example", link: "",
    },
    onClose: vi.fn(),
    comments: [],
    draft: "",
    setDraft: vi.fn(),
    loading: false,
    pending: null,
    votingCommentId: null,
    error: "",
    refresh: vi.fn(async () => {}),
    submit: vi.fn(async () => {}),
    remove: vi.fn(async () => {}),
    voteComment: vi.fn(async () => {}),
    federation: { loading: false, refresh: vi.fn(), error: undefined, response: undefined },
  };
}

describe("comments federation", () => {
  it("merges local and remote comments with the same ID, retaining controls only on the local row", () => {
    const view = props();
    render(<ServerCommentsPanel
      {...view}
      comments={[{ id: "same", text: "Local comment", created_at: stamp, can_delete: true }]}
      federation={{
        ...view.federation,
        response: { relays_checked: 1, relays_skipped: 1, partial: true, comments: [
          { id: "same", text: "Remote comment", created_at: stamp, relay_url: "https://other.example/portal/" },
          { id: "deleted", text: "Former content", created_at: stamp, deleted: true, relay_url: "https://other.example/portal/" },
        ] },
      }}
    />);
    expect(screen.getByText("Local comment")).toBeDefined();
    expect(screen.getByText("Remote comment")).toBeDefined();
    expect(screen.getByText("Deleted at its origin.")).toBeDefined();
    expect(screen.queryByText("Former content")).toBeNull();
    expect(screen.getByText("Some comments may be missing.")).toBeDefined();
    expect(screen.getAllByRole("button", { name: "Delete comment" })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Recommend comment" })).toHaveLength(1);
    expect(screen.getByLabelText("Add a comment")).toBeDefined();
    expect(screen.getAllByRole("link", { name: "Open comments on https://other.example/portal/" })[0]
      .getAttribute("href")).toBe(`https://other.example/portal/?identity=${address}`);
  });

  it("shows the remote failure without local write controls for remote-only services", () => {
    const view = props();
    render(<ServerCommentsPanel
      {...view}
      server={{ ...view.server, remoteOnly: true }}
      federation={{ ...view.federation, error: "Other relay comments could not be checked." }}
    />);
    expect(screen.getByText("Other relay comments could not be checked.")).toBeDefined();
    expect(screen.queryByLabelText("Add a comment")).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete comment" })).toBeNull();
  });

  it("shows incomplete comment coverage even when all checked relays responded", () => {
    const view = props();
    const response = { relays_checked: 2, relays_skipped: 0, partial: true, comments: [] };
    const { rerender } = render(<ServerCommentsPanel
      {...view}
      server={{ ...view.server, remoteOnly: true }}
      federation={{ ...view.federation, response }}
    />);
    expect(screen.getByText("Some comments may be missing.")).toBeDefined();

    rerender(<ServerCommentsPanel
      {...view}
      server={{ ...view.server, remoteOnly: true }}
      federation={{ ...view.federation, response: { ...response, relays_skipped: 0, partial: false } }}
    />);
    expect(screen.queryByText("Some comments may be missing.")).toBeNull();
  });
});
