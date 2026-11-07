import { useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import clsx from "clsx";
import { MessageSquare, RefreshCw, ThumbsDown, ThumbsUp, Trash2, X } from "lucide-react";
import type { BaseServer } from "@/hooks/useList";
import type { useServerComments } from "@/hooks/useServerComments";
import type { ReputationVote, ReputationVoteAction } from "@/types/api";
import { COMMENT_MAX_LENGTH } from "@/types/api";
import { isHiddenByVotes } from "@/utils/reputation";

type ServerCommentsPanelProps = ReturnType<typeof useServerComments> & {
  server: BaseServer;
  onClose: () => void;
  onVoteApp?: (hostname: string, vote: ReputationVoteAction) => void | Promise<void>;
};

export function ServerCommentsPanel({
  server,
  onClose,
  comments,
  draft,
  setDraft,
  loading,
  pending,
  votingCommentId,
  error,
  refresh,
  submit,
  remove,
  voteComment,
  onVoteApp,
}: ServerCommentsPanelProps) {
  const busy = loading || pending !== null || votingCommentId !== null;
  const [isAppVoting, setIsAppVoting] = useState(false);
  const [appVoteError, setAppVoteError] = useState("");

  const handleAppVote = async (vote: ReputationVote) => {
    if (!onVoteApp || !server.reputation || isAppVoting) return;
    setIsAppVoting(true);
    setAppVoteError("");
    try {
      const nextVote = server.reputation.viewer_vote === vote ? "clear" : vote;
      await onVoteApp(server.reputation.hostname, nextVote);
    } catch {
      setAppVoteError("Failed to submit app vote.");
    } finally {
      setIsAppVoting(false);
    }
  };

  return (
    <Dialog.Root open modal={false} onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Content
          onPointerDownOutside={(event) => {
            const target = event.target as HTMLElement | null;
            if (target?.closest("[data-comments-trigger]")) {
              event.preventDefault();
            }
          }}
          className="fixed top-[116px] right-0 bottom-0 z-[60] flex w-full flex-col border-l border-border bg-card text-card-foreground shadow-[-12px_0_40px_rgba(0,0,0,0.18)] outline-none md:top-16 sm:w-[400px]"
        >
          {/* Header */}
          <div className="border-b border-border p-5">
            <div className="flex items-center justify-between gap-3">
              <Dialog.Title className="flex items-center gap-2 text-lg font-bold">
                <MessageSquare className="size-5" />
                Comments <span className="text-sm font-normal text-muted-foreground">{loading ? "" : comments.length}</span>
              </Dialog.Title>
              <div className="flex gap-1">
                <button
                  type="button"
                  aria-label="Refresh comments"
                  disabled={busy}
                  onClick={() => void refresh()}
                  className="flex size-9 items-center justify-center rounded-full hover:bg-secondary disabled:opacity-40"
                >
                  <RefreshCw className="size-4" />
                </button>
                <Dialog.Close
                  aria-label="Close comments"
                  className="flex size-9 items-center justify-center rounded-full hover:bg-secondary"
                >
                  <X className="size-5" />
                </Dialog.Close>
              </div>
            </div>
            <Dialog.Description className="mt-2 truncate text-sm text-muted-foreground">
              {server.name}
            </Dialog.Description>
          </div>

          {/* App Recommendation Section */}
          {server.reputation && onVoteApp && (
            <div className="border-b border-border bg-secondary/30 px-5 py-3">
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs font-medium text-muted-foreground">
                  Recommend this app?
                </span>
                <div
                  className="inline-flex h-8 items-center rounded-lg border border-border/70 bg-secondary/60 p-0.5 text-xs"
                  aria-busy={isAppVoting}
                >
                  <button
                    type="button"
                    onClick={() => void handleAppVote("up")}
                    disabled={isAppVoting}
                    aria-label="Recommend app"
                    aria-pressed={server.reputation.viewer_vote === "up"}
                    className={clsx(
                      "inline-flex h-full items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors disabled:opacity-50",
                      server.reputation.viewer_vote === "up"
                        ? "bg-primary text-primary-foreground shadow-xs"
                        : "text-foreground/80 hover:bg-secondary hover:text-primary"
                    )}
                  >
                    <ThumbsUp className="size-3.5 shrink-0" />
                    <span>{server.reputation.up}</span>
                  </button>
                  <div className="my-1 h-3.5 w-px bg-border/80" />
                  <button
                    type="button"
                    onClick={() => void handleAppVote("down")}
                    disabled={isAppVoting}
                    aria-label="Do not recommend app"
                    aria-pressed={server.reputation.viewer_vote === "down"}
                    className={clsx(
                      "inline-flex h-full items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors disabled:opacity-50",
                      server.reputation.viewer_vote === "down"
                        ? "bg-destructive text-destructive-foreground shadow-xs"
                        : "text-foreground/80 hover:bg-secondary hover:text-destructive"
                    )}
                  >
                    <ThumbsDown className="size-3.5 shrink-0" />
                    <span>{server.reputation.down}</span>
                  </button>
                </div>
              </div>
              {appVoteError && (
                <p role="alert" className="mt-1.5 text-xs text-destructive">
                  {appVoteError}
                </p>
              )}
            </div>
          )}

          {/* Comments List */}
          <div className="min-h-0 flex-1 overflow-y-auto p-5" aria-busy={loading}>
            {loading ? (
              <p role="status" className="py-10 text-center text-sm text-muted-foreground">
                Loading comments...
              </p>
            ) : comments.length === 0 && !error ? (
              <div className="py-12 text-center">
                <MessageSquare className="mx-auto mb-3 size-8 text-muted-foreground" />
                <p className="text-sm font-semibold">Start the conversation</p>
                <p className="mt-2 text-xs text-muted-foreground">
                  Share feedback or ask a question about this app.
                </p>
              </div>
            ) : (
              <ol className="space-y-6">
                {comments.map((comment) => {
                  const content = (
                    <>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="font-semibold text-foreground/90">Guest</span>
                      <time dateTime={comment.created_at} className="text-muted-foreground">
                        {new Date(comment.created_at).toLocaleString()}
                      </time>
                      {comment.can_delete && (
                        <button
                          type="button"
                          aria-label="Delete comment"
                          disabled={busy}
                          onClick={() => void remove(comment.id)}
                          className="ml-auto rounded-full p-1.5 text-muted-foreground hover:bg-secondary hover:text-destructive disabled:opacity-40"
                        >
                          <Trash2 className="size-3.5" />
                        </button>
                      )}
                    </div>
                    <p className="mt-1.5 whitespace-pre-wrap wrap-anywhere text-sm leading-6 text-foreground/90">
                      {comment.text}
                    </p>
                    {/* Comment Vote controls */}
                    <div className="mt-2 flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => void voteComment(comment.id, comment.viewer_vote === "up" ? "clear" : "up")}
                        disabled={busy}
                        aria-label="Recommend comment"
                        aria-pressed={comment.viewer_vote === "up"}
                        className={clsx(
                          "inline-flex h-6 items-center gap-1 rounded-md px-1.5 text-xs font-medium transition-colors disabled:opacity-50",
                          comment.viewer_vote === "up"
                            ? "bg-primary text-primary-foreground shadow-xs"
                            : "text-muted-foreground hover:bg-secondary hover:text-primary"
                        )}
                      >
                        <ThumbsUp className="size-3 shrink-0" />
                        <span>{comment.up ?? 0}</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => void voteComment(comment.id, comment.viewer_vote === "down" ? "clear" : "down")}
                        disabled={busy}
                        aria-label="Do not recommend comment"
                        aria-pressed={comment.viewer_vote === "down"}
                        className={clsx(
                          "inline-flex h-6 items-center gap-1 rounded-md px-1.5 text-xs font-medium transition-colors disabled:opacity-50",
                          comment.viewer_vote === "down"
                            ? "bg-destructive text-destructive-foreground shadow-xs"
                            : "text-muted-foreground hover:bg-secondary hover:text-destructive"
                        )}
                      >
                        <ThumbsDown className="size-3 shrink-0" />
                        <span>{comment.down ?? 0}</span>
                      </button>
                    </div>
                    </>
                  );
                  return (
                    <li key={comment.id} className="group">
                      {isHiddenByVotes(comment.up ?? 0, comment.down ?? 0) ? (
                        <details>
                          <summary className="cursor-pointer text-sm text-muted-foreground hover:text-foreground">
                            Hidden due to downvotes · Show comment
                          </summary>
                          <div className="mt-3">{content}</div>
                        </details>
                      ) : content}
                    </li>
                  );
                })}
              </ol>
            )}
          </div>

          {/* Form */}
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
            className="shrink-0 border-t border-border p-4"
          >
            {error && <p role="alert" className="mb-3 text-sm text-destructive">{error}</p>}
            <label htmlFor="app-comment" className="mb-2 block text-sm font-medium">
              Add a comment
            </label>
            <textarea
              id="app-comment"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              maxLength={COMMENT_MAX_LENGTH}
              disabled={pending !== null}
              placeholder="What do you think?"
              rows={3}
              className="w-full resize-none rounded-xl border border-border bg-background p-3 text-sm outline-none focus:border-primary disabled:opacity-50"
            />
            <div className="mt-3 flex items-center justify-between gap-3">
              <span className="text-xs text-muted-foreground">Posting publicly as Guest</span>
              <button
                type="submit"
                disabled={busy || !draft.trim()}
                className="rounded-full bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-40"
              >
                {pending === "post" ? "Posting..." : "Comment"}
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
