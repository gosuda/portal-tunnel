import type { JSX } from "react";
import { useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import clsx from "clsx";
import { MessageSquare, RefreshCw, ThumbsDown, ThumbsUp, Trash2, X } from "lucide-react";
import type { BaseServer } from "@/lib/server";
import type { useServerComments } from "@/hooks/useServerComments";
import type { AppComment, ReputationVote, ReputationVoteAction } from "@/types/api";
import { COMMENT_MAX_LENGTH } from "@/types/api";
import { isHiddenByVotes } from "@/utils/reputation";

type ServerCommentsPanelProps = ReturnType<typeof useServerComments> & {
  server: BaseServer;
  onClose: () => void;
  onVoteApp?: (hostname: string, vote: ReputationVoteAction) => void | Promise<void>;
};

function CommentVoteButton({ direction, pressed, count, disabled, onSelect }: {
  direction: "up" | "down";
  pressed: boolean;
  count: number;
  disabled: boolean;
  onSelect: (direction: "up" | "down") => void;
}): JSX.Element {
  const recommend = direction === "up";
  return (
    <button
      type="button"
      onClick={() => onSelect(direction)}
      disabled={disabled}
      aria-label={recommend ? "Recommend comment" : "Do not recommend comment"}
      aria-pressed={pressed}
      className={clsx(
        "inline-flex h-6 items-center gap-1 rounded-md px-1.5 text-xs font-medium transition-colors disabled:opacity-50",
        pressed
          ? recommend
            ? "bg-primary text-primary-foreground shadow-xs"
            : "bg-destructive text-destructive-foreground shadow-xs"
          : recommend
            ? "text-muted-foreground hover:bg-secondary hover:text-primary"
            : "text-muted-foreground hover:bg-secondary hover:text-destructive"
      )}
    >
      {recommend ? (
        <ThumbsUp className="size-3 shrink-0" />
      ) : (
        <ThumbsDown className="size-3 shrink-0" />
      )}
      <span>{count}</span>
    </button>
  );
}

function CommentItem({ comment, busy, onRemove, onVote }: {
  comment: AppComment;
  busy: boolean;
  onRemove: (id: string) => void | Promise<void>;
  onVote: (id: string, vote: ReputationVoteAction) => void | Promise<void>;
}): JSX.Element {
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
            onClick={() => void onRemove(comment.id)}
            className="ml-auto rounded-full p-1.5 text-muted-foreground hover:bg-secondary hover:text-destructive disabled:opacity-40"
          >
            <Trash2 className="size-3.5" />
          </button>
        )}
      </div>
      <p className="mt-1.5 whitespace-pre-wrap wrap-anywhere text-sm leading-6 text-foreground/90">
        {comment.text}
      </p>
      <div className="mt-2 flex items-center gap-1">
        <CommentVoteButton
          direction="up"
          pressed={comment.viewer_vote === "up"}
          count={comment.up ?? 0}
          disabled={busy}
          onSelect={(direction) => void onVote(comment.id, comment.viewer_vote === direction ? "clear" : direction)}
        />
        <CommentVoteButton
          direction="down"
          pressed={comment.viewer_vote === "down"}
          count={comment.down ?? 0}
          disabled={busy}
          onSelect={(direction) => void onVote(comment.id, comment.viewer_vote === direction ? "clear" : direction)}
        />
      </div>
    </>
  );
  return (
    <li className="group">
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
}

function AppVoteSection({ reputation, isVoting, error, onVote }: {
  reputation: NonNullable<BaseServer["reputation"]>;
  isVoting: boolean;
  error: string;
  onVote: (vote: ReputationVote) => void;
}): JSX.Element {
  return (
    <div className="border-b border-border bg-secondary/30 px-5 py-3">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-medium text-muted-foreground">
          Recommend this app?
        </span>
        <div
          className="inline-flex h-8 items-center rounded-lg border border-border/70 bg-secondary/60 p-0.5 text-xs"
          aria-busy={isVoting}
        >
          <button
            type="button"
            onClick={() => onVote("up")}
            disabled={isVoting}
            aria-label="Recommend app"
            aria-pressed={reputation.viewer_vote === "up"}
            className={clsx(
              "inline-flex h-full items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors disabled:opacity-50",
              reputation.viewer_vote === "up"
                ? "bg-primary text-primary-foreground shadow-xs"
                : "text-foreground/80 hover:bg-secondary hover:text-primary"
            )}
          >
            <ThumbsUp className="size-3.5 shrink-0" />
            <span>{reputation.up}</span>
          </button>
          <div className="my-1 h-3.5 w-px bg-border/80" />
          <button
            type="button"
            onClick={() => onVote("down")}
            disabled={isVoting}
            aria-label="Do not recommend app"
            aria-pressed={reputation.viewer_vote === "down"}
            className={clsx(
              "inline-flex h-full items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors disabled:opacity-50",
              reputation.viewer_vote === "down"
                ? "bg-destructive text-destructive-foreground shadow-xs"
                : "text-foreground/80 hover:bg-secondary hover:text-destructive"
            )}
          >
            <ThumbsDown className="size-3.5 shrink-0" />
            <span>{reputation.down}</span>
          </button>
        </div>
      </div>
      {error && (
        <p role="alert" className="mt-1.5 text-xs text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}

function CommentsBody({ loading, comments, error, busy, onRemove, onVoteComment }: {
  loading: boolean;
  comments: AppComment[];
  error: string;
  busy: boolean;
  onRemove: (id: string) => void | Promise<void>;
  onVoteComment: (id: string, vote: ReputationVoteAction) => void | Promise<void>;
}): JSX.Element {
  return (
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
          {comments.map((comment) => (
            <CommentItem
              key={comment.id}
              comment={comment}
              busy={busy}
              onRemove={onRemove}
              onVote={onVoteComment}
            />
          ))}
        </ol>
      )}
    </div>
  );
}

function CommentComposer({ draft, pending, busy, error, onDraftChange, onPost }: {
  draft: string;
  pending: "post" | "delete" | null;
  busy: boolean;
  error: string;
  onDraftChange: (draft: string) => void;
  onPost: () => void;
}): JSX.Element {
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onPost();
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
        onChange={(event) => onDraftChange(event.target.value)}
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
  );
}

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
}: ServerCommentsPanelProps): JSX.Element {
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

          {server.reputation && onVoteApp && (
            <AppVoteSection
              reputation={server.reputation}
              isVoting={isAppVoting}
              error={appVoteError}
              onVote={(vote) => void handleAppVote(vote)}
            />
          )}

          <CommentsBody
            loading={loading}
            comments={comments}
            error={error}
            busy={busy}
            onRemove={remove}
            onVoteComment={voteComment}
          />

          <CommentComposer
            draft={draft}
            pending={pending}
            busy={busy}
            error={error}
            onDraftChange={setDraft}
            onPost={() => void submit()}
          />
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
