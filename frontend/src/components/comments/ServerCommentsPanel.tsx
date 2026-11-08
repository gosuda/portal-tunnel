import { useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { MessageSquare, RefreshCw, ThumbsDown, ThumbsUp, Trash2, X } from "lucide-react";
import { Badge } from "@/components/ui/chip";
import { IconButton, Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/input";
import type { ServerComments } from "@/hooks/useServerComments";
import type { BaseServer } from "@/lib/server";
import { cn } from "@/lib/utils";
import type { ReputationVote, ReputationVoteAction } from "@/types/api";
import { COMMENT_MAX_LENGTH } from "@/types/api";
import { isHiddenByVotes } from "@/utils/reputation";

type ServerCommentsPanelProps = ServerComments & {
  server: BaseServer;
  onClose: () => void;
  onVoteApp?: (hostname: string, vote: ReputationVoteAction) => void | Promise<void>;
};

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31_536_000],
  ["month", 2_592_000],
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
];

function relativeTime(iso: string): string {
  const seconds = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  if (Number.isNaN(seconds)) return "";
  const unit = UNITS.find(([, size]) => Math.abs(seconds) >= size);
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  return unit ? formatter.format(Math.round(seconds / unit[1]), unit[0]) : "just now";
}

interface VoteButtonProps {
  kind: ReputationVote;
  count: number;
  active: boolean;
  disabled: boolean;
  label: string;
  onClick: () => void;
}

function VoteButton({ kind, count, active, disabled, label, onClick }: VoteButtonProps) {
  const Icon = kind === "up" ? ThumbsUp : ThumbsDown;
  return (
    <button
      type="button"
      aria-label={label}
      aria-pressed={active}
      disabled={disabled}
      onClick={onClick}
      className={cn(
        "interactive inline-flex h-8 min-w-10 items-center gap-1.5 rounded-full px-2.5 text-xs font-semibold disabled:opacity-50",
        active ? (kind === "up" ? "bg-primary text-primary-content" : "bg-danger text-white") : "bg-surface-300 text-content-emphasis"
      )}
    >
      <Icon className="size-4 shrink-0" />
      <span>{count}</span>
    </button>
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
}: ServerCommentsPanelProps) {
  const busy = loading || pending !== null || votingCommentId !== null;
  const [isAppVoting, setIsAppVoting] = useState(false);
  const [appVoteError, setAppVoteError] = useState("");
  const reputation = server.reputation;

  const handleAppVote = async (vote: ReputationVote) => {
    if (!onVoteApp || !reputation || isAppVoting) return;
    setIsAppVoting(true);
    setAppVoteError("");
    try {
      await onVoteApp(reputation.hostname, reputation.viewer_vote === vote ? "clear" : vote);
    } catch {
      setAppVoteError("Failed to submit app vote.");
    } finally {
      setIsAppVoting(false);
    }
  };

  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-[60] bg-scrim" />
        <Dialog.Content
          className={cn(
            "fixed z-[61] flex flex-col bg-surface-100 outline-none",
            "inset-x-0 bottom-0 h-[85dvh] rounded-t-xl",
            "nav:inset-x-auto nav:bottom-0 nav:right-0 nav:top-header nav:h-auto nav:w-[420px] nav:rounded-none nav:border-l nav:border-stroke"
          )}
        >
          <header className="flex shrink-0 items-center gap-3 border-b border-stroke p-4">
            {server.thumbnail ? (
              <img src={server.thumbnail} alt="" className="size-10 shrink-0 rounded-md bg-surface-200 object-cover" />
            ) : (
              <div className="size-10 shrink-0 rounded-md bg-surface-200" />
            )}
            <div className="min-w-0 flex-1">
              <Dialog.Title className="truncate text-base font-bold text-content-emphasis">{server.name}</Dialog.Title>
              <Dialog.Description className="text-xs text-content-muted">
                Comments{loading ? "" : ` · ${comments.length}`}
              </Dialog.Description>
            </div>
            {reputation && onVoteApp && (
              <div className="flex shrink-0 gap-1" aria-busy={isAppVoting}>
                <VoteButton
                  kind="up"
                  count={reputation.up}
                  active={reputation.viewer_vote === "up"}
                  disabled={isAppVoting}
                  label="Recommend app"
                  onClick={() => void handleAppVote("up")}
                />
                <VoteButton
                  kind="down"
                  count={reputation.down}
                  active={reputation.viewer_vote === "down"}
                  disabled={isAppVoting}
                  label="Do not recommend app"
                  onClick={() => void handleAppVote("down")}
                />
              </div>
            )}
            <IconButton aria-label="Refresh comments" disabled={busy} onClick={() => void refresh()} className="disabled:opacity-40">
              <RefreshCw className="size-4" />
            </IconButton>
            <Dialog.Close asChild>
              <IconButton aria-label="Close comments">
                <X className="size-5" />
              </IconButton>
            </Dialog.Close>
          </header>
          {appVoteError && (
            <p role="alert" className="shrink-0 border-b border-stroke px-4 py-2 text-xs text-danger">
              {appVoteError}
            </p>
          )}

          <div className="min-h-0 flex-1 overflow-y-auto p-4" aria-busy={loading}>
            {loading ? (
              <div role="status" aria-label="Loading comments" className="space-y-6">
                {[0, 1, 2].map((i) => (
                  <div key={i} className="space-y-2">
                    <div className="h-3 w-1/3 rounded-sm bg-surface-200 motion-safe:animate-pulse" />
                    <div className="h-4 w-full rounded-sm bg-surface-200 motion-safe:animate-pulse" />
                    <div className="h-4 w-2/3 rounded-sm bg-surface-200 motion-safe:animate-pulse" />
                  </div>
                ))}
              </div>
            ) : comments.length === 0 && !error ? (
              <div className="flex flex-col items-center gap-2 py-12 text-center">
                <MessageSquare className="size-10 text-content-muted" />
                <p className="font-semibold text-content-emphasis">Start the conversation</p>
                <p className="text-sm text-content-muted">Share feedback or ask a question about this app.</p>
              </div>
            ) : (
              <ol className="space-y-5">
                {comments.map((comment) => {
                  const content = (
                    <>
                      <div className="flex items-center gap-2 text-xs">
                        <span className="font-semibold text-content-emphasis">Guest</span>
                        {comment.can_delete && <Badge>You</Badge>}
                        <time dateTime={comment.created_at} title={new Date(comment.created_at).toLocaleString()} className="text-content-muted">
                          {relativeTime(comment.created_at)}
                        </time>
                        {comment.can_delete && (
                          <IconButton
                            aria-label="Delete comment"
                            disabled={busy}
                            onClick={() => void remove(comment.id)}
                            className="ml-auto text-content-muted disabled:opacity-40"
                          >
                            <Trash2 className="size-4" />
                          </IconButton>
                        )}
                      </div>
                      <p className="mt-1 whitespace-pre-wrap wrap-anywhere text-sm text-content">{comment.text}</p>
                      <div className="mt-2 flex items-center gap-1">
                        <VoteButton
                          kind="up"
                          count={comment.up ?? 0}
                          active={comment.viewer_vote === "up"}
                          disabled={busy}
                          label="Recommend comment"
                          onClick={() => void voteComment(comment.id, comment.viewer_vote === "up" ? "clear" : "up")}
                        />
                        <VoteButton
                          kind="down"
                          count={comment.down ?? 0}
                          active={comment.viewer_vote === "down"}
                          disabled={busy}
                          label="Do not recommend comment"
                          onClick={() => void voteComment(comment.id, comment.viewer_vote === "down" ? "clear" : "down")}
                        />
                      </div>
                    </>
                  );
                  return (
                    <li key={comment.id}>
                      {isHiddenByVotes(comment.up ?? 0, comment.down ?? 0) ? (
                        <details>
                          <summary className="cursor-pointer text-sm text-content-muted">Hidden due to downvotes · Show comment</summary>
                          <div className="mt-3">{content}</div>
                        </details>
                      ) : (
                        content
                      )}
                    </li>
                  );
                })}
              </ol>
            )}
          </div>

          <form
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
            className="shrink-0 border-t border-stroke p-4"
          >
            {error && (
              <p role="alert" className="mb-2 text-sm text-danger">
                {error}
              </p>
            )}
            <label htmlFor="app-comment" className="sr-only">
              Add a comment
            </label>
            <Textarea
              id="app-comment"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              maxLength={COMMENT_MAX_LENGTH}
              disabled={pending !== null}
              placeholder="Add a comment"
              rows={3}
              className="resize-none"
            />
            <div className="mt-2 flex items-center justify-between gap-3">
              <span className="text-xs text-content-muted">
                Posting publicly as Guest · {draft.length}/{COMMENT_MAX_LENGTH}
              </span>
              <Button type="submit" variant="primary" disabled={busy || !draft.trim()} className="disabled:opacity-40">
                {pending === "post" ? "Posting..." : "Comment"}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
