import { useEffect, useState, type Dispatch, type SetStateAction } from "react";
import type { BaseServer } from "@/lib/server";
import { apiClient } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import type { AppComment, CommentListResponse, ReputationVoteAction, VoteCommentRequest } from "@/types/api";

function commentErrorMessage(reason: unknown, fallback: string): string {
  return reason instanceof Error ? reason.message : fallback;
}

function subscribeInitialComments(
  path: string,
  setComments: (comments: AppComment[]) => void,
  setError: (message: string) => void,
  setLoading: (loading: boolean) => void
): () => void {
  let cancelled = false;
  void apiClient.get<CommentListResponse>(path).then((data) => {
    if (!cancelled) setComments(data.comments);
  }).catch((reason: unknown) => {
    if (!cancelled) setError(commentErrorMessage(reason, "Could not load comments."));
  }).finally(() => {
    if (!cancelled) setLoading(false);
  });
  return () => {
    cancelled = true;
  };
}

async function mutateCommentList(
  request: () => Promise<CommentListResponse>,
  setComments: (comments: AppComment[]) => void,
  setError: (message: string) => void,
  fallback: string
): Promise<boolean> {
  try {
    const data = await request();
    setComments(data.comments);
    return true;
  } catch (reason) {
    setError(commentErrorMessage(reason, fallback));
    return false;
  }
}

export function useServerComments(server: BaseServer, enabled = true): { comments: AppComment[]; draft: string; setDraft: Dispatch<SetStateAction<string>>; loading: boolean; pending: "post" | "delete" | null; votingCommentId: string | null; busy: boolean; error: string; refresh: () => Promise<void>; submit: () => Promise<void>; remove: (id: string) => Promise<void>; voteComment: (id: string, vote: ReputationVoteAction) => Promise<void> } {
  const [comments, setComments] = useState<AppComment[]>([]);
  const [draft, setDraft] = useState("");
  const [loading, setLoading] = useState(enabled);
  const [pending, setPending] = useState<"post" | "delete" | null>(null);
  const [votingCommentId, setVotingCommentId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const path = `${RELAY_API_PATHS.public.comments}?hostname=${encodeURIComponent(server.id)}`;

  useEffect(() => enabled ? subscribeInitialComments(path, setComments, setError, setLoading) : undefined, [path, enabled]);

  const busy = loading || pending !== null || votingCommentId !== null;
  const blocked = !enabled || busy;

  const refresh = async () => {
    if (blocked) return;
    setLoading(true);
    setError("");
    await mutateCommentList(
      () => apiClient.get<CommentListResponse>(path),
      setComments,
      setError,
      "Could not load comments."
    );
    setLoading(false);
  };

  const submit = async () => {
    if (!draft.trim() || blocked) return;
    setPending("post");
    setError("");
    const posted = await mutateCommentList(
      () => apiClient.post<CommentListResponse>(RELAY_API_PATHS.public.comments, {
        hostname: server.id,
        text: draft,
      }),
      setComments,
      setError,
      "Could not post your comment."
    );
    if (posted) {
      setDraft("");
    }
    setPending(null);
  };

  const remove = async (id: string) => {
    if (blocked) return;
    setPending("delete");
    setError("");
    await mutateCommentList(
      () => apiClient.post<CommentListResponse>(RELAY_API_PATHS.public.commentsDelete, { hostname: server.id, id }),
      setComments,
      setError,
      "Could not delete this comment."
    );
    setPending(null);
  };

  const voteComment = async (id: string, vote: ReputationVoteAction) => {
    if (blocked) return;
    setVotingCommentId(id);
    setError("");
    await mutateCommentList(
      () => apiClient.post<CommentListResponse>(RELAY_API_PATHS.public.commentsVote, { hostname: server.id, id, vote } satisfies VoteCommentRequest),
      setComments,
      setError,
      "Could not submit vote on comment."
    );
    setVotingCommentId(null);
  };

  return {
    comments,
    draft,
    setDraft,
    loading,
    pending,
    votingCommentId,
    busy,
    error,
    refresh,
    submit,
    remove,
    voteComment,
  };
}
