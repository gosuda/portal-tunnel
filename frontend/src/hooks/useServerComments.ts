import { useEffect, useState } from "react";
import type { BaseServer } from "@/hooks/useList";
import { apiClient } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import type { AppComment, CommentListResponse, ReputationVoteAction } from "@/types/api";

// Mounted once per selected app by ServerList, so closing or switching panels
// discards that app's draft and cannot apply an old request to a new thread.
export function useServerComments(server: BaseServer) {
  const [comments, setComments] = useState<AppComment[]>([]);
  const [draft, setDraft] = useState("");
  const [loading, setLoading] = useState(true);
  const [pending, setPending] = useState<"post" | "delete" | null>(null);
  const [votingCommentId, setVotingCommentId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const path = `${RELAY_API_PATHS.public.comments}?hostname=${encodeURIComponent(server.id)}`;

  useEffect(() => {
    let cancelled = false;
    void apiClient.get<CommentListResponse>(path).then((data) => {
      if (!cancelled) setComments(data.comments);
    }).catch((reason: unknown) => {
      if (!cancelled) setError(reason instanceof Error ? reason.message : "Could not load comments.");
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => { cancelled = true; };
  }, [path]);

  const refresh = async () => {
    if (loading || pending || votingCommentId !== null) return;
    setLoading(true);
    setError("");
    try {
      const data = await apiClient.get<CommentListResponse>(path);
      setComments(data.comments);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load comments.");
    } finally {
      setLoading(false);
    }
  };

  const submit = async () => {
    if (!draft.trim() || loading || pending || votingCommentId !== null) return;
    setPending("post");
    setError("");
    try {
      const data = await apiClient.post<CommentListResponse>(RELAY_API_PATHS.public.comments, {
        hostname: server.id,
        text: draft,
      });
      setComments(data.comments);
      setDraft("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not post your comment.");
    } finally {
      setPending(null);
    }
  };

  const remove = async (id: string) => {
    if (loading || pending || votingCommentId !== null) return;
    setPending("delete");
    setError("");
    try {
      const data = await apiClient.post<CommentListResponse>(RELAY_API_PATHS.public.commentsDelete, { hostname: server.id, id });
      setComments(data.comments);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not delete this comment.");
    } finally {
      setPending(null);
    }
  };

  const voteComment = async (id: string, vote: ReputationVoteAction) => {
    if (loading || pending || votingCommentId !== null) return;
    setVotingCommentId(id);
    setError("");
    try {
      const data = await apiClient.post<CommentListResponse>(RELAY_API_PATHS.public.commentsVote, { hostname: server.id, id, vote });
      setComments(data.comments);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not submit vote on comment.");
    } finally {
      setVotingCommentId(null);
    }
  };

  return {
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
  };
}
