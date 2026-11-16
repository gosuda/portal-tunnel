import { useEffect, useState } from "react";
import { apiClient } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import type { BaseServer } from "@/lib/server";
import type { FederatedCommentsResponse } from "@/types/api";

// Leave enough time for the backend to return partial results at its deadline.
const COMMENTS_REQUEST_TIMEOUT_MS = 9_000;

type PendingPage = { key?: string; offset: number };
type LoadedPage = {
  key: string;
  request: PendingPage;
  response?: FederatedCommentsResponse;
  error?: string;
};

// Called only by the open comments panel; only the current relay fans out.
export function useFederatedComments(server: BaseServer) {
  const address = server.address?.trim() ?? "";
  const valid = /^0x[0-9a-f]{40}$/i.test(address);
  const key = new URLSearchParams({ address, name: server.serviceName ?? "" }).toString();
  const [request, setRequest] = useState<PendingPage>({ offset: 0 });
  const [page, setPage] = useState<LoadedPage>();
  const offset = request.key === key ? request.offset : 0;

  useEffect(() => {
    if (!valid) return;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), COMMENTS_REQUEST_TIMEOUT_MS);
    const query = offset ? `${key}&offset=${offset}` : key;
    let cancelled = false;
    void apiClient.get<FederatedCommentsResponse>(`${RELAY_API_PATHS.public.federatedComments}?${query}`, controller.signal)
      .then((response) => {
        if (cancelled) return;
        setPage((previous) => {
          if (!offset || previous?.key !== key || !previous.response) {
            return { key, request, response };
          }
          const comments = new Map([...previous.response.comments, ...response.comments]
            .map((comment) => [JSON.stringify([comment.relay_url, comment.id]), comment]));
          return {
            key,
            request,
            response: { ...response, partial: previous.response.partial || response.partial, comments: [...comments.values()] },
          };
        });
      })
      .catch(() => {
        if (cancelled) return;
        setPage((previous) => ({
          key,
          request,
          response: offset && previous?.key === key ? previous.response : undefined,
          error: "Other relay comments could not be checked.",
        }));
      })
      .finally(() => window.clearTimeout(timeout));
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
      controller.abort();
    };
  }, [key, offset, request, valid]);

  const current = page?.key === key ? page : undefined;
  const loading = valid && current?.request !== request;
  // A fresh page replaces observations so deleted/removed comments do not
  // linger after refresh. Existing pages stay visible on a load-more failure.
  const response = loading && !offset ? undefined : current?.response;
  const next = response?.next_offset;
  return {
    response,
    loading,
    error: loading ? undefined : current?.error,
    refresh: () => { if (valid) setRequest({ key, offset: 0 }); },
    loadMore: Number.isSafeInteger(next) && next !== undefined && (next > offset || (next === offset && Boolean(current?.error)))
      ? () => setRequest({ key, offset: next }) : undefined,
  };
}
