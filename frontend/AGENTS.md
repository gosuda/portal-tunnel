# Frontend AGENTS.md

## Frontend-Backend Contracts

1. Browser requests use the Go relay API directly through same-origin `/api/*`, `/sdk/*`, and `/discovery*` paths.
2. Relay path constants are owned by `../types/paths.go` and mirrored in `src/lib/apiPaths.ts`.
3. JSON control-plane responses use the `{ ok, data?, error?: { code, message } }` envelope.
4. Admin auth uses bearer tokens returned by `/api/admin/auth/login`; `src/lib/apiClient.ts` attaches them to admin and policy requests.
5. `VITE_PORTAL_API_BASE_URL` is the only built-in API origin setting. Leave it empty for same-origin deployment.
6. Lease and policy wire fields use snake_case. Go types in `../types/` own the contract mirrored by `src/types/api.ts`.
7. Lease metadata parsing and UI defaults are owned by `src/lib/metadata.ts`.
8. Landing-page visibility comes from `landing_page_enabled` in the Go relay public and policy state.

## Frontend Conventions

1. Do not add `useCallback`; React Compiler handles memoization.
2. Feature state lives in page-level hooks and is prop-drilled. Theme is the exception.
3. Only `handleBPSChange` uses optimistic update with rollback. Other admin actions await the API and refresh state.
