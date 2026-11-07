# Relay Server Frontend

React + TypeScript frontend for relay server discovery and onboarding.

## Tech Stack

- React 19
- TypeScript
- Vite 7
- Tailwind CSS 4
- shadcn/ui (Radix-based)
- Lucide React
- @ssgoi/react
- React Compiler (`babel-plugin-react-compiler`, enabled in `vite.config.ts`)

## Core Behavior

This frontend is a Vite SPA embedded in the Go Portal binary for production. It
talks to the relay over the JSON API and does not receive server-side injected
lease data.

- Public state is loaded directly from `/api/state`.
- Lease cards render a user-provided `thumbnail` metadata URL; Portal does not generate screenshots when it is empty.
- Operator policy state is loaded directly from `/api/policy/state`.
- All JSON API responses use the `{ ok, data?, error? }` envelope parsed by `src/lib/apiClient.ts`.
- `VITE_PORTAL_API_BASE_URL` points local development at a Portal origin or deployment base path, not at `/api`. Production uses same-origin requests. Admin auth uses a bearer token returned by `/api/admin/auth/login`.

## Project Structure

```text
frontend/
  src/
    components/
    hooks/
      useServerList.ts
      useAdmin.ts
      useList.ts
      useAuth.ts
    lib/
      apiClient.ts
      apiPaths.ts
      metadata.ts
    pages/
      Admin.tsx
      ServerDetail.tsx
      ServerList.tsx
    types/
      api.ts
    App.tsx
    main.tsx
    index.css
  index.html
  package.json
  tsconfig.json
  vite.config.ts
```

## Install and Build

```bash
cd frontend
npm install
npm run build
```

Build output goes to `frontend/dist/`.

## Development

```bash
cd frontend
npm run dev
```

Default dev URL: `http://localhost:5173`.

To run against another Portal origin during development:

```bash
VITE_PORTAL_API_BASE_URL=https://portal.example.com npm run dev
```

## Production Build

The root Dockerfile builds this SPA first and copies `frontend/dist` into
`cmd/relay-server/dist/app` before compiling the Go relay. The Go binary embeds
and serves those files on the Portal root host. No separate frontend image or
reverse proxy is required.

Operators can replace the embedded SPA at runtime by setting
`PORTAL_FRONTEND_DIR` to a directory containing a custom `index.html`. Portal
serves that directory exclusively and preserves `/api`, `/sdk`, `/discovery`,
and `/v1` for its own endpoints.

```bash
docker compose up -d --build portal
```

## NPM Scripts

| Script | Purpose |
| --- | --- |
| `npm run dev` | Start the Vite development server. |
| `npm run build` | Type-check and build production assets. |
| `npm run lint` | Run ESLint. |
| `npm run typecheck` | Run TypeScript checking. |
| `npm test` | Run Vitest. |
| `npm run preview` | Preview the production bundle. |

## Relay Integration

Relay server exposes:

- `/` - embedded React SPA
- `/api/state` - public leases
- `/api/install.sh` and `/api/install.ps1` - CLI installers
- `/api/admin/auth/*` - admin token auth endpoints
- `/api/policy/*` - relay policy endpoints
- `/sdk/*` - SDK/control endpoints
- `/discovery` - relay discovery when enabled

## Notes

- Relay path constants are owned by Go (`types/paths.go`) and mirrored in `src/lib/apiPaths.ts` for browser calls.
- Frontend API wire types live in `src/types/api.ts`.
- Radix Select values cannot be empty strings. Use stable values such as `"all"` and `"default"`.

## Recommendations

Favorites lists the current relay's public apps that the viewer has recommended.
Selecting the same vote again clears it. The relay stores votes and identifies
the viewer with a browser cookie; old browser-only favorites are not converted
into public votes.

## App Comments

The card's **Comments** action opens a separate right panel while the directory
remains usable. Comments are anonymous (displayed as Guest) and shared by
visitors of the same relay. Opening another app starts a separate draft.

`GET /api/comments?hostname=...` reads a public app's thread and
`POST /api/comments` accepts `{ hostname, text }`. Threads are attached to the
app's stable lease identity, so reusing a hostname does not inherit another
owner's comments. The relay saves them in `comments.json` beside its policy
state, independently of the app's current connection.

Comments are limited to 2,000 characters, 100 per app, and 1,000 per relay.
Posting uses a per-source budget of three comments per minute (burst three),
with a shared relay budget of 30 per minute (burst ten). Signed-in relay
administrators can delete a comment through
`POST /api/admin/comments/delete` with `{ id }`; the panel exposes this action
only after admin authentication. Reading and posting require an app to remain
in the public directory; admin deletion also works for offline threads.
