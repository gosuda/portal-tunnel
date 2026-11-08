# Relay Server Frontend

React + TypeScript frontend for relay server discovery and onboarding.

## Tech Stack

- React 19
- TypeScript
- Vite 7
- Tailwind CSS 4
- Lucide React
- Radix Dialog (the only headless primitive; everything else is Tailwind + tokens)
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
- UI is built on role-based design tokens in `src/index.css`; components pick a role, never a hue, so light and dark differ only there.
  - Roles: `surface-0..300` stack backgrounds (0 is the page, 300 the most raised), `content`, `content-emphasis` and `content-muted` color text and icons, `stroke` draws hairlines, and `state-hover` and `state-press` are translucent overlays rather than solid fills.
  - Hover and press come from the `interactive` state-layer utility: a translucent overlay painted between an element's own background and its content.
  - Spacing is Tailwind's 4px scale. `type-*` utilities give one class per type role (weight, size, line height).
  - `AppShell` fixes a 40px header and a 289px sidebar that docks at the `nav` breakpoint (1140px) and slides over the page below it. Any element carrying `data-nav-close` inside the sidebar closes the drawer.
- Browser storage can be unavailable in restricted contexts. The theme, the recently opened apps (`portal.recentApps`, newest first) and the `isPush` flag all ignore a failed read or write and carry on without it.
- Opening a flagged app (`/server/:id`) relies on the card passing its directory entry as router state. A direct visit has none and goes back to the directory, as does an unflagged app, which opens its service directly.
- `isPush` lives in session storage so it stays with one tab: a service opened in one tab never sends another tab's detail page back to the directory. It is set right before the page leaves for the service, and on returning (Back or a bfcache restore) the page goes to the directory instead of opening the service again.
- `WebAppLink` is for web apps only; a raw TCP or UDP app has no link and shows its endpoints with copy buttons instead.
- `src/lib/signinCopy.json` carries the texts of the Go sign-in pages. `sdk/appauth/signin_page_test.go` fails when a page and the file differ. OIDC and SAML leave for the provider at once and have no page of their own, so the Launch App preview only says where the visitor is sent.
- Live regions that announce text (the allow-list notices and the "Not ready to copy" notice in Launch App) stay mounted even when empty, because a region only announces text that appears inside it.
- Admin actions in `useAdmin` record their own failure in `error`; components only track that an action is running (`useBusy`).

## Recommendations

Favorites lists the current relay's public apps that the viewer has recommended.
Selecting the same vote again clears it. The relay stores votes and identifies
the viewer with a browser cookie; old browser-only favorites are not converted
into public votes.

## App Comments

The card's **Comments** action opens a right sheet (bottom sheet on narrow
screens). Comments are anonymous (displayed as Guest) and shared by
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
