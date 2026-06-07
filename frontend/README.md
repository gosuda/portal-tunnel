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

The Go relay is API-only. This frontend is a standalone Vite app that talks to
the relay over the JSON API and does not receive server-side injected lease
data.

- Public presentation state is loaded from `/ui/state`.
- Operator presentation policy state is loaded from `/ui/policy/state`.
- All JSON API responses use the `{ ok, data?, error? }` envelope parsed by `src/lib/apiClient.ts`.
- `VITE_PORTAL_API_BASE_URL` points the frontend at the public edge origin or deployment base path, not at `/api`; `/api`, `/ui`, `/sdk`, and `/discovery` are sibling paths. Admin auth uses a bearer token returned by `/api/admin/auth/login`.

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
  api/
    server.ts
  index.html
  package.json
  tsconfig.json
  tsconfig.api.json
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

To run against another origin, build or run the frontend with the public edge origin:

```bash
VITE_PORTAL_API_BASE_URL=https://portal.example.com npm run dev
```

## Docker

The frontend Docker image serves the built Vite app with nginx over HTTP. It
does not own API path routing; the public edge nginx routes relay-owned paths to
`portal:4017` and `/ui/*` presentation paths to `portal-api:8081`.
TLS for public domains should live in the outer reverse proxy. The app uses
same-origin relative API paths, so it does not need runtime config file
generation.

```bash
docker compose up -d portal-frontend
```

## NPM Scripts

| Script | Purpose |
| --- | --- |
| `npm run dev` | Start the Vite development server. |
| `npm run build` | Type-check and build production assets. |
| `npm run build:api` | Build the TypeScript API service. |
| `npm run lint` | Run ESLint. |
| `npm run typecheck` | Run TypeScript checking. |
| `npm test` | Run Vitest. |
| `npm run preview` | Preview the production bundle. |

## Relay Integration

Relay server exposes:

- `/` - relay API identity response
- `/api/state` - public leases
- `/api/install.sh` and `/api/install.ps1` - CLI installers
- `/api/admin/auth/*` - admin wallet auth endpoints
- `/api/policy/*` - relay policy endpoints
- `/sdk/*` - SDK/control endpoints
- `/discovery` - relay discovery when enabled

The TypeScript API service composes frontend-owned presentation
state on top of relay data under the `/ui/` prefix:

- `/ui/state` - relay leases plus `landing_page_enabled`
- `/ui/policy/*` - relay policy, with `landing_page_enabled` composed into `/ui/policy` and `/ui/policy/state`
- `/ui/service/status` - hostname and service readiness derived from relay `/api/state`
- `/ui/thumbnail/{hostname}` - generated screenshots, disabled when `HEADLESS_SHELL_URL` is empty

## Notes

- Relay path constants are owned by Go (`types/paths.go`) and mirrored in `src/lib/apiPaths.ts` for browser calls; presentation paths live under `/ui/` in `api/server.ts`, the edge nginx config, and `src/lib/apiPaths.ts`.
- Frontend API wire types live in `src/types/api.ts`.
- Radix Select values cannot be empty strings. Use stable values such as `"all"` and `"default"`.
