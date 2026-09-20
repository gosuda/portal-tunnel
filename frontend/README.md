# Relay frontend

React/Vite UI served by the Go relay at `/`. It uses the relay's `/api/*`,
`/sdk/*`, and `/discovery*` endpoints directly. See [AGENTS.md](AGENTS.md) for
API and component conventions.

```bash
npm ci
npm run dev
```

Set `VITE_PORTAL_API_BASE_URL` to a relay origin when developing against a
separate backend. Leave it unset to use the browser origin.

`npm run build` writes `dist/`. From the repository root, `make build-frontend`
builds and copies those assets into `cmd/relay-server/dist/app` for embedding.

Run `npm test` for component and API regressions. `npm run typecheck` and
`npm run lint` check types and source rules.
