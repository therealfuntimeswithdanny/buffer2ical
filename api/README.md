# buffer2ical-api

Cloudflare Worker backing [Buffer2iCal](https://buffer2ical.madebydanny.uk) — syncs
Buffer queues into subscribable iCal feeds. Written in TypeScript, no runtime
dependencies.

**One worker runs everything**: the API, the OAuth endpoints, the iCal feeds,
and the static frontend (served from `../public` via Workers Static Assets) all
live on the same domain. There is no CORS exposure in practice — session
cookies are `SameSite=Lax` because the frontend is same-origin.

## Layout

| File | Responsibility |
| --- | --- |
| `src/index.ts` | Worker entrypoint: route table, CORS, cron trigger |
| `src/types.ts` | Env bindings + KV record types |
| `src/http.ts` | JSON/CORS/redirect/cookie helpers |
| `src/session.ts` | Rolling sessions: create, resolve (with keep-alive renewal), reset-all |
| `src/routes.ts` | All route handlers: OAuth, API-key auth, sessions, feed, admin |
| `src/buffer.ts` | Buffer GraphQL client: token refresh (single-flight), API-key fallback, 429/5xx backoff, rate-limit parsing |
| `src/sync.ts` | Feed sync: channels + paginated scheduled posts → stats + ICS in KV; cron fan-out |
| `src/ics.ts` | RFC 5545 iCal generation (escaping, CRLF folding, refresh hints) |

## Sessions

Sessions are rolling 30-day cookies (`HttpOnly; Secure; SameSite=None`). Any
authenticated request extends the TTL (re-written at most once per day), so
active users never get logged out — "keep it on". `POST /api/session/reset`
invalidates every session for the user (server-side `sessionVersion` bump) and
issues a fresh cookie for the current browser: "sign out other devices".

## Buffer auth

Two credential modes per user:

- **OAuth** (`authMode: "oauth"`) — PKCE authorization-code flow against
  `auth.buffer.com` with a double-submit state cookie. Access tokens are
  refreshed automatically via the `refresh_token` grant 5 minutes before
  expiry (and retried once on any 401), single-flighted per user.
- **API key** (`authMode: "apiKey"`) — personal access tokens never expire.
  If OAuth becomes unrecoverable but the user also stored an API key, the
  worker falls back to it and pins the account to API-key mode.

Unrecoverable auth failures are recorded as `lastAuthError` on the user record
and surfaced in `/api/me` so the dashboard can prompt reconnection.

## Setup

```sh
npm install
```

1. Create two KV namespaces and put their IDs in `wrangler.toml`:
   ```sh
   npx wrangler kv namespace create USERS_KV
   npx wrangler kv namespace create SESSIONS_KV
   ```
2. Set secrets from your Buffer developer app:
   ```sh
   npx wrangler secret put BUFFER_CLIENT_ID
   npx wrangler secret put BUFFER_CLIENT_SECRET
   ```
3. Fix `FRONTEND_URL` in `wrangler.toml` (it must exactly match the origin the
   dashboard is served from — CORS and cookie rules depend on it).
4. Optionally set `ADMIN_BUFFER_ID` for `/api/admin/overview` access.

## Commands

```sh
npm run dev        # local dev server
npm run typecheck  # tsc --noEmit
npm run deploy     # wrangler deploy
```

## Cron

`*/5 * * * *` — syncs every user's feed with concurrency 5 and writes a status
row to `system:cron:last` (visible in the admin overview).
