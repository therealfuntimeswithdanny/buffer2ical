import type { Env } from "./types";
import { corsHeaders, json, withCors } from "./http";
import { runScheduledSync } from "./sync";
import {
  handleAccountRefresh,
  handleAdminOverview,
  handleApiKeySignIn,
  handleDeleteUser,
  handleFeed,
  handleLogout,
  handleMe,
  handleOAuthCallback,
  handleOAuthStart,
  handleOrganizationSignIn,
  handlePendingSignIn,
  handleRefresh,
  handleSessionHeartbeat,
  handleSessionReset,
} from "./routes";

type RouteHandler = (request: Request, env: Env) => Promise<Response>;

const routes: Record<string, Record<string, RouteHandler>> = {
  "/api/me": { GET: handleMe },
  "/api/session/heartbeat": { GET: handleSessionHeartbeat },
  "/api/session/reset": { POST: handleSessionReset },
  "/api/admin/overview": { GET: handleAdminOverview },
  "/api/auth/apikey": { POST: handleApiKeySignIn },
  "/api/auth/pending": { GET: handlePendingSignIn },
  "/api/auth/organization": { POST: handleOrganizationSignIn },
  "/api/refresh": { POST: handleRefresh },
  "/api/account/refresh": { POST: handleAccountRefresh },
  "/api/logout": { POST: handleLogout },
  "/api/user": { DELETE: handleDeleteUser },
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    // Note: /dashboard (and other clean URLs) are served by the assets
    // binding — it normalizes *.html URLs itself.
    if (path === "/auth/buffer") {
      return handleOAuthStart(env);
    }
    if (path === "/auth/callback") {
      return handleOAuthCallback(request, env);
    }
    if (path === "/feed") {
      return handleFeed(request, env);
    }

    // API routes — everything else falls through to static assets.
    const handler = routes[path]?.[method];
    if (!handler) {
      if (path.startsWith("/api/")) {
        return withCors(json({ error: "Not Found" }, 404), env);
      }
      return env.ASSETS.fetch(request);
    }

    let res: Response;
    try {
      res = await handler(request, env);
    } catch (e) {
      console.error("Worker error:", e);
      res = json({ error: (e as Error)?.message || "Internal server error" }, 500);
    }

    return withCors(res, env);
  },

  async scheduled(_event, env, ctx) {
    ctx.waitUntil(runScheduledSync(env));
  },
} satisfies ExportedHandler<Env>;
