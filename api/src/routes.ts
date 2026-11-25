import type {
  BufferAccount,
  BufferOrganization,
  Env,
  PendingAuth,
  UserRecord,
} from "./types";
import type { RateLimitWindow } from "./buffer";
import {
  clearSessionCookie,
  createSession,
  destroySession,
  getSessionId,
  getUser,
  putUser,
  resetUserSessions,
  resolveSession,
  sessionCookie,
  SESSION_TTL_SECONDS,
} from "./session";
import {
  fetchBufferForUser,
  parseRateLimitHeaders,
  readGraphQL,
} from "./buffer";
import { ensureOrganization, getAllUsers, getUserStats, refreshUserFeed } from "./sync";
import { CALENDAR_HEADERS, generateEmptyICS } from "./ics";
import {
  getCookie,
  json,
  originOk,
  redirectWithCookie,
} from "./http";

const PENDING_TTL_SECONDS = 600;
const OAUTH_STATE_TTL_SECONDS = 600;
const REQUEST_TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------------------
// OAuth (PKCE + double-submit state cookie)
// ---------------------------------------------------------------------------

function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function oauthStateCookie(state: string): string {
  return [
    `oauth_${state}=${state}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${OAUTH_STATE_TTL_SECONDS}`,
    "Path=/auth/callback",
  ].join("; ");
}

function clearOAuthStateCookie(state: string | null): string {
  return [
    `oauth_${state || "invalid"}=`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
    "Path=/auth/callback",
  ].join("; ");
}

export async function handleOAuthStart(env: Env): Promise<Response> {
  const state = crypto.randomUUID();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  await env.SESSIONS_KV.put(
    `oauth:${state}`,
    JSON.stringify({ codeVerifier, createdAt: Date.now() }),
    { expirationTtl: OAUTH_STATE_TTL_SECONDS },
  );

  const authUrl =
    "https://auth.buffer.com/auth?" +
    new URLSearchParams({
      client_id: env.BUFFER_CLIENT_ID,
      redirect_uri: `${env.API_URL}/auth/callback`,
      response_type: "code",
      scope: "posts:read account:read offline_access",
      prompt: "consent",
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });

  return redirectWithCookie(authUrl, oauthStateCookie(state));
}

export async function handleOAuthCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");
  const stateCookie = state ? getCookie(request, `oauth_${state}`) : null;

  const finish = (path: string) =>
    redirectWithCookie(`${env.FRONTEND_URL}${path}`, clearOAuthStateCookie(state));

  if (error) return finish(`/?error=${encodeURIComponent(error)}`);
  if (!code || !state) return finish("/?error=missing_oauth_parameters");
  if (!stateCookie || stateCookie !== state) return finish("/?error=invalid_state");

  const sessionData = await env.SESSIONS_KV.get(`oauth:${state}`);
  if (!sessionData) return finish("/?error=invalid_state");
  const { codeVerifier } = JSON.parse(sessionData) as { codeVerifier: string };
  await env.SESSIONS_KV.delete(`oauth:${state}`);

  const tokenRes = await fetch("https://auth.buffer.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.BUFFER_CLIENT_ID,
      client_secret: env.BUFFER_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: `${env.API_URL}/auth/callback`,
      code_verifier: codeVerifier,
    }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });

  if (!tokenRes.ok) {
    console.error("Token exchange failed:", await tokenRes.text());
    return finish("/?error=token_exchange_failed");
  }

  const tokens = (await tokenRes.json()) as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
  };
  if (!tokens.access_token) return finish("/?error=no_access_token");

  const userRes = await fetch("https://api.buffer.com", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tokens.access_token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      query: `{ account { id email name organizations { id name } } }`,
    }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });

  if (!userRes.ok) {
    console.error("Buffer account request failed:", await userRes.text());
    return finish("/?error=buffer_account_request_failed");
  }

  let bufferUser: BufferAccount;
  try {
    const userData = await readGraphQL<{ account?: BufferAccount }>(userRes, "account");
    bufferUser = (userData.account ?? {}) as BufferAccount;
  } catch (e) {
    console.error("Buffer account query failed:", e);
    return finish("/?error=buffer_account_query_failed");
  }

  if (!bufferUser.id || !bufferUser.organizations?.length) {
    return finish("/?error=no_buffer_organization");
  }

  const pendingId = crypto.randomUUID();
  const pending: PendingAuth = {
    bufferUser,
    organizations: bufferUser.organizations,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token || null,
    accessTokenExpiresAt: tokens.expires_in
      ? Date.now() + tokens.expires_in * 1000
      : null,
  };
  await env.SESSIONS_KV.put(`auth-pending:${pendingId}`, JSON.stringify(pending), {
    expirationTtl: PENDING_TTL_SECONDS,
  });

  return finish(`/app/organization.html?pending=${encodeURIComponent(pendingId)}`);
}

// ---------------------------------------------------------------------------
// API-key sign-in
// ---------------------------------------------------------------------------

export async function handleApiKeySignIn(request: Request, env: Env): Promise<Response> {
  if (!originOk(request, env)) return json({ error: "Forbidden" }, 403);

  let body: { apiKey?: unknown };
  try {
    body = (await request.json()) as { apiKey?: unknown };
  } catch {
    return json({ error: "Invalid request body." }, 400);
  }

  const apiKey = typeof body?.apiKey === "string" ? body.apiKey.trim() : "";
  if (!apiKey || apiKey.length > 512) {
    return json({ error: "Enter a valid Buffer API key." }, 400);
  }

  const accountResult = await fetch("https://api.buffer.com", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      query: `{ account { id email name organizations { id name } } }`,
    }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });

  if (!accountResult.ok) {
    if (accountResult.status === 401) {
      return json({ error: "Buffer rejected that API key. Check it and try again." }, 401);
    }
    console.error("Buffer API key verification failed:", accountResult.status);
    return json({ error: "Could not verify the API key with Buffer. Please try again." }, 502);
  }

  const accountData = (await accountResult.json()) as {
    data?: { account?: BufferAccount };
    errors?: unknown[];
  };
  if (accountData.errors?.length || !accountData.data?.account?.id) {
    console.error("Buffer account query failed during API key sign-in.");
    return json({ error: "Could not verify the API key with Buffer. Please try again." }, 502);
  }

  const bufferUser = accountData.data.account;
  if (!bufferUser.organizations?.length) {
    return json({ error: "No Buffer organizations were found for this account." }, 400);
  }

  const pendingId = crypto.randomUUID();
  const pending: PendingAuth = { bufferUser, organizations: bufferUser.organizations, apiKey };
  await env.SESSIONS_KV.put(`auth-pending:${pendingId}`, JSON.stringify(pending), {
    expirationTtl: PENDING_TTL_SECONDS,
  });

  return json({ pendingId });
}

export async function handlePendingSignIn(request: Request, env: Env): Promise<Response> {
  const origin = request.headers.get("Origin");
  if (origin && origin !== env.FRONTEND_URL) return json({ error: "Forbidden" }, 403);

  const pendingId = new URL(request.url).searchParams.get("pending");
  if (!pendingId) return json({ error: "Sign-in expired. Please start again." }, 400);

  const pending = await env.SESSIONS_KV.get(`auth-pending:${pendingId}`, "json");
  if (!pending) return json({ error: "Sign-in expired. Please start again." }, 404);

  const { organizations } = pending as PendingAuth;
  return json({
    organizations: organizations.map(({ id, name }) => ({ id, name })),
  });
}

export async function handleOrganizationSignIn(request: Request, env: Env): Promise<Response> {
  if (!originOk(request, env)) return json({ error: "Forbidden" }, 403);

  let body: { pendingId?: unknown; organizationId?: unknown };
  try {
    body = (await request.json()) as { pendingId?: unknown; organizationId?: unknown };
  } catch {
    return json({ error: "Invalid request body." }, 400);
  }
  if (typeof body?.pendingId !== "string" || typeof body?.organizationId !== "string") {
    return json({ error: "Choose a Buffer organization to continue." }, 400);
  }

  const pendingKey = `auth-pending:${body.pendingId}`;
  const pending = await env.SESSIONS_KV.get(pendingKey, "json");
  if (!pending) return json({ error: "Sign-in expired. Please start again." }, 404);
  const auth = pending as PendingAuth;

  const organization = auth.organizations.find(item => item.id === body.organizationId);
  if (!organization) {
    return json({ error: "That organization is not available for this Buffer account." }, 403);
  }

  const userId = auth.bufferUser.id;
  const oldUser = await getUser(userId, env);
  const userRecord: UserRecord = {
    ...(oldUser || {}),
    bufferId: userId,
    organizationId: organization.id,
    organizationName: organization.name,
    email: auth.bufferUser.email || oldUser?.email,
    name:
      auth.bufferUser.name ||
      auth.bufferUser.email?.split("@")[0] ||
      oldUser?.name ||
      "User",
    accessToken: auth.accessToken || oldUser?.accessToken || auth.apiKey,
    apiKey: auth.apiKey || oldUser?.apiKey,
    authMode: auth.accessToken
      ? "oauth"
      : auth.apiKey
        ? oldUser?.authMode || (oldUser?.accessToken ? "oauth" : "apiKey")
        : oldUser?.authMode || "oauth",
    refreshToken: auth.refreshToken || oldUser?.refreshToken || null,
    accessTokenExpiresAt: auth.accessTokenExpiresAt || oldUser?.accessTokenExpiresAt || null,
    sessionVersion: oldUser?.sessionVersion || crypto.randomUUID(),
    lastAuthError: null,
    createdAt: oldUser?.createdAt || new Date().toISOString(),
    lastSync: oldUser?.lastSync || null,
  };

  await putUser(env, userRecord);
  await env.SESSIONS_KV.delete(pendingKey);

  const sessionId = await createSession(env, userRecord);
  return json({ success: true }, 200, { "Set-Cookie": sessionCookie(sessionId) });
}

// ---------------------------------------------------------------------------
// Authenticated API
// ---------------------------------------------------------------------------

/** Standard renewal header when resolveSession() extended the rolling TTL. */
function renewalHeaders(renewed: boolean, sessionId: string): Record<string, string> {
  return renewed ? { "Set-Cookie": sessionCookie(sessionId) } : {};
}

export async function handleMe(request: Request, env: Env): Promise<Response> {
  const session = await resolveSession(request, env);
  if (!session) return json({ error: "Unauthorized" }, 401);
  let { user } = session;

  if (!user.organizationId) {
    try {
      user = await ensureOrganization(session.userId, user, env);
    } catch (e) {
      console.error("Organization repair failed:", e);
    }
  }

  const stats = await getUserStats(session.userId, env);

  return json(
    {
      user: {
        name: user.name,
        email: user.email,
        lastSync: user.lastSync,
        authMode: user.authMode,
      },
      isAdmin: session.userId === adminBufferId(env),
      feedUrl: `${env.API_URL}/feed?user=${session.userId}`,
      stats,
      authError: user.lastAuthError || null,
    },
    200,
    renewalHeaders(session.renewed, session.sessionId),
  );
}

/** "Keep it on" heartbeat: resolves + renews the session without extra work. */
export async function handleSessionHeartbeat(request: Request, env: Env): Promise<Response> {
  const session = await resolveSession(request, env);
  if (!session) return json({ authenticated: false }, 401);
  return json(
    { authenticated: true },
    200,
    renewalHeaders(session.renewed, session.sessionId),
  );
}

/** Sign out this device and every other session for the user, then start fresh. */
export async function handleSessionReset(request: Request, env: Env): Promise<Response> {
  if (!originOk(request, env)) return json({ error: "Forbidden" }, 403);
  const session = await resolveSession(request, env);
  if (!session) return json({ error: "Unauthorized" }, 401);

  // Invalidate all issued sessions, then mint a fresh one for this browser.
  const updatedUser = await resetUserSessions(env, session.user);
  await destroySession(env, session.sessionId);
  const newSessionId = await createSession(env, updatedUser);

  return json({ success: true }, 200, { "Set-Cookie": sessionCookie(newSessionId) });
}

export async function handleRefresh(request: Request, env: Env): Promise<Response> {
  if (!originOk(request, env)) return json({ error: "Forbidden" }, 403);
  const session = await resolveSession(request, env);
  if (!session) return json({ error: "Unauthorized" }, 401);

  try {
    const result = await refreshUserFeed(session.userId, env);
    return json(
      {
        success: true,
        count: result.events.length,
        stats: result.stats,
        lastSync: result.stats.lastSync,
      },
      200,
      renewalHeaders(session.renewed, session.sessionId),
    );
  } catch (e) {
    console.error("Refresh failed:", e);
    return json({ success: false, error: (e as Error).message }, 500);
  }
}

export async function handleAccountRefresh(request: Request, env: Env): Promise<Response> {
  if (!originOk(request, env)) return json({ error: "Forbidden" }, 403);
  const session = await resolveSession(request, env);
  if (!session) return json({ error: "Unauthorized" }, 401);

  try {
    const res = await fetchBufferForUser(
      session.userId,
      session.user,
      env,
      `{ account { email name } }`,
    );
    const data = await readGraphQL<{ account?: { email?: string; name?: string } }>(
      res,
      "account",
    );
    const account = data.account;
    if (!account) throw new Error("Buffer account data was not returned");

    const updatedUser: UserRecord = {
      ...session.user,
      email: account.email ?? session.user.email,
      name: account.name || account.email?.split("@")[0] || session.user.name,
    };
    await putUser(env, updatedUser);

    return json(
      { success: true, user: { name: updatedUser.name, email: updatedUser.email } },
      200,
      renewalHeaders(session.renewed, session.sessionId),
    );
  } catch (e) {
    console.error("Buffer account refresh failed:", e);
    return json(
      { success: false, error: (e as Error).message || "Unable to refresh account" },
      502,
    );
  }
}

export async function handleLogout(request: Request, env: Env): Promise<Response> {
  if (!originOk(request, env)) return json({ error: "Forbidden" }, 403);
  const sessionId = getSessionId(request);
  if (sessionId) await destroySession(env, sessionId);
  return json({ success: true }, 200, { "Set-Cookie": clearSessionCookie() });
}

export async function handleDeleteUser(request: Request, env: Env): Promise<Response> {
  if (!originOk(request, env)) return json({ error: "Forbidden" }, 403);
  const session = await resolveSession(request, env);
  if (!session) return json({ error: "Unauthorized" }, 401);

  await Promise.all([
    env.USERS_KV.delete(`user:${session.userId}`),
    env.USERS_KV.delete(`feed:${session.userId}`),
    env.USERS_KV.delete(`stats:${session.userId}`),
    destroySession(env, session.sessionId),
  ]);
  // Other browsers' sessions expire naturally; a re-login gets a fresh version.

  return json({ success: true }, 200, { "Set-Cookie": clearSessionCookie() });
}

// ---------------------------------------------------------------------------
// Feed
// ---------------------------------------------------------------------------

export async function handleFeed(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const userId = url.searchParams.get("user");
  if (!userId) return new Response("Missing user parameter", { status: 400 });

  const ics = await env.USERS_KV.get(`feed:${userId}`);
  if (ics) return new Response(ics, { headers: CALENDAR_HEADERS });

  try {
    await refreshUserFeed(userId, env);
    const fresh = await env.USERS_KV.get(`feed:${userId}`);
    if (fresh) return new Response(fresh, { headers: CALENDAR_HEADERS });
  } catch (e) {
    console.error(`Feed failed for ${userId}:`, e);
  }

  return new Response(generateEmptyICS(), { headers: CALENDAR_HEADERS });
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

const DEFAULT_ADMIN_BUFFER_ID = "69244d3f82e615cec1b2d47e";
function adminBufferId(env: Env): string {
  return env.ADMIN_BUFFER_ID || DEFAULT_ADMIN_BUFFER_ID;
}

export async function handleAdminOverview(request: Request, env: Env): Promise<Response> {
  const session = await resolveSession(request, env);
  if (!session) return json({ error: "Unauthorized" }, 401);
  if (session.userId !== adminBufferId(env)) return json({ error: "Forbidden" }, 403);

  const owner = session.user;
  if (owner.authMode !== "oauth" || !owner.accessToken) {
    return json(
      { error: "Sign in with Buffer OAuth to inspect OAuth client limits." },
      409,
    );
  }

  let limitResponse: Response;
  try {
    limitResponse = await fetchBufferForUser(
      session.userId,
      owner,
      env,
      "{ account { id } }",
    );
  } catch (error) {
    return json({ error: (error as Error).message || "Could not read Buffer API limits." }, 502);
  }

  const latestOwner = await getUser(session.userId, env);
  if (latestOwner?.authMode !== "oauth") {
    return json(
      { error: "The owner account switched to API key authentication. Reconnect it with OAuth to inspect OAuth client limits." },
      409,
    );
  }
  if (limitResponse.status === 401) {
    return json({ error: "Buffer OAuth authorization expired. Reconnect the owner account." }, 502);
  }
  if (!limitResponse.ok) {
    return json({ error: `Buffer returned HTTP ${limitResponse.status}.` }, 502);
  }

  const payload = (await limitResponse.json()) as {
    data?: { account?: { id?: string } };
    errors?: unknown[];
  };
  if (payload.errors?.length || payload.data?.account?.id !== adminBufferId(env)) {
    return json({ error: "Buffer did not confirm the owner account." }, 502);
  }

  const users = await getAllUsers(env);
  const now = Date.now();
  const summary = {
    total: users.length,
    oauth: users.filter(u => u.authMode !== "apiKey" && u.accessToken).length,
    apiKey: users.filter(u => u.authMode === "apiKey").length,
    authErrors: users.filter(u => u.lastAuthError).length,
    syncedLast24Hours: users.filter(
      u => u.lastSync && now - Date.parse(u.lastSync) < 86_400_000,
    ).length,
    scheduledPostsCached: 0,
    latestSync: null as string | null,
  };
  for (const user of users) {
    if (user.lastSync && (!summary.latestSync || user.lastSync > summary.latestSync)) {
      summary.latestSync = user.lastSync;
    }
    const rawStats = await env.USERS_KV.get(`stats:${user.bufferId}`);
    if (rawStats) {
      try {
        summary.scheduledPostsCached +=
          (JSON.parse(rawStats) as { scheduled?: number }).scheduled || 0;
      } catch {
        // ignore malformed stats rows
      }
    }
  }

  const rateLimits: RateLimitWindow[] = parseRateLimitHeaders(limitResponse.headers);

  return json({
    generatedAt: new Date().toISOString(),
    users: summary,
    rateLimits,
    rateLimitSource: "Live Buffer OAuth API response headers",
    scheduledSync: await env.USERS_KV.get("system:cron:last", "json"),
  });
}
