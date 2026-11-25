import type { Env, UserRecord } from "./types";
import { getUser, putUser } from "./session";

const BUFFER_GQL_URL = "https://api.buffer.com";
const BUFFER_TOKEN_URL = "https://auth.buffer.com/token";

/** Refresh the access token this long before its recorded expiry. */
const TOKEN_REFRESH_SKEW_MS = 5 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 15_000;
const MAX_ATTEMPTS = 3;

/** Single-flight map so concurrent syncs share one token refresh per user. */
const refreshesInFlight = new Map<string, Promise<UserRecord>>();

export class BufferAuthError extends Error {}

interface GraphQLResponse<T> {
  data?: T;
  errors?: { message?: string; extensions?: { code?: string } }[];
}

/**
 * Buffer sometimes reports auth failures as HTTP 200 with a GraphQL errors
 * array (`extensions.code: UNAUTHORIZED/FORBIDDEN`) instead of a 401, so both
 * shapes must be treated as credential failures.
 */
async function isAuthFailure(response: Response): Promise<boolean> {
  if (response.status === 401 || response.status === 403) return true;
  if (response.status !== 200) return false;
  try {
    const body = (await response.clone().json()) as {
      errors?: { extensions?: { code?: string } }[];
    };
    return (
      body.errors?.some(e =>
        ["UNAUTHORIZED", "FORBIDDEN"].includes(e?.extensions?.code ?? ""),
      ) ?? false
    );
  } catch {
    return false;
  }
}

/**
 * Run a GraphQL query against the Buffer API as `user`, transparently:
 *  - refreshing the OAuth access token when it is near/past expiry,
 *  - retrying once on auth failure after a forced refresh,
 *  - falling back to the stored API key (and pinning authMode to it) when
 *    OAuth is unrecoverable,
 *  - retrying transient failures (429 + 5xx) with bounded backoff.
 * Returns the final raw Response so callers can inspect rate-limit headers.
 */
export async function fetchBufferForUser(
  userId: string,
  user: UserRecord,
  env: Env,
  query: string,
): Promise<Response> {
  if (
    user.authMode !== "apiKey" &&
    user.refreshToken &&
    user.accessTokenExpiresAt &&
    user.accessTokenExpiresAt - Date.now() <= TOKEN_REFRESH_SKEW_MS
  ) {
    user = await refreshOAuthToken(userId, user, env);
  }

  const useApiKey = user.authMode === "apiKey";
  const credential = useApiKey ? user.apiKey : user.accessToken || user.apiKey;
  if (!credential) {
    throw new BufferAuthError("No Buffer credential is available");
  }

  let response = await requestWithRetry(credential, query);
  let authFailure = await isAuthFailure(response);

  if (authFailure && !useApiKey && user.refreshToken) {
    try {
      user = await refreshOAuthToken(userId, user, env, true);
      response = await requestWithRetry(user.accessToken!, query);
      authFailure = await isAuthFailure(response);
    } catch (error) {
      if (!user.apiKey) throw error;
      response = await requestWithRetry(user.apiKey, query);
      authFailure = false;
      if (response.ok) await pinApiKeyMode(userId, user, env);
    }
  }

  if (authFailure && !useApiKey && user.apiKey && user.apiKey !== credential) {
    response = await requestWithRetry(user.apiKey, query);
    if (response.ok) await pinApiKeyMode(userId, user, env);
  }

  return response;
}

async function pinApiKeyMode(userId: string, user: UserRecord, env: Env): Promise<void> {
  const latest = (await getUser(userId, env)) || user;
  const updated: UserRecord = { ...latest, authMode: "apiKey" };
  user.authMode = "apiKey";
  await putUser(env, updated);
}

/** Execute one GraphQL POST, retrying transient failures (429, 5xx, network). */
async function requestWithRetry(credential: string, query: string): Promise<Response> {
  let attempt = 0;
  let lastError: unknown;
  while (attempt < MAX_ATTEMPTS) {
    attempt++;
    try {
      const response = await fetch(BUFFER_GQL_URL, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${credential}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ query }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });

      // 401/403 are credential problems — never retried here.
      const retryable = response.status === 429 || response.status >= 500;
      if (!retryable || attempt === MAX_ATTEMPTS) return response;

      await sleep(backoffMs(attempt, response));
    } catch (error) {
      lastError = error;
      if (attempt === MAX_ATTEMPTS) break;
      await sleep(backoffMs(attempt, null));
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new Error("Buffer API request failed");
}

function backoffMs(attempt: number, response: Response | null): number {
  const retryAfter = response?.headers.get("Retry-After");
  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds > 0) {
      return Math.min(seconds * 1000, 30_000);
    }
  }
  const base = Math.min(1000 * 2 ** (attempt - 1), 8000);
  return base + Math.floor(Math.random() * 500);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Refresh the user's OAuth token pair via the refresh_token grant.
 *
 * Buffer refresh tokens are single-use and rotating — reusing a consumed one
 * REVOKES the whole grant — so refreshes must never race. Within one isolate
 * the in-flight map dedupes; across isolates (e.g. cron + manual refresh) a
 * short-lived KV lock makes concurrent refreshers wait and pick up the fresh
 * token instead of re-spending the old one.
 */
export async function refreshOAuthToken(
  userId: string,
  user: UserRecord,
  env: Env,
  force = false,
): Promise<UserRecord> {
  const existing = refreshesInFlight.get(userId);
  if (existing) return existing;

  const refresh = (async (): Promise<UserRecord> => {
    const lockKey = `lock:refresh:${userId}`;

    // If another isolate is mid-refresh, wait briefly for the new token pair
    // to land in KV rather than spending the same single-use refresh token.
    for (let attempt = 0; attempt < 3; attempt++) {
      if (!(await env.USERS_KV.get(lockKey))) break;
      await sleep(1500);
      const settled = await getUser(userId, env);
      if (
        settled?.accessTokenExpiresAt &&
        settled.accessTokenExpiresAt - Date.now() > TOKEN_REFRESH_SKEW_MS
      ) {
        Object.assign(user, settled);
        return settled;
      }
    }

    const latest = (await getUser(userId, env)) || user;
    if (
      !force &&
      latest.accessTokenExpiresAt &&
      latest.accessTokenExpiresAt - Date.now() > TOKEN_REFRESH_SKEW_MS
    ) {
      Object.assign(user, latest);
      return latest;
    }
    if (!latest.refreshToken) return latest;

    await env.USERS_KV.put(lockKey, "1", { expirationTtl: 30 });
    try {
      const response = await fetch(BUFFER_TOKEN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: env.BUFFER_CLIENT_ID,
          client_secret: env.BUFFER_CLIENT_SECRET,
          grant_type: "refresh_token",
          refresh_token: latest.refreshToken,
        }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });

      if (!response.ok) {
        console.error("Buffer OAuth token refresh failed:", response.status);
        await recordAuthError(env, userId, "Buffer authorization expired. Please sign in again.");
        throw new BufferAuthError("Buffer authorization expired. Please sign in again.");
      }

      const tokens = (await response.json()) as {
        access_token?: string;
        refresh_token?: string;
        expires_in?: number;
      };
      if (!tokens.access_token) {
        throw new BufferAuthError("Buffer did not return a refreshed access token.");
      }

      // Buffer rotates refresh tokens on every refresh — always persist the
      // replacement atomically with the access token, and never reuse the old
      // one (doing so revokes the grant).
      const updated: UserRecord = {
        ...latest,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token ?? latest.refreshToken,
        accessTokenExpiresAt: Date.now() + (tokens.expires_in || 3600) * 1000,
        lastAuthError: null,
      };
      await putUser(env, updated);
      Object.assign(user, updated);
      return updated;
    } finally {
      await env.USERS_KV.delete(lockKey);
    }
  })();

  refreshesInFlight.set(userId, refresh);
  try {
    return await refresh;
  } finally {
    refreshesInFlight.delete(userId);
  }
}

/** Stamp a user with an auth error so the dashboard can prompt reconnection. */
export async function recordAuthError(env: Env, userId: string, message: string): Promise<void> {
  const latest = await getUser(userId, env);
  if (!latest) return;
  await putUser(env, { ...latest, lastAuthError: message });
}

/** Parse a GraphQL response body, throwing on transport or GraphQL errors. */
export async function readGraphQL<T>(response: Response, label: string): Promise<T> {
  if (!response.ok) {
    if (response.status === 401) throw new BufferAuthError("Buffer auth expired");
    throw new Error(`Buffer ${label} HTTP error: ${response.status}`);
  }
  const data = (await response.json()) as GraphQLResponse<T>;
  if (data.errors?.length) {
    console.error(`Buffer ${label} GraphQL errors:`, JSON.stringify(data.errors));
    const first = data.errors[0];
    if (["UNAUTHORIZED", "FORBIDDEN"].includes(first?.extensions?.code ?? "")) {
      throw new BufferAuthError(first?.message || "Buffer auth expired");
    }
    throw new Error(first?.message || `Buffer ${label} query failed`);
  }
  if (data.data === undefined || data.data === null) {
    throw new Error(`Buffer ${label} returned no data`);
  }
  return data.data;
}

export interface RateLimitWindow {
  window: string;
  limit: number;
  remaining: number | null;
  used: number | null;
  resetInSeconds: number | null;
}

/** Parse IETF `RateLimit` / `RateLimit-Policy` headers returned by Buffer. */
export function parseRateLimitHeaders(headers: Headers): RateLimitWindow[] {
  const rateHeader = headers.get("ratelimit") || "";
  const policyHeader = headers.get("ratelimit-policy") || "";
  const rates = [...rateHeader.matchAll(/"([^"]+)"\s*;\s*r=(\d+)\s*;\s*t=(\d+)/gi)];
  const policies = [...policyHeader.matchAll(/"([^"]+)"\s*;\s*q=(\d+)\s*;\s*w=(\d+)/gi)];
  const labels: Record<number, string> = {
    900: "15 minutes",
    86400: "24 hours",
    2592000: "30 days",
  };
  return policies.map((policy, index) => {
    const windowSeconds = Number(policy[3]);
    const rate = rates.find(entry => entry[1] === policy[1]) || rates[index];
    const limit = Number(policy[2]);
    const remaining = rate ? Number(rate[2]) : null;
    return {
      window: labels[windowSeconds] || `${windowSeconds} seconds`,
      limit,
      remaining,
      used: remaining === null ? null : Math.max(0, limit - remaining),
      resetInSeconds: rate ? Number(rate[3]) : null,
    };
  });
}
