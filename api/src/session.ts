import type { Env, SessionRecord, UserRecord } from "./types";
import { getCookie } from "./http";

/** Rolling session length: renewed automatically while the user stays active. */
export const SESSION_TTL_SECONDS = 86400 * 30; // 30 days
/** Only re-write the session KV row / cookie at most this often. */
const SESSION_TOUCH_INTERVAL_MS = 24 * 60 * 60 * 1000; // 1 day

const SESSION_COOKIE_NAME = "session";

export function sessionCookie(sessionId: string): string {
  return [
    `${SESSION_COOKIE_NAME}=${sessionId}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${SESSION_TTL_SECONDS}`,
    "Path=/",
  ].join("; ");
}

export function clearSessionCookie(): string {
  return [
    `${SESSION_COOKIE_NAME}=`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
    "Path=/",
  ].join("; ");
}

export function getSessionId(request: Request): string | null {
  return getCookie(request, SESSION_COOKIE_NAME);
}

export async function createSession(env: Env, user: UserRecord): Promise<string> {
  const sessionId = crypto.randomUUID();
  const record: SessionRecord = {
    userId: user.bufferId,
    version: user.sessionVersion,
    touchedAt: Date.now(),
  };
  await env.SESSIONS_KV.put(`session:${sessionId}`, JSON.stringify(record), {
    expirationTtl: SESSION_TTL_SECONDS,
  });
  return sessionId;
}

export interface SessionResolution {
  userId: string;
  sessionId: string;
  user: UserRecord;
  /** Non-null when the rolling TTL was extended — caller should re-set the cookie. */
  renewed: boolean;
}

/**
 * Resolve the `session` cookie to a user, or null when the session is missing,
 * malformed, or invalidated by a later `sessionVersion` bump ("sign out
 * everywhere"). Extends the rolling TTL at most once per day — this is the
 * "keep me signed in" behaviour: active users are never logged out.
 */
export async function resolveSession(
  request: Request,
  env: Env,
): Promise<SessionResolution | null> {
  const sessionId = getSessionId(request);
  if (!sessionId) return null;

  const raw = await env.SESSIONS_KV.get(`session:${sessionId}`);
  if (!raw) return null;

  let session: SessionRecord;
  try {
    session = JSON.parse(raw) as SessionRecord;
  } catch {
    return null;
  }
  if (!session?.userId || !session?.version) return null;

  const user = await getUser(session.userId, env);
  if (!user || user.sessionVersion !== session.version) return null;

  let renewed = false;
  if (Date.now() - (session.touchedAt || 0) > SESSION_TOUCH_INTERVAL_MS) {
    session.touchedAt = Date.now();
    await env.SESSIONS_KV.put(`session:${sessionId}`, JSON.stringify(session), {
      expirationTtl: SESSION_TTL_SECONDS,
    });
    renewed = true;
  }

  return { userId: session.userId, sessionId, user, renewed };
}

export async function destroySession(env: Env, sessionId: string): Promise<void> {
  await env.SESSIONS_KV.delete(`session:${sessionId}`);
}

/** Invalidate every session for this user by bumping their sessionVersion. */
export async function resetUserSessions(
  env: Env,
  user: UserRecord,
): Promise<UserRecord> {
  const updated: UserRecord = { ...user, sessionVersion: crypto.randomUUID() };
  await env.USERS_KV.put(`user:${user.bufferId}`, JSON.stringify(updated));
  return updated;
}

export async function getUser(
  userId: string,
  env: Env,
): Promise<UserRecord | null> {
  const data = await env.USERS_KV.get(`user:${userId}`);
  return data ? (JSON.parse(data) as UserRecord) : null;
}

export async function putUser(env: Env, user: UserRecord): Promise<void> {
  await env.USERS_KV.put(`user:${user.bufferId}`, JSON.stringify(user));
}
