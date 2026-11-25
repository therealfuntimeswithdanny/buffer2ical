export interface Env {
  USERS_KV: KVNamespace;
  SESSIONS_KV: KVNamespace;
  ASSETS: Fetcher;
  API_URL: string;
  FRONTEND_URL: string;
  BUFFER_CLIENT_ID: string;
  BUFFER_CLIENT_SECRET: string;
  /** Optional override; falls back to the built-in owner ID. */
  ADMIN_BUFFER_ID?: string;
}

export type AuthMode = "oauth" | "apiKey";

export interface BufferOrganization {
  id: string;
  name: string;
}

export interface BufferAccount {
  id: string;
  email?: string;
  name?: string;
  organizations?: BufferOrganization[];
}

/** Persisted at `user:{userId}` in USERS_KV. */
export interface UserRecord {
  bufferId: string;
  organizationId?: string;
  organizationName?: string;
  email?: string;
  name: string;
  authMode: AuthMode;
  accessToken?: string;
  apiKey?: string;
  refreshToken?: string | null;
  /** Epoch ms when `accessToken` expires; null when unknown/non-expiring. */
  accessTokenExpiresAt?: number | null;
  /** Bumped to invalidate every issued session. */
  sessionVersion: string;
  /** Last Buffer auth failure observed during sync, for surfacing "reconnect" UX. */
  lastAuthError?: string | null;
  createdAt: string;
  lastSync?: string | null;
}

/** Persisted at `session:{sessionId}` in SESSIONS_KV. */
export interface SessionRecord {
  userId: string;
  version: string;
  /** Last time the rolling TTL was extended (epoch ms). */
  touchedAt: number;
}

/** Persisted at `auth-pending:{id}` (10 min TTL) between sign-in and org pick. */
export interface PendingAuth {
  bufferUser: BufferAccount;
  organizations: BufferOrganization[];
  accessToken?: string;
  refreshToken?: string | null;
  accessTokenExpiresAt?: number | null;
  apiKey?: string;
}

export interface FeedEvent {
  id: string;
  start: string;
  text: string;
  channel: string;
  profileName: string;
  status: string;
  url: string;
}

export interface RecentPost {
  text: string;
  status: string;
  channel: string;
  profileName: string;
  start: string;
}

export interface UserStats {
  totalEvents: number;
  scheduled: number;
  drafts: number;
  needsApproval: number;
  profiles: number;
  recentPosts: RecentPost[];
  isStale: boolean;
  lastSync?: string;
}

export interface CronStatus {
  state: "running" | "complete" | "complete_with_errors" | "failed";
  startedAt: string;
  finishedAt: string | null;
  totalUsers: number;
  succeeded: number;
  failed: number;
  lastError?: string;
  error?: string;
}
