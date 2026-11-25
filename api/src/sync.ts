import type {
  BufferOrganization,
  CronStatus,
  Env,
  FeedEvent,
  UserRecord,
  UserStats,
} from "./types";
import { BufferAuthError, fetchBufferForUser, readGraphQL, recordAuthError } from "./buffer";
import { getUser, putUser } from "./session";
import { generateICS } from "./ics";

const FEED_TTL_SECONDS = 86400;
const STATS_TTL_SECONDS = 86400;
const SYNC_CONCURRENCY = 5;
/** Mark stats stale when the last successful sync is older than the cron interval. */
const STALE_AFTER_MS = 5 * 60 * 1000;

interface BufferChannel {
  id: string;
  name?: string;
  service?: string;
}

interface BufferPost {
  id: string;
  text?: string;
  status?: string;
  dueAt?: string;
  channelId?: string;
  createdAt?: string;
  externalLink?: string;
}

interface PostsPage {
  posts?: {
    edges?: { node?: BufferPost | null }[];
    pageInfo?: { hasNextPage?: boolean; endCursor?: string | null };
  };
}

export async function refreshUserFeed(
  userId: string,
  env: Env,
): Promise<{ events: FeedEvent[]; stats: UserStats; profiles: BufferChannel[] }> {
  let user = await getUser(userId, env);
  if (!user) throw new Error("User not found");

  user = await ensureOrganization(userId, user, env);
  const organizationId = user.organizationId!;

  // ---------------------------------------------------------
  // Channels
  // ---------------------------------------------------------
  const channelsRes = await fetchBufferForUser(
    userId,
    user,
    env,
    `query GetChannels {
      channels(input: { organizationId: ${JSON.stringify(organizationId)} }) {
        id
        name
        service
      }
    }`,
  );
  const channelsData = await readGraphQL<{ channels?: BufferChannel[] }>(
    channelsRes,
    "channels",
  );
  const channels = channelsData.channels ?? [];

  // ---------------------------------------------------------
  // Scheduled posts (paginated)
  // ---------------------------------------------------------
  const events: FeedEvent[] = [];
  let after: string | null = null;

  do {
    const pagination = after
      ? `first: 100\n            after: ${JSON.stringify(after)}`
      : `first: 100`;

    const postsRes = await fetchBufferForUser(
      userId,
      user,
      env,
      `query GetScheduledPosts {
        posts(
          ${pagination}
          input: {
            organizationId: ${JSON.stringify(organizationId)}
            sort: [
              { field: dueAt, direction: asc }
              { field: createdAt, direction: desc }
            ]
            filter: { status: [scheduled] }
          }
        ) {
          edges {
            node {
              id
              text
              status
              dueAt
              channelId
              createdAt
              externalLink
            }
          }
          pageInfo {
            hasNextPage
            endCursor
          }
        }
      }`,
    );

    const postsData = await readGraphQL<PostsPage>(postsRes, "posts");
    const posts =
      postsData.posts?.edges
        ?.map(edge => edge.node)
        .filter((node): node is BufferPost => Boolean(node)) ?? [];

    for (const post of posts) {
      const channel = channels.find(c => c.id === post.channelId);
      events.push({
        id: post.id,
        start: post.dueAt || post.createdAt || new Date().toISOString(),
        text: post.text || "",
        channel: channel?.service || "unknown",
        profileName: channel?.name || "Unknown profile",
        status: "scheduled",
        url: post.externalLink || "",
      });
    }

    const pageInfo = postsData.posts?.pageInfo;
    after = pageInfo?.hasNextPage && pageInfo?.endCursor ? pageInfo.endCursor : null;
  } while (after);

  // ---------------------------------------------------------
  // Stats + feed persistence
  // ---------------------------------------------------------
  const now = new Date().toISOString();
  const stats: UserStats = {
    totalEvents: events.length,
    scheduled: events.length,
    drafts: 0,
    needsApproval: 0,
    profiles: channels.length,
    recentPosts: [...events]
      .sort((a, b) => new Date(b.start).getTime() - new Date(a.start).getTime())
      .slice(0, 5)
      .map(e => ({
        text: e.text,
        status: e.status,
        channel: e.channel,
        profileName: e.profileName,
        start: e.start,
      })),
    isStale: false,
    lastSync: now,
  };

  const ics = generateICS(events, userId);

  // A successful sync means Buffer auth is healthy — clear any stale flag.
  const syncedUser: UserRecord = { ...user, lastSync: now, lastAuthError: null };

  await Promise.all([
    env.USERS_KV.put(`feed:${userId}`, ics, { expirationTtl: FEED_TTL_SECONDS }),
    env.USERS_KV.put(`stats:${userId}`, JSON.stringify(stats), {
      expirationTtl: STATS_TTL_SECONDS,
    }),
    putUser(env, syncedUser),
  ]);

  console.log(`Buffer sync complete for ${userId}: ${events.length} scheduled posts`);
  return { events, stats, profiles: channels };
}

export async function ensureOrganization(
  userId: string,
  user: UserRecord,
  env: Env,
): Promise<UserRecord> {
  if (user.organizationId) return user;

  const res = await fetchBufferForUser(
    userId,
    user,
    env,
    `query GetOrganizations {
      account { organizations { id name } }
    }`,
  );
  const data = await readGraphQL<{
    account?: { organizations?: BufferOrganization[] };
  }>(res, "organization");

  const organization = data.account?.organizations?.[0];
  if (!organization?.id) throw new Error("No Buffer organization found");

  const updated: UserRecord = {
    ...user,
    organizationId: organization.id,
    organizationName: organization.name,
  };
  await putUser(env, updated);
  return updated;
}

export async function getUserStats(userId: string, env: Env): Promise<UserStats> {
  const data = await env.USERS_KV.get(`stats:${userId}`);
  if (!data) {
    return {
      totalEvents: 0,
      scheduled: 0,
      drafts: 0,
      needsApproval: 0,
      profiles: 0,
      recentPosts: [],
      isStale: true,
    };
  }
  const stats = JSON.parse(data) as UserStats;
  stats.isStale =
    !stats.lastSync || Date.now() - new Date(stats.lastSync).getTime() > STALE_AFTER_MS;
  return stats;
}

export async function getAllUsers(env: Env): Promise<UserRecord[]> {
  const users: UserRecord[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.USERS_KV.list({ prefix: "user:", cursor });
    const records = await Promise.all(
      page.keys.map(async key => {
        const raw = await env.USERS_KV.get(key.name);
        if (!raw) return null;
        try {
          return JSON.parse(raw) as UserRecord;
        } catch {
          return null;
        }
      }),
    );
    users.push(...records.filter((r): r is UserRecord => Boolean(r)));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return users;
}

/**
 * Cron entrypoint: sync every user's feed with bounded concurrency, and
 * record a status row at `system:cron:last` for the admin overview.
 */
export async function runScheduledSync(env: Env): Promise<void> {
  const status: CronStatus = {
    state: "running",
    startedAt: new Date().toISOString(),
    finishedAt: null,
    totalUsers: 0,
    succeeded: 0,
    failed: 0,
  };
  await env.USERS_KV.put("system:cron:last", JSON.stringify(status));

  try {
    const userIds: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await env.USERS_KV.list({ prefix: "user:", cursor });
      userIds.push(...page.keys.map(key => key.name.slice(5)));
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    status.totalUsers = userIds.length;

    let next = 0;
    const workers = Array.from(
      { length: Math.min(SYNC_CONCURRENCY, userIds.length) },
      async () => {
        while (next < userIds.length) {
          const userId = userIds[next++]!;
          try {
            await refreshUserFeed(userId, env);
            status.succeeded++;
          } catch (error) {
            status.failed++;
            status.lastError = String(
              (error as Error)?.message || error,
            ).slice(0, 200);
            if (error instanceof BufferAuthError) {
              await recordAuthError(env, userId, error.message);
            }
            console.error(`Scheduled sync failed for ${userId}:`, error);
          }
        }
      },
    );
    await Promise.all(workers);

    status.state = status.failed ? "complete_with_errors" : "complete";
    status.finishedAt = new Date().toISOString();
    await env.USERS_KV.put("system:cron:last", JSON.stringify(status));
    console.log("Scheduled sync complete:", JSON.stringify(status));
  } catch (error) {
    status.state = "failed";
    status.finishedAt = new Date().toISOString();
    status.error = String((error as Error)?.message || error).slice(0, 300);
    await env.USERS_KV.put("system:cron:last", JSON.stringify(status));
    throw error;
  }
}
