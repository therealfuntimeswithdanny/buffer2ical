var __defProp = Object.defineProperty;
var __name = (target, value) =>
  __defProp(target, "name", { value, configurable: true });

const SESSION_TTL = 86400 * 365 * 2; // 2 years

var index_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(env)
      });
    }

    if (path === "/dashboard") {
      return redirectToFrontend(env, "/dashboard");
    }

    if (path === "/auth/buffer") {
      return handleOAuthStart(env);
    }

    if (path === "/auth/callback") {
      return handleOAuthCallback(request, env);
    }

    if (path === "/feed") {
      return handleFeed(request, env);
    }

    let res;

    try {
      if (path === "/api/me" && method === "GET") {
        res = await handleMe(request, env);
      } else if (path === "/api/auth/apikey" && method === "POST") {
        res = await handleApiKeySignIn(request, env);
      } else if (path === "/api/auth/pending" && method === "GET") {
        res = await handlePendingSignIn(request, env);
      } else if (path === "/api/auth/organization" && method === "POST") {
        res = await handleOrganizationSignIn(request, env);
      } else if (path === "/api/refresh" && method === "POST") {
        res = await handleRefresh(request, env);
      } else if (path === "/api/account/refresh" && method === "POST") {
        res = await handleAccountRefresh(request, env);
      } else if (path === "/api/logout" && method === "POST") {
        res = await handleLogout(request, env);
      } else if (path === "/api/user" && method === "DELETE") {
        res = await handleDeleteUser(request, env);
      } else {
        res = json({ error: "Not Found" }, 404);
      }
    } catch (e) {
      console.error("Worker error:", e);
      res = json(
        { error: e?.message || "Internal server error" },
        500
      );
    }

    const headers = new Headers(res.headers);

    for (const [k, v] of Object.entries(corsHeaders(env))) {
      headers.set(k, v);
    }

    return new Response(res.body, {
      status: res.status,
      headers
    });
  },

  async scheduled(event, env, ctx) {
    const users = await env.USERS_KV.list({
      prefix: "user:"
    });

    for (const key of users.keys) {
      const userId = key.name.replace("user:", "");
      ctx.waitUntil(refreshUserFeed(userId, env));
    }
  }
};

// =========================================================
// OAuth
// =========================================================

async function handleOAuthStart(env) {
  const state = crypto.randomUUID();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  await env.SESSIONS_KV.put(
    `oauth:${state}`,
    JSON.stringify({
      codeVerifier,
      createdAt: Date.now()
    }),
    { expirationTtl: 600 }
  );

  const authUrl =
    "https://auth.buffer.com/auth?" +
    new URLSearchParams({
      client_id: env.BUFFER_CLIENT_ID,
      redirect_uri: `${env.API_URL}/auth/callback`,
      response_type: "code",
      scope: "posts:read account:read offline_access",
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256"
    });

  return Response.redirect(authUrl, 302);
}

__name(handleOAuthStart, "handleOAuthStart");

async function handleOAuthCallback(request, env) {
  const url = new URL(request.url);

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    return redirectToFrontend(
      env,
      `/?error=${encodeURIComponent(error)}`
    );
  }

  if (!code || !state) {
    return redirectToFrontend(
      env,
      "/?error=missing_oauth_parameters"
    );
  }

  const sessionData = await env.SESSIONS_KV.get(
    `oauth:${state}`
  );

  if (!sessionData) {
    return redirectToFrontend(
      env,
      "/?error=invalid_state"
    );
  }

  const { codeVerifier } = JSON.parse(sessionData);

  await env.SESSIONS_KV.delete(`oauth:${state}`);

  const tokenRes = await fetch(
    "https://auth.buffer.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        client_id: env.BUFFER_CLIENT_ID,
        client_secret: env.BUFFER_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: `${env.API_URL}/auth/callback`,
        code_verifier: codeVerifier
      })
    }
  );

  if (!tokenRes.ok) {
    console.error(
      "Token exchange failed:",
      await tokenRes.text()
    );

    return redirectToFrontend(
      env,
      "/?error=token_exchange_failed"
    );
  }

  const tokens = await tokenRes.json();

  if (!tokens.access_token) {
    return redirectToFrontend(
      env,
      "/?error=no_access_token"
    );
  }

  // Get account + organization
  const userRes = await fetch(
    "https://api.buffer.com",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        query: `{
          account {
            id
            email
            name
            organizations {
              id
              name
            }
          }
        }`
      })
    }
  );

  if (!userRes.ok) {
    console.error(
      "Buffer account request failed:",
      await userRes.text()
    );

    return redirectToFrontend(
      env,
      "/?error=buffer_account_request_failed"
    );
  }

  const userData = await userRes.json();

  if (userData.errors?.length) {
    console.error(
      "Buffer account GraphQL errors:",
      JSON.stringify(userData.errors)
    );

    return redirectToFrontend(
      env,
      "/?error=buffer_account_query_failed"
    );
  }

  const bufferUser = userData.data?.account || {};
  if (!bufferUser.id || !bufferUser.organizations?.length) {
    return redirectToFrontend(
      env,
      "/?error=no_buffer_organization"
    );
  }

  const pendingId = crypto.randomUUID();
  await env.SESSIONS_KV.put(
    `auth-pending:${pendingId}`,
    JSON.stringify({
      bufferUser,
      organizations: bufferUser.organizations,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || null
    }),
    { expirationTtl: 600 }
  );

  return redirectToFrontend(
    env,
    `/app/organization.html?pending=${encodeURIComponent(pendingId)}`
  );
}

__name(
  handleOAuthCallback,
  "handleOAuthCallback"
);

async function handleApiKeySignIn(request, env) {
  if (!originOk(request, env)) {
    return json({ error: "Forbidden" }, 403);
  }

  let body;
  try {
    body = await request.json();
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
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      query: `{
        account {
          id
          email
          name
          organizations {
            id
            name
          }
        }
      }`
    })
  });

  if (!accountResult.ok) {
    if (accountResult.status === 401) {
      return json({ error: "Buffer rejected that API key. Check it and try again." }, 401);
    }
    console.error("Buffer API key verification failed:", accountResult.status);
    return json({ error: "Could not verify the API key with Buffer. Please try again." }, 502);
  }

  const accountData = await accountResult.json();
  if (accountData.errors?.length || !accountData.data?.account?.id) {
    console.error("Buffer account query failed during API key sign-in.");
    return json({ error: "Could not verify the API key with Buffer. Please try again." }, 502);
  }

  const bufferUser = accountData.data.account;
  if (!bufferUser.organizations?.length) {
    return json({ error: "No Buffer organizations were found for this account." }, 400);
  }

  const pendingId = crypto.randomUUID();
  await env.SESSIONS_KV.put(
    `auth-pending:${pendingId}`,
    JSON.stringify({
      bufferUser,
      organizations: bufferUser.organizations,
      apiKey
    }),
    { expirationTtl: 600 }
  );

  return json({ pendingId });
}

__name(handleApiKeySignIn, "handleApiKeySignIn");

async function handlePendingSignIn(request, env) {
  if (!originOk(request, env)) {
    return json({ error: "Forbidden" }, 403);
  }

  const pendingId = new URL(request.url).searchParams.get("pending");
  if (!pendingId) {
    return json({ error: "Sign-in expired. Please start again." }, 400);
  }

  const pending = await env.SESSIONS_KV.get(`auth-pending:${pendingId}`, "json");
  if (!pending) {
    return json({ error: "Sign-in expired. Please start again." }, 404);
  }

  return json({
    organizations: pending.organizations.map(({ id, name }) => ({ id, name }))
  });
}

__name(handlePendingSignIn, "handlePendingSignIn");

async function handleOrganizationSignIn(request, env) {
  if (!originOk(request, env)) {
    return json({ error: "Forbidden" }, 403);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid request body." }, 400);
  }
  if (typeof body?.pendingId !== "string" || typeof body?.organizationId !== "string") {
    return json({ error: "Choose a Buffer organization to continue." }, 400);
  }

  const pendingKey = `auth-pending:${body.pendingId}`;
  const pending = await env.SESSIONS_KV.get(pendingKey, "json");
  if (!pending) {
    return json({ error: "Sign-in expired. Please start again." }, 404);
  }

  const organization = pending.organizations.find(
    item => item.id === body.organizationId
  );
  if (!organization) {
    return json({ error: "That organization is not available for this Buffer account." }, 403);
  }

  const userId = pending.bufferUser.id;
  const oldUser = await getUser(userId, env);
  const userRecord = {
    ...(oldUser || {}),
    bufferId: userId,
    organizationId: organization.id,
    organizationName: organization.name,
    email: pending.bufferUser.email || oldUser?.email,
    name:
      pending.bufferUser.name ||
      pending.bufferUser.email?.split("@")[0] ||
      oldUser?.name ||
      "User",
    accessToken:
      pending.accessToken ||
      oldUser?.accessToken ||
      pending.apiKey,
    apiKey: pending.apiKey || oldUser?.apiKey,
    refreshToken:
      pending.refreshToken ||
      oldUser?.refreshToken ||
      null,
    createdAt: oldUser?.createdAt || new Date().toISOString(),
    lastSync: oldUser?.lastSync || null
  };

  await env.USERS_KV.put(`user:${userId}`, JSON.stringify(userRecord));
  await env.SESSIONS_KV.delete(pendingKey);

  const sessionId = crypto.randomUUID();
  await env.SESSIONS_KV.put(`session:${sessionId}`, userId, {
    expirationTtl: SESSION_TTL
  });

  return json(
    { success: true },
    200,
    { "Set-Cookie": sessionCookie(sessionId) }
  );
}

__name(handleOrganizationSignIn, "handleOrganizationSignIn");

async function fetchBufferAccountProfile(accessToken) {
  const response = await fetch("https://api.buffer.com", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      query: `{
        account {
          email
          name
        }
      }`
    })
  });

  if (!response.ok) {
    throw new Error(`Buffer account HTTP error: ${response.status}`);
  }

  const data = await response.json();
  if (data.errors?.length) {
    console.error(
      "Buffer account GraphQL errors:",
      JSON.stringify(data.errors)
    );
    throw new Error(
      data.errors[0]?.message || "Buffer account query failed"
    );
  }

  if (!data.data?.account) {
    throw new Error("Buffer account data was not returned");
  }

  return data.data.account;
}

__name(fetchBufferAccountProfile, "fetchBufferAccountProfile");

// =========================================================
// PKCE
// =========================================================

function generateCodeVerifier() {
  const bytes = new Uint8Array(32);

  crypto.getRandomValues(bytes);

  return btoa(
    String.fromCharCode(...bytes)
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

__name(
  generateCodeVerifier,
  "generateCodeVerifier"
);

async function generateCodeChallenge(
  verifier
) {
  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(verifier)
    );

  return btoa(
    String.fromCharCode(
      ...new Uint8Array(digest)
    )
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

__name(
  generateCodeChallenge,
  "generateCodeChallenge"
);

// =========================================================
// API
// =========================================================

async function handleMe(request, env) {
  const userId =
    await getUserIdFromSession(
      request,
      env
    );

  if (!userId) {
    return json(
      { error: "Unauthorized" },
      401
    );
  }

  const user =
    await getUser(
      userId,
      env
    );

  if (!user) {
    return json(
      { error: "Unauthorized" },
      401
    );
  }

  // Repair older users that don't have an organizationId
  if (!user.organizationId) {
    try {
      await ensureOrganization(
        userId,
        user,
        env
      );
    } catch (e) {
      console.error(
        "Organization repair failed:",
        e
      );
    }
  }

  const stats =
    await getUserStats(
      userId,
      env
    );

  // Renew session for another two years
  const sessionId =
    getSessionId(request);

  const extraHeaders = {};

  if (sessionId) {
    await env.SESSIONS_KV.put(
      `session:${sessionId}`,
      userId,
      {
        expirationTtl:
          SESSION_TTL
      }
    );

    extraHeaders["Set-Cookie"] =
      sessionCookie(sessionId);
  }

  return json(
    {
      user: {
        name: user.name,
        email: user.email,
        lastSync: user.lastSync
      },

      feedUrl:
        `${env.API_URL}/feed?user=${userId}`,

      stats
    },
    200,
    extraHeaders
  );
}

__name(handleMe, "handleMe");

async function handleAccountRefresh(request, env) {
  if (!originOk(request, env)) {
    return json({ error: "Forbidden" }, 403);
  }

  const userId = await getUserIdFromSession(request, env);
  if (!userId) {
    return json({ error: "Unauthorized" }, 401);
  }

  const user = await getUser(userId, env);
  if (!user) {
    return json({ error: "Unauthorized" }, 401);
  }

  try {
    const account = await fetchBufferAccountProfile(user.accessToken);
    const updatedUser = {
      ...user,
      email: account.email ?? user.email,
      name:
        account.name ||
        account.email?.split("@")[0] ||
        user.name
    };

    await env.USERS_KV.put(
      `user:${userId}`,
      JSON.stringify(updatedUser)
    );

    return json({
      success: true,
      user: {
        name: updatedUser.name,
        email: updatedUser.email
      }
    });
  } catch (e) {
    console.error("Buffer account refresh failed:", e);
    return json(
      {
        success: false,
        error: e.message || "Unable to refresh account"
      },
      502
    );
  }
}

__name(handleAccountRefresh, "handleAccountRefresh");

async function handleRefresh(
  request,
  env
) {
  if (!originOk(request, env)) {
    return json(
      { error: "Forbidden" },
      403
    );
  }

  const userId =
    await getUserIdFromSession(
      request,
      env
    );

  if (!userId) {
    return json(
      { error: "Unauthorized" },
      401
    );
  }

  try {
    const result =
      await refreshUserFeed(
        userId,
        env
      );

    return json({
      success: true,
      count: result.events.length
    });
  } catch (e) {
    console.error(
      "Refresh failed:",
      e
    );

    return json(
      {
        success: false,
        error: e.message
      },
      500
    );
  }
}

__name(
  handleRefresh,
  "handleRefresh"
);

async function handleLogout(
  request,
  env
) {
  if (!originOk(request, env)) {
    return json(
      { error: "Forbidden" },
      403
    );
  }

  const sessionId =
    getSessionId(request);

  if (sessionId) {
    await env.SESSIONS_KV.delete(
      `session:${sessionId}`
    );
  }

  return json(
    { success: true },
    200,
    {
      "Set-Cookie":
        clearCookie()
    }
  );
}

__name(
  handleLogout,
  "handleLogout"
);

async function handleDeleteUser(
  request,
  env
) {
  if (!originOk(request, env)) {
    return json(
      { error: "Forbidden" },
      403
    );
  }

  const userId =
    await getUserIdFromSession(
      request,
      env
    );

  if (!userId) {
    return json(
      { error: "Unauthorized" },
      401
    );
  }

  const sessionId =
    getSessionId(request);

  await Promise.all([
    env.USERS_KV.delete(
      `user:${userId}`
    ),
    env.USERS_KV.delete(
      `feed:${userId}`
    ),
    env.USERS_KV.delete(
      `stats:${userId}`
    ),
    sessionId
      ? env.SESSIONS_KV.delete(
          `session:${sessionId}`
        )
      : null
  ]);

  return json(
    { success: true },
    200,
    {
      "Set-Cookie":
        clearCookie()
    }
  );
}

__name(
  handleDeleteUser,
  "handleDeleteUser"
);

// =========================================================
// FEED
// =========================================================

async function handleFeed(
  request,
  env
) {
  const url =
    new URL(request.url);

  const userId =
    url.searchParams.get(
      "user"
    );

  if (!userId) {
    return new Response(
      "Missing user parameter",
      { status: 400 }
    );
  }

  const ics =
    await env.USERS_KV.get(
      `feed:${userId}`
    );

  if (ics) {
    return new Response(
      ics,
      {
        headers: {
          "Content-Type":
            "text/calendar; charset=utf-8",

          "Content-Disposition":
            'attachment; filename="buffer.ics"',

          "Cache-Control":
            "public, max-age=300"
        }
      }
    );
  }

  try {
    await refreshUserFeed(
      userId,
      env
    );

    const fresh =
      await env.USERS_KV.get(
        `feed:${userId}`
      );

    if (fresh) {
      return new Response(
        fresh,
        {
          headers: {
            "Content-Type":
              "text/calendar; charset=utf-8"
          }
        }
      );
    }
  } catch (e) {
    console.error(
      `Feed failed for ${userId}:`,
      e
    );
  }

  return new Response(
    generateEmptyICS(),
    {
      headers: {
        "Content-Type":
          "text/calendar; charset=utf-8"
      }
    }
  );
}

__name(
  handleFeed,
  "handleFeed"
);

// =========================================================
// BUFFER SYNC
// =========================================================

async function refreshUserFeed(
  userId,
  env
) {
  let user =
    await getUser(
      userId,
      env
    );

  if (!user) {
    throw new Error(
      "User not found"
    );
  }

  user =
    await ensureOrganization(
      userId,
      user,
      env
    );

  const organizationId =
    user.organizationId;

  // ---------------------------------------------------------
  // Get channels
  // ---------------------------------------------------------

  const channelsRes =
    await fetch(
      "https://api.buffer.com",
      {
        method: "POST",

        headers: {
          Authorization:
            `Bearer ${user.accessToken}`,

          "Content-Type":
            "application/json"
        },

        body:
          JSON.stringify({
            query: `
              query GetChannels {
                channels(
                  input: {
                    organizationId: "${organizationId}"
                  }
                ) {
                  id
                  name
                  service
                }
              }
            `
          })
      }
    );

  if (!channelsRes.ok) {
    if (
      channelsRes.status ===
      401
    ) {
      throw new Error(
        "Buffer auth expired"
      );
    }

    throw new Error(
      `Buffer channels HTTP error: ${channelsRes.status}`
    );
  }

  const channelsData =
    await channelsRes.json();

  if (
    channelsData.errors?.length
  ) {
    console.error(
      "Buffer channels GraphQL errors:",
      JSON.stringify(
        channelsData.errors
      )
    );

    throw new Error(
      channelsData.errors[0]
        ?.message ||
        "Buffer channels query failed"
    );
  }

  const channels =
    channelsData.data
      ?.channels ||
    [];

  // ---------------------------------------------------------
  // Get scheduled posts
  // ---------------------------------------------------------

  const events = [];
  let after = null;

  do {
    const pagination =
      after
        ? `
            first: 100
            after: ${JSON.stringify(after)}
          `
        : `
            first: 100
          `;

    const postsRes =
      await fetch(
        "https://api.buffer.com",
        {
          method: "POST",

          headers: {
            Authorization:
              `Bearer ${user.accessToken}`,

            "Content-Type":
              "application/json"
          },

          body:
            JSON.stringify({
              query: `
                query GetScheduledPosts {
                  posts(
                    ${pagination}
                    input: {
                      organizationId: "${organizationId}"

                      sort: [
                        {
                          field: dueAt
                          direction: asc
                        }

                        {
                          field: createdAt
                          direction: desc
                        }
                      ]

                      filter: {
                        status: [scheduled]
                      }
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
                }
              `
            })
        }
      );

    if (!postsRes.ok) {
      if (
        postsRes.status ===
        401
      ) {
        throw new Error(
          "Buffer auth expired"
        );
      }

      throw new Error(
        `Buffer posts HTTP error: ${postsRes.status}`
      );
    }

    const postsData =
      await postsRes.json();

    if (
      postsData.errors?.length
    ) {
      console.error(
        "Buffer posts GraphQL errors:",
        JSON.stringify(
          postsData.errors
        )
      );

      throw new Error(
        postsData.errors[0]
          ?.message ||
          "Buffer posts query failed"
      );
    }

    const posts =
      postsData.data
        ?.posts
        ?.edges
        ?.map(
          edge => edge.node
        )
        .filter(Boolean) ||
      [];

    for (const post of posts) {
      const channel =
        channels.find(
          c =>
            c.id ===
            post.channelId
        );

      events.push({
        id:
          post.id,

        start:
          post.dueAt ||
          post.createdAt ||
          new Date().toISOString(),

        text:
          post.text || "",

        channel:
          channel?.service ||
          "unknown",

        profileName:
          channel?.name ||
          "Unknown profile",

        status:
          "scheduled",

        url:
          post.externalLink ||
          ""
      });
    }

    const pageInfo =
      postsData.data
        ?.posts
        ?.pageInfo;

    if (
      pageInfo?.hasNextPage &&
      pageInfo?.endCursor
    ) {
      after =
        pageInfo.endCursor;
    } else {
      after = null;
    }
  } while (after);

  // ---------------------------------------------------------
  // Stats
  // ---------------------------------------------------------

  const now =
    new Date().toISOString();

  const stats = {
    totalEvents:
      events.length,

    scheduled:
      events.length,

    drafts:
      0,

    needsApproval:
      0,

    profiles:
      channels.length,

    recentPosts:
      [...events]
        .sort(
          (a, b) =>
            new Date(b.start) -
            new Date(a.start)
        )
        .slice(0, 5)
        .map(
          e => ({
            text:
              e.text,

            status:
              e.status,

            channel:
              e.channel,

            profileName:
              e.profileName,

            start:
              e.start
          })
        ),

    isStale:
      false,

    lastSync:
      now
  };

  const ics =
    generateICS(
      events,
      userId
    );

  await Promise.all([
    env.USERS_KV.put(
      `feed:${userId}`,
      ics,
      {
        expirationTtl:
          86400
      }
    ),

    env.USERS_KV.put(
      `stats:${userId}`,
      JSON.stringify(stats),
      {
        expirationTtl:
          86400
      }
    ),

    env.USERS_KV.put(
      `user:${userId}`,
      JSON.stringify({
        ...user,
        lastSync:
          now
      })
    )
  ]);

  console.log(
    `Buffer sync complete: ${events.length} scheduled posts`
  );

  return {
    events,
    profiles:
      channels
  };
}

__name(
  refreshUserFeed,
  "refreshUserFeed"
);

// =========================================================
// ORGANIZATION REPAIR
// =========================================================

async function ensureOrganization(
  userId,
  user,
  env
) {
  if (
    user.organizationId
  ) {
    return user;
  }

  const accountRes =
    await fetch(
      "https://api.buffer.com",
      {
        method: "POST",

        headers: {
          Authorization:
            `Bearer ${user.accessToken}`,

          "Content-Type":
            "application/json"
        },

        body:
          JSON.stringify({
            query: `
              query GetOrganizations {
                account {
                  organizations {
                    id
                    name
                  }
                }
              }
            `
          })
      }
    );

  if (!accountRes.ok) {
    if (
      accountRes.status ===
      401
    ) {
      throw new Error(
        "Buffer auth expired"
      );
    }

    throw new Error(
      `Buffer organization HTTP error: ${accountRes.status}`
    );
  }

  const accountData =
    await accountRes.json();

  if (
    accountData.errors?.length
  ) {
    throw new Error(
      accountData.errors[0]
        ?.message ||
        "Buffer organization query failed"
    );
  }

  const organization =
    accountData.data
      ?.account
      ?.organizations?.[0];

  if (!organization?.id) {
    throw new Error(
      "No Buffer organization found"
    );
  }

  const updatedUser = {
    ...user,

    organizationId:
      organization.id,

    organizationName:
      organization.name
  };

  await env.USERS_KV.put(
    `user:${userId}`,
    JSON.stringify(
      updatedUser
    )
  );

  return updatedUser;
}

__name(
  ensureOrganization,
  "ensureOrganization"
);

// =========================================================
// HELPERS
// =========================================================

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin":
      env.FRONTEND_URL,

    "Access-Control-Allow-Credentials":
      "true",

    "Access-Control-Allow-Methods":
      "GET, POST, DELETE, OPTIONS",

    "Access-Control-Allow-Headers":
      "Content-Type",

    "Vary":
      "Origin"
  };
}

__name(
  corsHeaders,
  "corsHeaders"
);

function originOk(
  request,
  env
) {
  return (
    request.headers.get(
      "Origin"
    ) ===
    env.FRONTEND_URL
  );
}

__name(
  originOk,
  "originOk"
);

function json(
  data,
  status = 200,
  extraHeaders = {}
) {
  return new Response(
    JSON.stringify(data),
    {
      status,

      headers: {
        "Content-Type":
          "application/json",

        ...extraHeaders
      }
    }
  );
}

__name(
  json,
  "json"
);

function redirectToFrontend(
  env,
  path
) {
  return Response.redirect(
    `${env.FRONTEND_URL}${path}`,
    302
  );
}

__name(
  redirectToFrontend,
  "redirectToFrontend"
);

function sessionCookie(
  sessionId
) {
  return [
    `session=${sessionId}`,
    "HttpOnly",
    "Secure",
    "SameSite=None",
    `Max-Age=${SESSION_TTL}`,
    "Path=/"
  ].join("; ");
}

__name(
  sessionCookie,
  "sessionCookie"
);

function clearCookie() {
  return [
    "session=",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    "Max-Age=0",
    "Path=/"
  ].join("; ");
}

__name(
  clearCookie,
  "clearCookie"
);

function getSessionId(
  request
) {
  const cookie =
    request.headers.get(
      "Cookie"
    );

  if (!cookie) {
    return null;
  }

  const match =
    cookie.match(
      /(?:^|;\s*)session=([^;]+)/
    );

  return match
    ? match[1]
    : null;
}

__name(
  getSessionId,
  "getSessionId"
);

async function getUserIdFromSession(
  request,
  env
) {
  const sessionId =
    getSessionId(request);

  if (!sessionId) {
    return null;
  }

  return await env.SESSIONS_KV.get(
    `session:${sessionId}`
  );
}

__name(
  getUserIdFromSession,
  "getUserIdFromSession"
);

async function getUser(
  userId,
  env
) {
  const data =
    await env.USERS_KV.get(
      `user:${userId}`
    );

  return data
    ? JSON.parse(data)
    : null;
}

__name(
  getUser,
  "getUser"
);

async function getUserStats(
  userId,
  env
) {
  const data =
    await env.USERS_KV.get(
      `stats:${userId}`
    );

  if (!data) {
    return {
      totalEvents: 0,
      scheduled: 0,
      drafts: 0,
      needsApproval: 0,
      profiles: 0,
      recentPosts: [],
      isStale: true
    };
  }

  const stats =
    JSON.parse(data);

  stats.isStale =
    Date.now() -
      new Date(
        stats.lastSync
      ).getTime() >
    5 * 60 * 1000;

  return stats;
}

__name(
  getUserStats,
  "getUserStats"
);

// =========================================================
// ICS
// =========================================================

function generateICS(
  events,
  userId
) {
  const now =
    new Date()
      .toISOString()
      .replace(
        /[-:]/g,
        ""
      )
      .split(".")[0] +
    "Z";

  let ics = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Buffer2iCal//EN
CALSCALE:GREGORIAN
METHOD:PUBLISH
X-WR-CALNAME:Buffer Scheduled Posts
X-WR-TIMEZONE:UTC
`;

  for (const e of events) {
    const start =
      new Date(e.start);

    const dtStart =
      start
        .toISOString()
        .replace(
          /[-:]/g,
          ""
        )
        .split(".")[0] +
      "Z";

    const dtEnd =
      new Date(
        start.getTime() +
          30 * 60000
      )
        .toISOString()
        .replace(
          /[-:]/g,
          ""
        )
        .split(".")[0] +
      "Z";

const preview = e.text
  .replace(/\s+/g, " ")
  .trim();

const summary =
  `${e.channel} - ${
    preview.length > 30
      ? preview.substring(0, 30) + "..."
      : preview
  }`
    .replace(/[,;\\]/g, "\\$&");
    const desc = [
      `Status: SCHEDULED`,
      `Channel: ${e.channel}`,
      `Profile: ${e.profileName}`,
      e.url
        ? `URL: ${e.url}`
        : "",
      "",
      e.text
    ]
      .join("\\n")
      .replace(
        /[,;\\]/g,
        "\\$&"
      );

    ics += `BEGIN:VEVENT
UID:buffer-${e.id}-${userId}@buffer2ical
DTSTAMP:${now}
DTSTART:${dtStart}
DTEND:${dtEnd}
SUMMARY:${summary}
DESCRIPTION:${desc}
STATUS:CONFIRMED
TRANSP:OPAQUE
CATEGORIES:SCHEDULED,${e.channel.toUpperCase()}
END:VEVENT
`;
  }

  return (
    ics +
    "END:VCALENDAR"
  );
}

__name(
  generateICS,
  "generateICS"
);

function generateEmptyICS() {
  return `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Buffer2iCal//EN
CALSCALE:GREGORIAN
METHOD:PUBLISH
X-WR-CALNAME:Buffer Scheduled Posts
END:VCALENDAR`;
}

__name(
  generateEmptyICS,
  "generateEmptyICS"
);

export {
  index_default as default
};