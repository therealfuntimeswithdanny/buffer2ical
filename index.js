export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    // Browser navigations (no CORS needed)
    if (path === '/auth/buffer') return handleOAuthStart(env);
    if (path === '/auth/callback') return handleOAuthCallback(request, env);

    // Calendar apps fetch this (no CORS needed)
    if (path === '/feed') return handleFeed(request, env);

    // JSON API for the frontend
    let res;
    try {
      if (path === '/api/me' && method === 'GET') res = await handleMe(request, env);
      else if (path === '/api/refresh' && method === 'POST') res = await handleRefresh(request, env);
      else if (path === '/api/logout' && method === 'POST') res = await handleLogout(request, env);
      else if (path === '/api/user' && method === 'DELETE') res = await handleDeleteUser(request, env);
      else res = json({ error: 'Not Found' }, 404);
    } catch (e) {
      res = json({ error: e.message }, 500);
    }

    const headers = new Headers(res.headers);
    for (const [k, v] of Object.entries(corsHeaders(env))) headers.set(k, v);
    return new Response(res.body, { status: res.status, headers });
  },

  async scheduled(event, env, ctx) {
    const users = await env.USERS_KV.list({ prefix: 'user:' });
    for (const key of users.keys) {
      const userId = key.name.replace('user:', '');
      ctx.waitUntil(refreshUserFeed(userId, env));
    }
  }
};

// ============ OAuth ============

async function handleOAuthStart(env) {
  const state = crypto.randomUUID();
  await env.SESSIONS_KV.put(`state:${state}`, '1', { expirationTtl: 300 });

  const authUrl = 'https://buffer.com/oauth2/authorize?' + new URLSearchParams({
    client_id: env.BUFFER_CLIENT_ID,
    redirect_uri: `${env.API_URL}/auth/callback`,
    response_type: 'code',
    state
  });

  return Response.redirect(authUrl, 302);
}

async function handleOAuthCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (error) return redirectToFrontend(env, `/?error=${encodeURIComponent(error)}`);

  const validState = state && await env.SESSIONS_KV.get(`state:${state}`);
  if (!validState) return redirectToFrontend(env, '/?error=invalid_state');
  await env.SESSIONS_KV.delete(`state:${state}`);

  const tokenRes = await fetch('https://api.bufferapp.com/1/oauth2/token.json', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.BUFFER_CLIENT_ID,
      client_secret: env.BUFFER_CLIENT_SECRET,
      redirect_uri: `${env.API_URL}/auth/callback`,
      code,
      grant_type: 'authorization_code'
    })
  });

  if (!tokenRes.ok) return redirectToFrontend(env, '/?error=token_exchange_failed');

  const tokens = await tokenRes.json();

  const userRes = await fetch(`https://api.bufferapp.com/1/user.json?access_token=${tokens.access_token}`);
  const bufferUser = await userRes.json();

  const userId = bufferUser.id || crypto.randomUUID();

  const userData = {
    bufferId: bufferUser.id,
    email: bufferUser.email,
    name: bufferUser.name || bufferUser.email?.split('@')[0] || 'User',
    accessToken: tokens.access_token,
    createdAt: new Date().toISOString(),
    lastSync: null
  };

  await env.USERS_KV.put(`user:${userId}`, JSON.stringify(userData));

  const sessionId = crypto.randomUUID();
  await env.SESSIONS_KV.put(`session:${sessionId}`, userId, { expirationTtl: 86400 * 30 });

  return new Response(null, {
    status: 302,
    headers: {
      'Location': `${env.FRONTEND_URL}/dashboard`,
      'Set-Cookie': `session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000; Path=/`
    }
  });
}

// ============ API ============

async function handleMe(request, env) {
  const userId = await getUserIdFromSession(request, env);
  if (!userId) return json({ error: 'Unauthorized' }, 401);

  const user = await getUser(userId, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  const stats = await getUserStats(userId, env);

  return json({
    user: { name: user.name, email: user.email, lastSync: user.lastSync },
    feedUrl: `${env.API_URL}/feed?user=${userId}`,
    stats
  });
}

async function handleRefresh(request, env) {
  if (!originOk(request, env)) return json({ error: 'Forbidden' }, 403);
  const userId = await getUserIdFromSession(request, env);
  if (!userId) return json({ error: 'Unauthorized' }, 401);

  try {
    await refreshUserFeed(userId, env);
    return json({ success: true });
  } catch (e) {
    return json({ success: false, error: e.message }, 500);
  }
}

async function handleLogout(request, env) {
  if (!originOk(request, env)) return json({ error: 'Forbidden' }, 403);
  const sessionId = getSessionId(request);
  if (sessionId) await env.SESSIONS_KV.delete(`session:${sessionId}`);

  return json({ success: true }, 200, { 'Set-Cookie': clearCookie() });
}

async function handleDeleteUser(request, env) {
  if (!originOk(request, env)) return json({ error: 'Forbidden' }, 403);
  const userId = await getUserIdFromSession(request, env);
  if (!userId) return json({ error: 'Unauthorized' }, 401);

  const sessionId = getSessionId(request);

  await Promise.all([
    env.USERS_KV.delete(`user:${userId}`),
    env.USERS_KV.delete(`feed:${userId}`),
    env.USERS_KV.delete(`stats:${userId}`),
    sessionId ? env.SESSIONS_KV.delete(`session:${sessionId}`) : null
  ]);

  return json({ success: true }, 200, { 'Set-Cookie': clearCookie() });
}

async function handleFeed(request, env) {
  const url = new URL(request.url);
  const userId = url.searchParams.get('user');

  if (!userId) return new Response('Missing user parameter', { status: 400 });

  const ics = await env.USERS_KV.get(`feed:${userId}`);

  if (ics) {
    return new Response(ics, {
      headers: {
        'Content-Type': 'text/calendar; charset=utf-8',
        'Content-Disposition': 'attachment; filename="buffer.ics"',
        'Cache-Control': 'public, max-age=300'
      }
    });
  }

  try {
    await refreshUserFeed(userId, env);
    const fresh = await env.USERS_KV.get(`feed:${userId}`);
    if (fresh) {
      return new Response(fresh, {
        headers: { 'Content-Type': 'text/calendar; charset=utf-8' }
      });
    }
  } catch (e) {
    console.error(`Feed failed for ${userId}:`, e);
  }

  return new Response(generateEmptyICS(), {
    headers: { 'Content-Type': 'text/calendar; charset=utf-8' }
  });
}

// ============ Core ============

async function refreshUserFeed(userId, env) {
  const user = await getUser(userId, env);
  if (!user) throw new Error('User not found');

  const profilesRes = await fetch(
    `https://api.buffer.com/1/profiles.json?access_token=${user.accessToken}`
  );

  if (!profilesRes.ok) {
    if (profilesRes.status === 401) throw new Error('Buffer auth expired');
    throw new Error(`Buffer API error: ${profilesRes.status}`);
  }

  const profiles = await profilesRes.json();
  const events = [];

  for (const profile of profiles) {
    const [pendingRes, draftsRes] = await Promise.all([
      fetch(`https://api.buffer.com/1/profiles/${profile.id}/updates/pending.json?access_token=${user.accessToken}`),
      fetch(`https://api.buffer.com/1/profiles/${profile.id}/updates/drafts.json?access_token=${user.accessToken}`)
    ]);

    if (pendingRes.ok) {
      const pending = await pendingRes.json();
      for (const u of pending) {
        if (u.due_at) events.push(parseUpdate(u, profile, 'scheduled'));
      }
    }

    if (draftsRes.ok) {
      const drafts = await draftsRes.json();
      for (const u of drafts) {
        const date = u.due_at || u.created_at;
        if (date) events.push(parseUpdate(u, profile, 'draft', date));
      }
    }
  }

  const ics = generateICS(events, userId);

  const stats = {
    totalEvents: events.length,
    scheduled: events.filter(e => e.status === 'scheduled').length,
    drafts: events.filter(e => e.status === 'draft').length,
    profiles: profiles.length,
    recentPosts: events
      .sort((a, b) => new Date(b.start) - new Date(a.start))
      .slice(0, 5)
      .map(e => ({ text: e.text, status: e.status })),
    isStale: false,
    lastSync: new Date().toISOString()
  };

  await Promise.all([
    env.USERS_KV.put(`feed:${userId}`, ics, { expirationTtl: 86400 }),
    env.USERS_KV.put(`stats:${userId}`, JSON.stringify(stats), { expirationTtl: 86400 }),
    env.USERS_KV.put(`user:${userId}`, JSON.stringify({ ...user, lastSync: new Date().toISOString() }))
  ]);

  return { events, profiles };
}

// ============ Helpers ============

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.FRONTEND_URL,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin'
  };
}

// CSRF guard for state-changing requests
function originOk(request, env) {
  return request.headers.get('Origin') === env.FRONTEND_URL;
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders }
  });
}

function redirectToFrontend(env, path) {
  return Response.redirect(`${env.FRONTEND_URL}${path}`, 302);
}

function clearCookie() {
  return 'session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/';
}

function getSessionId(request) {
  const cookie = request.headers.get('Cookie');
  if (!cookie) return null;
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  return match ? match[1] : null;
}

async function getUserIdFromSession(request, env) {
  const sessionId = getSessionId(request);
  if (!sessionId) return null;
  return await env.SESSIONS_KV.get(`session:${sessionId}`);
}

async function getUser(userId, env) {
  const data = await env.USERS_KV.get(`user:${userId}`);
  return data ? JSON.parse(data) : null;
}

async function getUserStats(userId, env) {
  const data = await env.USERS_KV.get(`stats:${userId}`);
  if (!data) return { totalEvents: 0, scheduled: 0, drafts: 0, profiles: 0, recentPosts: [], isStale: true };
  const stats = JSON.parse(data);
  stats.isStale = (Date.now() - new Date(stats.lastSync)) > 5 * 60 * 1000;
  return stats;
}

function parseUpdate(update, profile, status, forcedDate = null) {
  return {
    id: update.id,
    start: forcedDate || update.due_at,
    text: update.text || '',
    channel: profile.service,
    profileName: profile.formatted_name || profile.service_username,
    status,
    url: update.permalink || ''
  };
}

function generateICS(events, userId) {
  const now = new Date().toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';

  let ics = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Buffer2iCal//EN
CALSCALE:GREGORIAN
METHOD:PUBLISH
X-WR-CALNAME:Buffer Scheduled Posts
X-WR-TIMEZONE:UTC
`;

  for (const e of events) {
    const start = new Date(e.start);
    const isDraft = e.status === 'draft';
    const duration = isDraft ? 15 : 30;

    const dtStart = start.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
    const dtEnd = new Date(start.getTime() + duration * 60000).toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';

    const prefix = isDraft ? 'DRAFT' : 'SCHEDULED';
    const summary = `${prefix} [${e.channel.toUpperCase()}] ${e.text.substring(0, 40)}${e.text.length > 40 ? '...' : ''}`
      .replace(/[,;\\]/g, '\\$&');

    const desc = [
      `Status: ${e.status.toUpperCase()}`,
      `Channel: ${e.channel}`,
      `Profile: ${e.profileName}`,
      e.url ? `URL: ${e.url}` : '',
      '',
      e.text
    ].join('\\n').replace(/[,;\\]/g, '\\$&');

    ics += `BEGIN:VEVENT
UID:buffer-${e.id}-${userId}@buffer2ical
DTSTAMP:${now}
DTSTART:${dtStart}
DTEND:${dtEnd}
SUMMARY:${summary}
DESCRIPTION:${desc}
STATUS:${isDraft ? 'TENTATIVE' : 'CONFIRMED'}
TRANSP:${isDraft ? 'TRANSPARENT' : 'OPAQUE'}
CATEGORIES:${e.status.toUpperCase()},${e.channel.toUpperCase()}
END:VEVENT
`;
  }

  ics += 'END:VCALENDAR';
  return ics;
}

function generateEmptyICS() {
  return `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Buffer2iCal//EN
CALSCALE:GREGORIAN
METHOD:PUBLISH
X-WR-CALNAME:Buffer Scheduled Posts
END:VCALENDAR`;
}
