import type { Env } from "./types";

export function corsHeaders(env: Env): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": env.FRONTEND_URL,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    Vary: "Origin",
  };
}

export function originOk(request: Request, env: Env): boolean {
  return request.headers.get("Origin") === env.FRONTEND_URL;
}

export function json(
  data: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

export function redirectToFrontend(env: Env, path: string): Response {
  return Response.redirect(`${env.FRONTEND_URL}${path}`, 302);
}

export function redirectWithCookie(url: string, cookie: string): Response {
  return new Response(null, {
    status: 302,
    headers: { Location: url, "Set-Cookie": cookie },
  });
}

export function getCookie(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match?.[1] ?? null;
}

export function withCors(response: Response, env: Env): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders(env))) {
    headers.set(key, value);
  }
  return new Response(response.body, { status: response.status, headers });
}
