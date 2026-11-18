export interface Session {
  user_id: string;
}

type Fetch = typeof globalThis.fetch;

/**
 * `/api/session` is the only endpoint that refreshes the access token. The
 * auth server rotates refresh tokens and revokes the whole session if one is
 * reused, so concurrent refreshes must never happen: calls within this tab
 * share one in-flight request, and a Web Lock serializes them across tabs.
 */
let inFlight: Promise<Session | null> | null = null;

const LOCK_NAME = "console-session-refresh";

async function fetchSession(fetch: Fetch): Promise<Session | null> {
  const response = await fetch("/api/session", { credentials: "same-origin" });
  if (response.status === 401) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`failed to load session: ${response.status}`);
  }
  return (await response.json()) as Session;
}

function withLock<T>(fn: () => Promise<T>): Promise<T> {
  if (typeof navigator !== "undefined" && navigator.locks) {
    return navigator.locks.request(LOCK_NAME, fn);
  }
  return fn();
}

export function getSession(fetch: Fetch = globalThis.fetch): Promise<Session | null> {
  inFlight ??= withLock(() => fetchSession(fetch)).finally(() => {
    inFlight = null;
  });
  return inFlight;
}
