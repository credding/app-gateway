export interface Session {
	user_id: string;
}

export async function getSession(fetch: typeof globalThis.fetch): Promise<Session | null> {
	const response = await fetch('/api/session', { credentials: 'same-origin' });
	if (response.status === 401) {
		return null;
	}
	if (!response.ok) {
		throw new Error(`failed to load session: ${response.status}`);
	}
	return (await response.json()) as Session;
}
