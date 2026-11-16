type Fetch = typeof globalThis.fetch;

export type ClientType = 'confidential' | 'public';

export interface User {
	user_id: string;
	claims: Record<string, unknown>;
}

export interface Idp {
	idp_id: string;
	name: string;
}

export interface AppIdp {
	idp_id: string;
	name: string;
	client_id: string;
}

export interface Client {
	client_type: ClientType;
	name: string;
	client_id: string;
	redirect_uris: string[];
	created_at: string;
	updated_at: string;
}

export interface ClientWithSecret extends Client {
	client_secret: string | null;
}

export interface Resource {
	resource_id: string;
	name: string;
	uri: string;
	created_at: string;
	updated_at: string;
}

export interface App {
	app_id: string;
	slug: string;
	name: string;
}

export interface AppListItem extends App {
	owners: User[];
	idps: AppIdp[];
	clients: Client[];
	resources: Resource[];
	created_at: string;
	updated_at: string;
}

export interface Owner {
	user_id: string;
	name: string | null;
	email: string | null;
}

export interface CatalogApp extends App {
	owners: Owner[];
	resources: Resource[];
	is_owner: boolean;
	created_at: string;
	updated_at: string;
}

/** Mirrors the `Slug` pattern in `console_app/app_schema.py`. */
export const SLUG_PATTERN = '[a-z0-9]+(-[a-z0-9]+)*';

export class ApiError extends Error {
	constructor(
		readonly status: number,
		message: string
	) {
		super(message);
		this.name = 'ApiError';
	}
}

interface ValidationIssue {
	loc?: (string | number)[];
	msg?: string;
}

function errorMessage(status: number, body: unknown): string {
	const detail = (body as { detail?: unknown } | null)?.detail;
	if (typeof detail === 'string') {
		return detail;
	}
	if (Array.isArray(detail)) {
		return (detail as ValidationIssue[])
			.map((issue) => {
				const loc = (issue.loc ?? []).filter((part) => part !== 'body').join('.');
				return loc ? `${loc}: ${issue.msg}` : (issue.msg ?? 'invalid value');
			})
			.join('; ');
	}
	return `request failed (${status})`;
}

async function request<T>(fetch: Fetch, method: string, path: string, body?: unknown): Promise<T> {
	const response = await fetch(path, {
		method,
		credentials: 'same-origin',
		headers: body === undefined ? undefined : { 'content-type': 'application/json' },
		body: body === undefined ? undefined : JSON.stringify(body)
	});
	if (!response.ok) {
		const errorBody: unknown = await response.json().catch(() => null);
		throw new ApiError(response.status, errorMessage(response.status, errorBody));
	}
	if (response.status === 204) {
		return undefined as T;
	}
	return (await response.json()) as T;
}

const app = (appId: string) => `/api/apps/${encodeURIComponent(appId)}`;

export async function listIdps(fetch: Fetch): Promise<Idp[]> {
	const { identity_providers } = await request<{ identity_providers: Idp[] }>(
		fetch,
		'GET',
		'/api/identity-providers'
	);
	return identity_providers;
}

export async function listApps(fetch: Fetch): Promise<AppListItem[]> {
	const { apps } = await request<{ apps: AppListItem[] }>(fetch, 'GET', '/api/apps');
	return apps;
}

export async function listCatalog(fetch: Fetch): Promise<CatalogApp[]> {
	const { apps } = await request<{ apps: CatalogApp[] }>(fetch, 'GET', '/api/catalog/apps');
	return apps;
}

export function getCatalogApp(fetch: Fetch, appSlug: string): Promise<CatalogApp> {
	return request(fetch, 'GET', `/api/catalog/apps/${encodeURIComponent(appSlug)}`);
}

export function describeOwner(owner: Owner): string {
	const label = [owner.name, owner.email].filter(Boolean).join(' · ');
	return label || owner.user_id;
}

export function createApp(body: { slug: string; name: string }): Promise<App> {
	return request(fetch, 'POST', '/api/apps', body);
}

export function updateApp(appId: string, body: { slug?: string; name?: string }): Promise<App> {
	return request(fetch, 'PATCH', app(appId), body);
}

export function deleteApp(appId: string): Promise<void> {
	return request(fetch, 'DELETE', app(appId));
}

export function putAppIdp(
	appId: string,
	idpId: string,
	body: { client_id: string; client_secret: string }
): Promise<AppIdp> {
	return request(fetch, 'PUT', `${app(appId)}/idps/${encodeURIComponent(idpId)}`, body);
}

export function deleteAppIdp(appId: string, idpId: string): Promise<void> {
	return request(fetch, 'DELETE', `${app(appId)}/idps/${encodeURIComponent(idpId)}`);
}

export function createClient(
	appId: string,
	body: { client_type: ClientType; name: string; redirect_uris: string[] }
): Promise<ClientWithSecret> {
	return request(fetch, 'POST', `${app(appId)}/clients`, body);
}

export function updateClient(
	appId: string,
	clientId: string,
	body: { name?: string; redirect_uris?: string[] }
): Promise<Client> {
	return request(fetch, 'PATCH', `${app(appId)}/clients/${encodeURIComponent(clientId)}`, body);
}

export function rotateClientSecret(appId: string, clientId: string): Promise<ClientWithSecret> {
	return request(
		fetch,
		'POST',
		`${app(appId)}/clients/${encodeURIComponent(clientId)}/client-secret`
	);
}

export function deleteClient(appId: string, clientId: string): Promise<void> {
	return request(fetch, 'DELETE', `${app(appId)}/clients/${encodeURIComponent(clientId)}`);
}

export function createResource(appId: string, body: { name: string; uri: string }): Promise<Resource> {
	return request(fetch, 'POST', `${app(appId)}/resources`, body);
}

export function updateResource(
	appId: string,
	resourceId: string,
	body: { name?: string; uri?: string }
): Promise<Resource> {
	return request(
		fetch,
		'PATCH',
		`${app(appId)}/resources/${encodeURIComponent(resourceId)}`,
		body
	);
}

export function deleteResource(appId: string, resourceId: string): Promise<void> {
	return request(fetch, 'DELETE', `${app(appId)}/resources/${encodeURIComponent(resourceId)}`);
}
