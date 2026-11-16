import { listCatalog } from '#lib/api.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, depends }) => {
	depends('app:catalog');
	return { apps: await listCatalog(fetch) };
};
