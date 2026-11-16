import { error } from '@sveltejs/kit';
import { listApps, listIdps } from '#lib/api.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, depends, params }) => {
	depends('app:apps');
	const [apps, idps] = await Promise.all([listApps(fetch), listIdps(fetch)]);
	const app = apps.find((a) => a.app_id === params.app_id);
	if (!app) {
		error(404, 'app not found');
	}
	return { app, idps };
};
