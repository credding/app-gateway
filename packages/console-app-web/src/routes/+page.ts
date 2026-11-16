import { redirect } from '@sveltejs/kit';
import { getSession } from '#lib/session.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	if (await getSession(fetch)) {
		redirect(307, '/console');
	}
};
