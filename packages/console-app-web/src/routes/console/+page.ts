import { redirect } from '@sveltejs/kit';
import { getSession } from '#lib/session.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	const session = await getSession(fetch);
	if (!session) {
		redirect(307, '/');
	}
	return { session };
};
