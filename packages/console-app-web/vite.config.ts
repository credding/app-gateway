import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},

			// Built as a static SPA and served by console_app (FastAPI), which falls
			// back to index.html for unknown paths.
			adapter: adapter({ pages: 'build', assets: 'build', fallback: 'index.html' })
		})
	]
});
