<script lang="ts">
	import { page } from '$app/state';
	import { Button } from '#lib/components/ui/button/index.js';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	const links = [
		{ href: '/dashboard', label: 'Dashboard' },
		{ href: '/apps', label: 'Apps' }
	];
</script>

<header class="border-b">
	<div class="mx-auto flex h-14 max-w-5xl items-center gap-4 px-6">
		<span class="font-semibold">App Gateway</span>
		<nav class="flex flex-1 gap-1">
			{#each links as link (link.href)}
				<Button
					variant="ghost"
					size="sm"
					href={link.href}
					aria-current={page.url.pathname.startsWith(link.href) ? 'page' : undefined}
				>
					{link.label}
				</Button>
			{/each}
		</nav>
		<form method="post" action="/api/auth/logout">
			<Button type="submit" variant="outline" size="sm">Log out</Button>
		</form>
	</div>
</header>

<main class="mx-auto max-w-5xl space-y-6 p-6">
	{@render children()}
</main>
