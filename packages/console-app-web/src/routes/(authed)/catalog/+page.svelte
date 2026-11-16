<script lang="ts">
	import { describeOwner } from '#lib/api.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const PREVIEW_COUNT = 3;

	let query = $state('');
	let apps = $derived.by(() => {
		const q = query.trim().toLowerCase();
		if (!q) {
			return data.apps;
		}
		return data.apps.filter(
			(app) => app.name.toLowerCase().includes(q) || app.slug.includes(q)
		);
	});
</script>

<svelte:head>
	<title>Catalog · Console</title>
</svelte:head>

<div class="flex flex-wrap items-center justify-between gap-4">
	<div>
		<h1 class="text-2xl font-semibold">Catalog</h1>
		<p class="text-sm text-muted-foreground">Browse apps and the resources they provide.</p>
	</div>
	<Input class="w-full sm:w-64" type="search" placeholder="Search apps" bind:value={query} />
</div>

{#if data.apps.length === 0}
	<p class="text-sm text-muted-foreground">No apps have been created yet.</p>
{:else if apps.length === 0}
	<p class="text-sm text-muted-foreground">No apps match "{query}".</p>
{:else}
	<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
		{#each apps as app (app.app_id)}
			<Card.Root class="relative transition-colors hover:bg-accent/50">
				<Card.Header>
					<Card.Title>
						<a href="/catalog/apps/{app.slug}" class="after:absolute after:inset-0">
							{app.name}
						</a>
					</Card.Title>
					<Card.Description><code>{app.slug}</code></Card.Description>
					{#if app.is_owner}
						<Card.Action><Badge variant="secondary">Yours</Badge></Card.Action>
					{/if}
				</Card.Header>
				<Card.Content class="flex-1 text-sm">
					{#if app.resources.length === 0}
						<p class="text-muted-foreground">No resources</p>
					{:else}
						<p class="text-muted-foreground">
							{app.resources.length}
							{app.resources.length === 1 ? 'resource' : 'resources'}
						</p>
						<ul class="mt-1 space-y-0.5">
							{#each app.resources.slice(0, PREVIEW_COUNT) as resource (resource.resource_id)}
								<li class="truncate">{resource.name}</li>
							{/each}
							{#if app.resources.length > PREVIEW_COUNT}
								<li class="text-muted-foreground">
									+{app.resources.length - PREVIEW_COUNT} more
								</li>
							{/if}
						</ul>
					{/if}
				</Card.Content>
				<Card.Footer class="text-xs text-muted-foreground">
					<span class="truncate">
						{app.owners.map(describeOwner).join(', ') || 'No owners'}
					</span>
				</Card.Footer>
			</Card.Root>
		{/each}
	</div>
{/if}
