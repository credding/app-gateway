<script lang="ts">
	import ArrowLeftIcon from '@lucide/svelte/icons/arrow-left';
	import { describeOwner } from '#lib/api.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let app = $derived(data.app);
</script>

<svelte:head>
	<title>{app.name} · Catalog · Console</title>
</svelte:head>

<div class="space-y-2">
	<Button variant="ghost" size="sm" href="/catalog"><ArrowLeftIcon /> Catalog</Button>
	<div class="flex items-center justify-between gap-4">
		<div class="flex items-center gap-3">
			<h1 class="text-2xl font-semibold">{app.name}</h1>
			{#if app.is_owner}
				<Badge variant="secondary">Yours</Badge>
			{/if}
		</div>
		{#if app.is_owner}
			<Button variant="outline" href="/apps/{app.app_id}">Manage</Button>
		{/if}
	</div>
</div>

<Card.Root>
	<Card.Header>
		<Card.Title>Details</Card.Title>
	</Card.Header>
	<Card.Content>
		<dl class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
			<dt class="text-muted-foreground">Slug</dt>
			<dd><code>{app.slug}</code></dd>
			<dt class="text-muted-foreground">Owners</dt>
			<dd>
				<ul>
					{#each app.owners as owner (owner.user_id)}
						<li title={owner.user_id}>{describeOwner(owner)}</li>
					{/each}
				</ul>
			</dd>
		</dl>
	</Card.Content>
</Card.Root>

<Card.Root>
	<Card.Header>
		<Card.Title>Resources</Card.Title>
	</Card.Header>
	<Card.Content>
		{#if app.resources.length === 0}
			<p class="text-sm text-muted-foreground">This app has no resources.</p>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>Name</Table.Head>
						<Table.Head>URI</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each app.resources as resource (resource.resource_id)}
						<Table.Row>
							<Table.Cell>{resource.name}</Table.Cell>
							<Table.Cell><code>{resource.uri}</code></Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		{/if}
	</Card.Content>
</Card.Root>
