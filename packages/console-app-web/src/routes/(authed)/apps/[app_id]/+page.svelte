<script lang="ts">
	import { goto, invalidate } from '$app/navigation';
	import ArrowLeftIcon from '@lucide/svelte/icons/arrow-left';
	import { SLUG_PATTERN, deleteApp, updateApp, type User } from '#lib/api.js';
	import { action } from '#lib/action.svelte.js';
	import ConfirmDialog, { type ConfirmRequest } from '#lib/components/confirm-dialog.svelte';
	import ErrorAlert from '#lib/components/error-alert.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import ClientSection from './ClientSection.svelte';
	import IdpSection from './IdpSection.svelte';
	import ResourceSection from './ResourceSection.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let app = $derived(data.app);

	let open = $state(false);
	let name = $state('');
	let slug = $state('');
	let confirming = $state<ConfirmRequest | null>(null);
	const save = action();
	const remove = action();

	function startEdit() {
		name = app.name;
		slug = app.slug;
		save.clear();
		open = true;
	}

	async function onsubmit(event: SubmitEvent) {
		event.preventDefault();
		const updated = await save.run(() => updateApp(app.app_id, { name, slug }));
		if (updated) {
			open = false;
			await invalidate('app:apps');
		}
	}

	function onDelete() {
		confirming = {
			title: `Delete app "${app.name}"?`,
			description: 'This also deletes its clients and resources.',
			action: 'Delete app',
			onconfirm: async () => {
				const deleted = await remove.run(async () => {
					await deleteApp(app.app_id);
					return true;
				});
				if (deleted) {
					await goto('/apps', { invalidate: ['app:apps'] });
				}
			}
		};
	}

	function describeUser(user: User): string {
		const { email, name } = user.claims;
		const label = [name, email].filter((v) => typeof v === 'string' && v).join(' · ');
		return label || user.user_id;
	}
</script>

<svelte:head>
	<title>{app.name} · Apps · Console</title>
</svelte:head>

<div class="space-y-2">
	<Button variant="ghost" size="sm" href="/apps"><ArrowLeftIcon /> All apps</Button>
	<div class="flex items-center justify-between gap-4">
		<h1 class="text-2xl font-semibold">{app.name}</h1>
		<div class="flex gap-2">
			<Button variant="outline" onclick={startEdit}>Edit</Button>
			<Button variant="destructive" onclick={onDelete} disabled={remove.pending}>Delete</Button>
		</div>
	</div>
</div>

<ErrorAlert error={remove.error} />

<Card.Root>
	<Card.Header>
		<Card.Title>Details</Card.Title>
	</Card.Header>
	<Card.Content>
		<dl class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
			<dt class="text-muted-foreground">Slug</dt>
			<dd><code>{app.slug}</code></dd>
			<dt class="text-muted-foreground">App ID</dt>
			<dd><code>{app.app_id}</code></dd>
			<dt class="text-muted-foreground">Owners</dt>
			<dd>
				<ul>
					{#each app.owners as owner (owner.user_id)}
						<li title={owner.user_id}>{describeUser(owner)}</li>
					{/each}
				</ul>
			</dd>
		</dl>
	</Card.Content>
</Card.Root>

<IdpSection {app} idps={data.idps} />
<ClientSection {app} />
<ResourceSection {app} />

<Dialog.Root bind:open>
	<Dialog.Content>
		<form class="grid gap-4" {onsubmit}>
			<Dialog.Header>
				<Dialog.Title>Edit app</Dialog.Title>
			</Dialog.Header>
			<div class="grid gap-2">
				<Label for="app-name">Name</Label>
				<Input id="app-name" bind:value={name} required maxlength={200} />
			</div>
			<div class="grid gap-2">
				<Label for="app-slug">Slug</Label>
				<Input
					id="app-slug"
					bind:value={slug}
					required
					maxlength={64}
					pattern={SLUG_PATTERN}
					title="Lowercase letters, numbers, and single hyphens"
				/>
			</div>
			<ErrorAlert error={save.error} />
			<Dialog.Footer>
				<Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
				<Button type="submit" disabled={save.pending}>Save</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>

<ConfirmDialog bind:request={confirming} />
