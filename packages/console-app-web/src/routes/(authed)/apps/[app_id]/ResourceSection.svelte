<script lang="ts">
	import { invalidate } from '$app/navigation';
	import EllipsisIcon from '@lucide/svelte/icons/ellipsis';
	import {
		createResource,
		deleteResource,
		updateResource,
		type AppListItem,
		type Resource
	} from '#lib/api.js';
	import { action } from '#lib/action.svelte.js';
	import ConfirmDialog, { type ConfirmRequest } from '#lib/components/confirm-dialog.svelte';
	import ErrorAlert from '#lib/components/error-alert.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Table from '#lib/components/ui/table/index.js';

	let { app }: { app: AppListItem } = $props();

	let open = $state(false);
	// The resource_id being edited, or null when creating a new resource.
	let editingId = $state<string | null>(null);
	let name = $state('');
	let uri = $state('');
	let confirming = $state<ConfirmRequest | null>(null);
	const save = action();
	const remove = action();

	function startCreate() {
		name = '';
		uri = '';
		editingId = null;
		save.clear();
		open = true;
	}

	function startEdit(resource: Resource) {
		name = resource.name;
		uri = resource.uri;
		editingId = resource.resource_id;
		save.clear();
		open = true;
	}

	async function onsubmit(event: SubmitEvent) {
		event.preventDefault();
		const target = editingId;
		const saved = await save.run(() =>
			target
				? updateResource(app.app_id, target, { name, uri })
				: createResource(app.app_id, { name, uri })
		);
		if (saved) {
			open = false;
			await invalidate('app:apps');
		}
	}

	function onDelete(resource: Resource) {
		confirming = {
			title: `Delete resource "${resource.name}"?`,
			description: 'This cannot be undone.',
			action: 'Delete',
			onconfirm: async () => {
				const deleted = await remove.run(async () => {
					await deleteResource(app.app_id, resource.resource_id);
					return true;
				});
				if (deleted) {
					await invalidate('app:apps');
				}
			}
		};
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>Resources</Card.Title>
		<Card.Action>
			<Button variant="outline" size="sm" onclick={startCreate}>New resource</Button>
		</Card.Action>
	</Card.Header>
	<Card.Content class="space-y-4">
		<ErrorAlert error={remove.error} />
		{#if app.resources.length === 0}
			<p class="text-sm text-muted-foreground">No resources.</p>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>Name</Table.Head>
						<Table.Head>URI</Table.Head>
						<Table.Head class="w-0"><span class="sr-only">Actions</span></Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each app.resources as resource (resource.resource_id)}
						<Table.Row>
							<Table.Cell>{resource.name}</Table.Cell>
							<Table.Cell><code>{resource.uri}</code></Table.Cell>
							<Table.Cell>
								<DropdownMenu.Root>
									<DropdownMenu.Trigger>
										{#snippet child({ props })}
											<Button {...props} variant="ghost" size="icon-sm" aria-label="Actions">
												<EllipsisIcon />
											</Button>
										{/snippet}
									</DropdownMenu.Trigger>
									<DropdownMenu.Content align="end">
										<DropdownMenu.Item onSelect={() => startEdit(resource)}>Edit</DropdownMenu.Item>
										<DropdownMenu.Item
											variant="destructive"
											disabled={remove.pending}
											onSelect={() => onDelete(resource)}
										>
											Delete
										</DropdownMenu.Item>
									</DropdownMenu.Content>
								</DropdownMenu.Root>
							</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		{/if}
	</Card.Content>
</Card.Root>

<Dialog.Root bind:open>
	<Dialog.Content>
		<form class="grid gap-4" {onsubmit}>
			<Dialog.Header>
				<Dialog.Title>{editingId ? 'Edit resource' : 'New resource'}</Dialog.Title>
			</Dialog.Header>
			<div class="grid gap-2">
				<Label for="resource-name">Name</Label>
				<Input id="resource-name" bind:value={name} required maxlength={200} />
			</div>
			<div class="grid gap-2">
				<Label for="resource-uri">URI</Label>
				<Input id="resource-uri" bind:value={uri} required />
			</div>
			<ErrorAlert error={save.error} />
			<Dialog.Footer>
				<Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
				<Button type="submit" disabled={save.pending}>{editingId ? 'Save' : 'Create resource'}</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>

<ConfirmDialog bind:request={confirming} />
