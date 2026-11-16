<script lang="ts">
	import { invalidate } from '$app/navigation';
	import CheckIcon from '@lucide/svelte/icons/check';
	import CopyIcon from '@lucide/svelte/icons/copy';
	import EllipsisIcon from '@lucide/svelte/icons/ellipsis';
	import PlusIcon from '@lucide/svelte/icons/plus';
	import XIcon from '@lucide/svelte/icons/x';
	import {
		createClient,
		deleteClient,
		rotateClientSecret,
		updateClient,
		type AppListItem,
		type Client,
		type ClientType,
		type ClientWithSecret
	} from '#lib/api.js';
	import { action } from '#lib/action.svelte.js';
	import ConfirmDialog, { type ConfirmRequest } from '#lib/components/confirm-dialog.svelte';
	import ErrorAlert from '#lib/components/error-alert.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import * as Table from '#lib/components/ui/table/index.js';

	let { app }: { app: AppListItem } = $props();

	const clientTypes: { value: ClientType; label: string }[] = [
		{ value: 'confidential', label: 'Confidential' },
		{ value: 'public', label: 'Public' }
	];

	let open = $state(false);
	// The client_id being edited, or null when creating a new client.
	let editingId = $state<string | null>(null);
	let name = $state('');
	let clientType = $state<ClientType>('confidential');
	let redirectUris = $state<string[]>([]);
	let confirming = $state<ConfirmRequest | null>(null);
	const save = action();
	const mutate = action();

	let secretOpen = $state(false);
	let revealed = $state<ClientWithSecret | null>(null);
	let copied = $state(false);

	function startCreate() {
		name = '';
		clientType = 'confidential';
		redirectUris = [''];
		editingId = null;
		save.clear();
		open = true;
	}

	function startEdit(client: Client) {
		name = client.name;
		redirectUris = [...client.redirect_uris];
		editingId = client.client_id;
		save.clear();
		open = true;
	}

	function showSecret(client: ClientWithSecret) {
		if (client.client_secret) {
			revealed = client;
			copied = false;
			secretOpen = true;
		}
	}

	async function onsubmit(event: SubmitEvent) {
		event.preventDefault();
		const redirect_uris = redirectUris.map((uri) => uri.trim());
		const target = editingId;
		const saved = await save.run(async () => {
			if (target) {
				await updateClient(app.app_id, target, { name, redirect_uris });
			} else {
				showSecret(
					await createClient(app.app_id, { client_type: clientType, name, redirect_uris })
				);
			}
			return true;
		});
		if (saved) {
			open = false;
			await invalidate('app:apps');
		}
	}

	function onRotate(client: Client) {
		confirming = {
			title: `Rotate the secret for "${client.name}"?`,
			description: 'The current secret stops working immediately.',
			action: 'Rotate secret',
			onconfirm: async () => {
				const rotated = await mutate.run(() => rotateClientSecret(app.app_id, client.client_id));
				if (rotated) {
					showSecret(rotated);
					await invalidate('app:apps');
				}
			}
		};
	}

	function onDelete(client: Client) {
		confirming = {
			title: `Delete client "${client.name}"?`,
			description: 'Applications using this client will stop working.',
			action: 'Delete',
			onconfirm: async () => {
				const deleted = await mutate.run(async () => {
					await deleteClient(app.app_id, client.client_id);
					return true;
				});
				if (deleted) {
					await invalidate('app:apps');
				}
			}
		};
	}

	async function copySecret() {
		if (revealed?.client_secret) {
			await navigator.clipboard.writeText(revealed.client_secret);
			copied = true;
		}
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>Clients</Card.Title>
		<Card.Action>
			<Button variant="outline" size="sm" onclick={startCreate}>New client</Button>
		</Card.Action>
	</Card.Header>
	<Card.Content class="space-y-4">
		<ErrorAlert error={mutate.error} />
		{#if app.clients.length === 0}
			<p class="text-sm text-muted-foreground">No clients.</p>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>Name</Table.Head>
						<Table.Head>Type</Table.Head>
						<Table.Head>Client ID</Table.Head>
						<Table.Head>Redirect URIs</Table.Head>
						<Table.Head class="w-0"><span class="sr-only">Actions</span></Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each app.clients as client (client.client_id)}
						<Table.Row>
							<Table.Cell>{client.name}</Table.Cell>
							<Table.Cell><Badge variant="secondary">{client.client_type}</Badge></Table.Cell>
							<Table.Cell><code>{client.client_id}</code></Table.Cell>
							<Table.Cell>
								{#if client.redirect_uris.length}
									<ul>
										{#each client.redirect_uris as uri, i (i)}
											<li><code>{uri}</code></li>
										{/each}
									</ul>
								{:else}
									<span class="text-muted-foreground">None</span>
								{/if}
							</Table.Cell>
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
										<DropdownMenu.Item onSelect={() => startEdit(client)}>Edit</DropdownMenu.Item>
										{#if client.client_type === 'confidential'}
											<DropdownMenu.Item disabled={mutate.pending} onSelect={() => onRotate(client)}>
												Rotate secret
											</DropdownMenu.Item>
										{/if}
										<DropdownMenu.Separator />
										<DropdownMenu.Item
											variant="destructive"
											disabled={mutate.pending}
											onSelect={() => onDelete(client)}
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
				<Dialog.Title>{editingId ? 'Edit client' : 'New client'}</Dialog.Title>
			</Dialog.Header>
			<div class="grid gap-2">
				<Label for="client-name">Name</Label>
				<Input id="client-name" bind:value={name} required maxlength={200} />
			</div>
			{#if !editingId}
				<div class="grid gap-2">
					<Label for="client-type">Type</Label>
					<Select.Root type="single" bind:value={clientType}>
						<Select.Trigger id="client-type" class="w-full">
							{clientTypes.find((t) => t.value === clientType)?.label}
						</Select.Trigger>
						<Select.Content>
							{#each clientTypes as type (type.value)}
								<Select.Item value={type.value} label={type.label} />
							{/each}
						</Select.Content>
					</Select.Root>
				</div>
			{/if}
			<div class="grid gap-2" role="group" aria-labelledby="client-redirect-uris">
				<Label id="client-redirect-uris">Redirect URIs</Label>
				{#each redirectUris as _, i (i)}
					<div class="flex gap-2">
						<Input
							type="url"
							bind:value={redirectUris[i]}
							required
							placeholder="https://example.com/callback"
							aria-label="Redirect URI {i + 1}"
						/>
						<Button
							variant="outline"
							size="icon"
							aria-label="Remove redirect URI {i + 1}"
							onclick={() => redirectUris.splice(i, 1)}
						>
							<XIcon />
						</Button>
					</div>
				{/each}
				<Button
					variant="outline"
					size="sm"
					class="justify-self-start"
					onclick={() => redirectUris.push('')}
				>
					<PlusIcon /> Add redirect URI
				</Button>
			</div>
			<ErrorAlert error={save.error} />
			<Dialog.Footer>
				<Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
				<Button type="submit" disabled={save.pending}>{editingId ? 'Save' : 'Create client'}</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>

<Dialog.Root bind:open={secretOpen}>
	<Dialog.Content>
		{#if revealed}
			<Dialog.Header>
				<Dialog.Title>Client secret for "{revealed.name}"</Dialog.Title>
				<Dialog.Description>Copy this secret now. It won't be shown again.</Dialog.Description>
			</Dialog.Header>
			<div class="grid gap-2">
				<Label for="revealed-client-id">Client ID</Label>
				<Input id="revealed-client-id" readonly value={revealed.client_id} />
			</div>
			<div class="grid gap-2">
				<Label for="revealed-client-secret">Client secret</Label>
				<div class="flex gap-2">
					<Input id="revealed-client-secret" readonly value={revealed.client_secret} />
					<Button variant="outline" size="icon" aria-label="Copy secret" onclick={copySecret}>
						{#if copied}<CheckIcon />{:else}<CopyIcon />{/if}
					</Button>
				</div>
			</div>
			<Dialog.Footer>
				<Button onclick={() => (secretOpen = false)}>Done</Button>
			</Dialog.Footer>
		{/if}
	</Dialog.Content>
</Dialog.Root>

<ConfirmDialog bind:request={confirming} />
