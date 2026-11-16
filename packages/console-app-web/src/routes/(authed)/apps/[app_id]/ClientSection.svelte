<script lang="ts">
	import { invalidate } from '$app/navigation';
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

	let { app }: { app: AppListItem } = $props();

	// null: no form open; '': creating a new client; otherwise the client_id being edited.
	let editing = $state<string | null>(null);
	let name = $state('');
	let clientType = $state<ClientType>('confidential');
	let redirectUris = $state('');
	const save = action();
	const mutate = action();

	let secretDialog: HTMLDialogElement;
	let revealed = $state<ClientWithSecret | null>(null);

	function parseUris(text: string): string[] {
		return text
			.split('\n')
			.map((line) => line.trim())
			.filter(Boolean);
	}

	function startCreate() {
		name = '';
		clientType = 'confidential';
		redirectUris = '';
		save.clear();
		editing = '';
	}

	function startEdit(client: Client) {
		name = client.name;
		redirectUris = client.redirect_uris.join('\n');
		save.clear();
		editing = client.client_id;
	}

	function showSecret(client: ClientWithSecret) {
		if (client.client_secret) {
			revealed = client;
			secretDialog.showModal();
		}
	}

	async function onsubmit(event: SubmitEvent) {
		event.preventDefault();
		const redirect_uris = parseUris(redirectUris);
		const target = editing;
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
			editing = null;
			await invalidate('app:apps');
		}
	}

	async function onRotate(client: Client) {
		if (!confirm(`Rotate the secret for "${client.name}"? The current secret stops working.`)) {
			return;
		}
		const rotated = await mutate.run(() => rotateClientSecret(app.app_id, client.client_id));
		if (rotated) {
			showSecret(rotated);
			await invalidate('app:apps');
		}
	}

	async function onDelete(client: Client) {
		if (!confirm(`Delete client "${client.name}"?`)) {
			return;
		}
		const deleted = await mutate.run(async () => {
			await deleteClient(app.app_id, client.client_id);
			return true;
		});
		if (deleted) {
			await invalidate('app:apps');
		}
	}

	async function copySecret() {
		if (revealed?.client_secret) {
			await navigator.clipboard.writeText(revealed.client_secret);
		}
	}
</script>

{#snippet clientForm(isNew: boolean)}
	<form {onsubmit}>
		<fieldset>
			<legend>{isNew ? 'New client' : 'Edit client'}</legend>
			<p>
				<label>
					Name<br />
					<input bind:value={name} required maxlength="200" />
				</label>
			</p>
			{#if isNew}
				<p>
					<label>
						Type<br />
						<select bind:value={clientType}>
							<option value="confidential">Confidential</option>
							<option value="public">Public</option>
						</select>
					</label>
				</p>
			{/if}
			<p>
				<label>
					Redirect URIs (one per line)<br />
					<textarea bind:value={redirectUris} rows="4" cols="60"></textarea>
				</label>
			</p>
			{#if save.error}<p role="alert">{save.error}</p>{/if}
			<p>
				<button type="submit" disabled={save.pending}>{isNew ? 'Create client' : 'Save'}</button>
				<button type="button" onclick={() => (editing = null)}>Cancel</button>
			</p>
		</fieldset>
	</form>
{/snippet}

<section>
	<h2>Clients</h2>

	{#if app.clients.length === 0}
		<p>No clients.</p>
	{:else}
		<table>
			<thead>
				<tr>
					<th scope="col">Name</th>
					<th scope="col">Type</th>
					<th scope="col">Client ID</th>
					<th scope="col">Redirect URIs</th>
					<th scope="col"><span hidden>Actions</span></th>
				</tr>
			</thead>
			<tbody>
				{#each app.clients as client (client.client_id)}
					<tr>
						<td>{client.name}</td>
						<td>{client.client_type}</td>
						<td><code>{client.client_id}</code></td>
						<td>
							{#if client.redirect_uris.length}
								<ul>
									{#each client.redirect_uris as uri, i (i)}
										<li><code>{uri}</code></li>
									{/each}
								</ul>
							{:else}
								<em>none</em>
							{/if}
						</td>
						<td>
							<button type="button" onclick={() => startEdit(client)}>Edit</button>
							{#if client.client_type === 'confidential'}
								<button type="button" onclick={() => onRotate(client)} disabled={mutate.pending}>
									Rotate secret
								</button>
							{/if}
							<button type="button" onclick={() => onDelete(client)} disabled={mutate.pending}>
								Delete
							</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
	{#if mutate.error}<p role="alert">{mutate.error}</p>{/if}

	{#if editing !== null}
		{@render clientForm(editing === '')}
	{:else}
		<p><button type="button" onclick={startCreate}>New client</button></p>
	{/if}
</section>

<dialog bind:this={secretDialog} onclose={() => (revealed = null)}>
	{#if revealed}
		<h3>Client secret for "{revealed.name}"</h3>
		<p>Copy this secret now. It won't be shown again.</p>
		<p>
			<label>
				Client ID<br />
				<input readonly value={revealed.client_id} size="50" />
			</label>
		</p>
		<p>
			<label>
				Client secret<br />
				<input readonly value={revealed.client_secret} size="50" />
			</label>
		</p>
		<form method="dialog">
			<button type="button" onclick={copySecret}>Copy secret</button>
			<button type="submit">Done</button>
		</form>
	{/if}
</dialog>
