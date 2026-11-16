<script lang="ts">
	import { invalidate } from '$app/navigation';
	import { deleteAppIdp, putAppIdp, type AppIdp, type AppListItem, type Idp } from '#lib/api.js';
	import { action } from '#lib/action.svelte.js';

	let { app, idps }: { app: AppListItem; idps: Idp[] } = $props();

	let available = $derived(idps.filter((idp) => !app.idps.some((a) => a.idp_id === idp.idp_id)));

	// null: no form open; '': adding a new IdP; otherwise the idp_id being edited.
	let editing = $state<string | null>(null);
	let idpId = $state('');
	let clientId = $state('');
	let clientSecret = $state('');
	const save = action();
	const remove = action();

	function startAdd() {
		idpId = available[0]?.idp_id ?? '';
		clientId = '';
		clientSecret = '';
		save.clear();
		editing = '';
	}

	function startEdit(appIdp: AppIdp) {
		idpId = appIdp.idp_id;
		clientId = appIdp.client_id;
		clientSecret = '';
		save.clear();
		editing = appIdp.idp_id;
	}

	async function onsubmit(event: SubmitEvent) {
		event.preventDefault();
		const saved = await save.run(() =>
			putAppIdp(app.app_id, idpId, { client_id: clientId, client_secret: clientSecret })
		);
		if (saved) {
			editing = null;
			await invalidate('app:apps');
		}
	}

	async function onRemove(appIdp: AppIdp) {
		if (!confirm(`Remove identity provider "${appIdp.name}" from this app?`)) {
			return;
		}
		const removed = await remove.run(async () => {
			await deleteAppIdp(app.app_id, appIdp.idp_id);
			return true;
		});
		if (removed) {
			await invalidate('app:apps');
		}
	}
</script>

{#snippet idpForm(isNew: boolean)}
	<form {onsubmit}>
		<fieldset>
			<legend>{isNew ? 'Add identity provider' : 'Edit identity provider'}</legend>
			<p>
				<label>
					Identity provider<br />
					<select bind:value={idpId} required disabled={!isNew}>
						{#if isNew}
							{#each available as idp (idp.idp_id)}
								<option value={idp.idp_id}>{idp.name}</option>
							{/each}
						{:else}
							{#each app.idps as idp (idp.idp_id)}
								<option value={idp.idp_id}>{idp.name}</option>
							{/each}
						{/if}
					</select>
				</label>
			</p>
			<p>
				<label>
					Client ID<br />
					<input bind:value={clientId} required autocomplete="off" />
				</label>
			</p>
			<p>
				<label>
					Client secret<br />
					<input type="password" bind:value={clientSecret} required autocomplete="new-password" />
				</label>
			</p>
			{#if save.error}<p role="alert">{save.error}</p>{/if}
			<p>
				<button type="submit" disabled={save.pending}>Save</button>
				<button type="button" onclick={() => (editing = null)}>Cancel</button>
			</p>
		</fieldset>
	</form>
{/snippet}

<section>
	<h2>Identity providers</h2>

	{#if app.idps.length === 0}
		<p>No identity providers configured.</p>
	{:else}
		<table>
			<thead>
				<tr>
					<th scope="col">Name</th>
					<th scope="col">Client ID</th>
					<th scope="col"><span hidden>Actions</span></th>
				</tr>
			</thead>
			<tbody>
				{#each app.idps as appIdp (appIdp.idp_id)}
					<tr>
						<td>{appIdp.name}</td>
						<td><code>{appIdp.client_id}</code></td>
						<td>
							<button type="button" onclick={() => startEdit(appIdp)}>Edit</button>
							<button type="button" onclick={() => onRemove(appIdp)} disabled={remove.pending}>
								Remove
							</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
	{#if remove.error}<p role="alert">{remove.error}</p>{/if}

	{#if editing !== null}
		{@render idpForm(editing === '')}
	{:else if available.length > 0}
		<p><button type="button" onclick={startAdd}>Add identity provider</button></p>
	{/if}
</section>
