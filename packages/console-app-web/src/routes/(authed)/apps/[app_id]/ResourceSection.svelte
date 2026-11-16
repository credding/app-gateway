<script lang="ts">
	import { invalidate } from '$app/navigation';
	import {
		createResource,
		deleteResource,
		updateResource,
		type AppListItem,
		type Resource
	} from '#lib/api.js';
	import { action } from '#lib/action.svelte.js';

	let { app }: { app: AppListItem } = $props();

	// null: no form open; '': creating a new resource; otherwise the resource_id being edited.
	let editing = $state<string | null>(null);
	let name = $state('');
	let uri = $state('');
	const save = action();
	const remove = action();

	function startCreate() {
		name = '';
		uri = '';
		save.clear();
		editing = '';
	}

	function startEdit(resource: Resource) {
		name = resource.name;
		uri = resource.uri;
		save.clear();
		editing = resource.resource_id;
	}

	async function onsubmit(event: SubmitEvent) {
		event.preventDefault();
		const target = editing;
		const saved = await save.run(() =>
			target
				? updateResource(app.app_id, target, { name, uri })
				: createResource(app.app_id, { name, uri })
		);
		if (saved) {
			editing = null;
			await invalidate('app:apps');
		}
	}

	async function onDelete(resource: Resource) {
		if (!confirm(`Delete resource "${resource.name}"?`)) {
			return;
		}
		const deleted = await remove.run(async () => {
			await deleteResource(app.app_id, resource.resource_id);
			return true;
		});
		if (deleted) {
			await invalidate('app:apps');
		}
	}
</script>

{#snippet resourceForm(isNew: boolean)}
	<form {onsubmit}>
		<fieldset>
			<legend>{isNew ? 'New resource' : 'Edit resource'}</legend>
			<p>
				<label>
					Name<br />
					<input bind:value={name} required maxlength="200" />
				</label>
			</p>
			<p>
				<label>
					URI<br />
					<input bind:value={uri} required size="60" />
				</label>
			</p>
			{#if save.error}<p role="alert">{save.error}</p>{/if}
			<p>
				<button type="submit" disabled={save.pending}>{isNew ? 'Create resource' : 'Save'}</button>
				<button type="button" onclick={() => (editing = null)}>Cancel</button>
			</p>
		</fieldset>
	</form>
{/snippet}

<section>
	<h2>Resources</h2>

	{#if app.resources.length === 0}
		<p>No resources.</p>
	{:else}
		<table>
			<thead>
				<tr>
					<th scope="col">Name</th>
					<th scope="col">URI</th>
					<th scope="col"><span hidden>Actions</span></th>
				</tr>
			</thead>
			<tbody>
				{#each app.resources as resource (resource.resource_id)}
					<tr>
						<td>{resource.name}</td>
						<td><code>{resource.uri}</code></td>
						<td>
							<button type="button" onclick={() => startEdit(resource)}>Edit</button>
							<button type="button" onclick={() => onDelete(resource)} disabled={remove.pending}>
								Delete
							</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
	{#if remove.error}<p role="alert">{remove.error}</p>{/if}

	{#if editing !== null}
		{@render resourceForm(editing === '')}
	{:else}
		<p><button type="button" onclick={startCreate}>New resource</button></p>
	{/if}
</section>
