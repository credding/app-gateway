<script lang="ts">
	import { goto } from '$app/navigation';
	import { SLUG_PATTERN, createApp } from '#lib/api.js';
	import { action } from '#lib/action.svelte.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let name = $state('');
	let slug = $state('');
	const create = action();

	async function onsubmit(event: SubmitEvent) {
		event.preventDefault();
		const app = await create.run(() => createApp({ name, slug }));
		if (app) {
			await goto(`/apps/${app.app_id}`, { invalidate: ['app:apps'] });
		}
	}
</script>

<svelte:head>
	<title>Apps · Console</title>
</svelte:head>

<main>
	<h1>Apps</h1>

	{#if data.apps.length === 0}
		<p>You don't have any apps yet.</p>
	{:else}
		<table>
			<thead>
				<tr>
					<th scope="col">Name</th>
					<th scope="col">Slug</th>
					<th scope="col">Identity providers</th>
					<th scope="col">Clients</th>
					<th scope="col">Resources</th>
				</tr>
			</thead>
			<tbody>
				{#each data.apps as app (app.app_id)}
					<tr>
						<td><a href="/apps/{app.app_id}">{app.name}</a></td>
						<td><code>{app.slug}</code></td>
						<td>{app.idps.length}</td>
						<td>{app.clients.length}</td>
						<td>{app.resources.length}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	<h2>New app</h2>
	<form {onsubmit}>
		<p>
			<label>
				Name<br />
				<input bind:value={name} required maxlength="200" />
			</label>
		</p>
		<p>
			<label>
				Slug<br />
				<input
					bind:value={slug}
					required
					maxlength="64"
					pattern={SLUG_PATTERN}
					title="Lowercase letters, numbers, and single hyphens"
				/>
			</label>
		</p>
		{#if create.error}<p role="alert">{create.error}</p>{/if}
		<p><button type="submit" disabled={create.pending}>Create app</button></p>
	</form>
</main>
