<script lang="ts">
	import { goto, invalidate } from '$app/navigation';
	import { SLUG_PATTERN, deleteApp, updateApp, type User } from '#lib/api.js';
	import { action } from '#lib/action.svelte.js';
	import ClientSection from './ClientSection.svelte';
	import IdpSection from './IdpSection.svelte';
	import ResourceSection from './ResourceSection.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let app = $derived(data.app);

	let editing = $state(false);
	let name = $state('');
	let slug = $state('');
	const save = action();
	const remove = action();

	function startEdit() {
		name = app.name;
		slug = app.slug;
		save.clear();
		editing = true;
	}

	async function onsubmit(event: SubmitEvent) {
		event.preventDefault();
		const updated = await save.run(() => updateApp(app.app_id, { name, slug }));
		if (updated) {
			editing = false;
			await invalidate('app:apps');
		}
	}

	async function onDelete() {
		if (!confirm(`Delete app "${app.name}"? This also deletes its clients and resources.`)) {
			return;
		}
		const deleted = await remove.run(async () => {
			await deleteApp(app.app_id);
			return true;
		});
		if (deleted) {
			await goto('/apps', { invalidate: ['app:apps'] });
		}
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

<main>
	<p><a href="/apps">← All apps</a></p>
	<h1>{app.name}</h1>

	<section>
		<h2>App</h2>
		{#if editing}
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
				{#if save.error}<p role="alert">{save.error}</p>{/if}
				<p>
					<button type="submit" disabled={save.pending}>Save</button>
					<button type="button" onclick={() => (editing = false)}>Cancel</button>
				</p>
			</form>
		{:else}
			<dl>
				<dt>Name</dt>
				<dd>{app.name}</dd>
				<dt>Slug</dt>
				<dd><code>{app.slug}</code></dd>
				<dt>App ID</dt>
				<dd><code>{app.app_id}</code></dd>
				<dt>Owners</dt>
				<dd>
					<ul>
						{#each app.owners as owner (owner.user_id)}
							<li title={owner.user_id}>{describeUser(owner)}</li>
						{/each}
					</ul>
				</dd>
			</dl>
			<p>
				<button type="button" onclick={startEdit}>Edit app</button>
				<button type="button" onclick={onDelete} disabled={remove.pending}>Delete app</button>
			</p>
			{#if remove.error}<p role="alert">{remove.error}</p>{/if}
		{/if}
	</section>

	<IdpSection {app} idps={data.idps} />
	<ClientSection {app} />
	<ResourceSection {app} />
</main>
