<script lang="ts">
  import { goto } from "$app/navigation";
  import { SLUG_PATTERN, createApp } from "#lib/api.js";
  import { action } from "#lib/action.svelte.js";
  import ErrorAlert from "#lib/components/error-alert.svelte";
  import { Button } from "#lib/components/ui/button/index.js";
  import * as Card from "#lib/components/ui/card/index.js";
  import * as Dialog from "#lib/components/ui/dialog/index.js";
  import { Input } from "#lib/components/ui/input/index.js";
  import { Label } from "#lib/components/ui/label/index.js";
  import * as Table from "#lib/components/ui/table/index.js";
  import type { PageProps } from "./$types";

  let { data }: PageProps = $props();

  let open = $state(false);
  let name = $state("");
  let slug = $state("");
  const create = action();

  function startCreate() {
    name = "";
    slug = "";
    create.clear();
    open = true;
  }

  async function onsubmit(event: SubmitEvent) {
    event.preventDefault();
    const app = await create.run(() => createApp({ name, slug }));
    if (app) {
      open = false;
      await goto(`/apps/${app.app_id}`, { invalidate: ["app:apps"] });
    }
  }
</script>

<svelte:head>
  <title>Apps · Console</title>
</svelte:head>

<div class="flex items-center justify-between gap-4">
  <h1 class="text-2xl font-semibold">Apps</h1>
  <Button onclick={startCreate}>New app</Button>
</div>

<Card.Root>
  <Card.Content>
    {#if data.apps.length === 0}
      <p class="text-sm text-muted-foreground">You don't have any apps yet.</p>
    {:else}
      <Table.Root>
        <Table.Header>
          <Table.Row>
            <Table.Head>Name</Table.Head>
            <Table.Head>Slug</Table.Head>
            <Table.Head class="text-right">Identity providers</Table.Head>
            <Table.Head class="text-right">Clients</Table.Head>
            <Table.Head class="text-right">Resources</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each data.apps as app (app.app_id)}
            <Table.Row>
              <Table.Cell>
                <a class="font-medium hover:underline" href="/apps/{app.app_id}">{app.name}</a>
              </Table.Cell>
              <Table.Cell><code>{app.slug}</code></Table.Cell>
              <Table.Cell class="text-right">{app.idps.length}</Table.Cell>
              <Table.Cell class="text-right">{app.clients.length}</Table.Cell>
              <Table.Cell class="text-right">{app.resources.length}</Table.Cell>
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
        <Dialog.Title>New app</Dialog.Title>
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
      <ErrorAlert error={create.error} />
      <Dialog.Footer>
        <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={create.pending}>Create app</Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
