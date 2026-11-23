<script lang="ts">
  import { invalidate } from "$app/navigation";
  import ChevronsUpDownIcon from "@lucide/svelte/icons/chevrons-up-down";
  import EllipsisIcon from "@lucide/svelte/icons/ellipsis";
  import {
    ACCESS_TYPES,
    createAccessGrant,
    deleteAccessGrant,
    type AccessGrant,
    type AccessType,
    type App,
    type AppListItem,
  } from "#lib/api.js";
  import { action } from "#lib/action.svelte.js";
  import ConfirmDialog, { type ConfirmRequest } from "#lib/components/confirm-dialog.svelte";
  import ErrorAlert from "#lib/components/error-alert.svelte";
  import { Badge } from "#lib/components/ui/badge/index.js";
  import { Button } from "#lib/components/ui/button/index.js";
  import * as Card from "#lib/components/ui/card/index.js";
  import { Checkbox } from "#lib/components/ui/checkbox/index.js";
  import * as Command from "#lib/components/ui/command/index.js";
  import * as Dialog from "#lib/components/ui/dialog/index.js";
  import * as DropdownMenu from "#lib/components/ui/dropdown-menu/index.js";
  import { Label } from "#lib/components/ui/label/index.js";
  import * as Popover from "#lib/components/ui/popover/index.js";
  import * as Select from "#lib/components/ui/select/index.js";
  import * as Table from "#lib/components/ui/table/index.js";

  let { app, grants, apps }: { app: AppListItem; grants: AccessGrant[]; apps: App[] } = $props();

  /** The grants one app holds on one resource, shown as a single row. */
  interface GrantGroup {
    key: string;
    app: App;
    resource: AccessGrant["resource"];
    grants: AccessGrant[];
  }

  const groupKey = (appId: string, resourceId: string) => `${appId}/${resourceId}`;

  let groups = $derived.by(() => {
    const byKey = new Map<string, GrantGroup>();
    for (const grant of grants) {
      const key = groupKey(grant.app.app_id, grant.resource.resource_id);
      let group = byKey.get(key);
      if (!group) {
        group = { key, app: grant.app, resource: grant.resource, grants: [] };
        byKey.set(key, group);
      }
      group.grants.push(grant);
    }
    const order = (t: AccessType) => ACCESS_TYPES.findIndex((a) => a.value === t);
    for (const group of byKey.values()) {
      group.grants.sort((a, b) => order(a.access_type) - order(b.access_type));
    }
    return [...byKey.values()];
  });

  let open = $state(false);
  let appPickerOpen = $state(false);
  // True when editing an existing app/resource pair, which can't be changed.
  let editing = $state(false);
  let grantAppId = $state("");
  let resourceId = $state("");
  let selected = $state<AccessType[]>([]);
  let confirming = $state<ConfirmRequest | null>(null);
  const save = action();
  const remove = action();

  const describeApp = (a: App) => `${a.name} (${a.slug})`;
  const accessTypeLabel = (value: AccessType) =>
    ACCESS_TYPES.find((t) => t.value === value)?.label ?? value;

  let selectedApp = $derived(apps.find((a) => a.app_id === grantAppId));
  let selectedResource = $derived(app.resources.find((r) => r.resource_id === resourceId));

  // Grants that already exist for the chosen app/resource pair.
  let existing = $derived(
    grantAppId && resourceId
      ? (groups.find((g) => g.key === groupKey(grantAppId, resourceId))?.grants ?? [])
      : [],
  );
  let toCreate = $derived(selected.filter((t) => !existing.some((g) => g.access_type === t)));
  let toDelete = $derived(existing.filter((g) => !selected.includes(g.access_type)));

  // Start the checkboxes from what's already granted whenever the pair changes.
  function syncSelected() {
    selected = existing.map((g) => g.access_type);
  }

  function startCreate() {
    editing = false;
    grantAppId = "";
    resourceId = app.resources.length === 1 ? app.resources[0].resource_id : "";
    selected = [];
    save.clear();
    open = true;
  }

  function startEdit(group: GrantGroup) {
    editing = true;
    grantAppId = group.app.app_id;
    resourceId = group.resource.resource_id;
    selected = group.grants.map((g) => g.access_type);
    save.clear();
    open = true;
  }

  function pickResource(id: string) {
    resourceId = id;
    syncSelected();
  }

  function pickApp(appId: string) {
    grantAppId = appId;
    appPickerOpen = false;
    syncSelected();
  }

  function toggle(type: AccessType, checked: boolean) {
    selected = checked ? [...selected, type] : selected.filter((t) => t !== type);
  }

  async function onsubmit(event: SubmitEvent) {
    event.preventDefault();
    if (!grantAppId || !resourceId) {
      return;
    }
    const appId = grantAppId;
    const resId = resourceId;
    const creates = toCreate;
    const deletes = toDelete;
    const saved = await save.run(async () => {
      try {
        await Promise.all([
          ...creates.map((access_type) =>
            createAccessGrant({ app_id: appId, resource_id: resId, access_type }),
          ),
          ...deletes.map((grant) => deleteAccessGrant(grant.rule_id)),
        ]);
      } finally {
        // Some changes may have landed even if another failed; show the real state.
        await invalidate("app:apps");
      }
      return true;
    });
    if (saved) {
      open = false;
    }
  }

  function onRevoke(group: GrantGroup) {
    confirming = {
      title: `Revoke ${group.app.name}'s access to "${group.resource.name}"?`,
      description: `This removes all ${group.grants.length} access type(s) granted to ${group.app.name} for this resource.`,
      action: "Revoke",
      onconfirm: async () => {
        await remove.run(async () => {
          try {
            await Promise.all(group.grants.map((g) => deleteAccessGrant(g.rule_id)));
          } finally {
            await invalidate("app:apps");
          }
        });
      },
    };
  }
</script>

<Card.Root>
  <Card.Header>
    <Card.Title>Access grants</Card.Title>
    <Card.Description>Apps allowed to access this app's resources.</Card.Description>
    <Card.Action>
      <Button
        variant="outline"
        size="sm"
        onclick={startCreate}
        disabled={app.resources.length === 0}>Grant access</Button
      >
    </Card.Action>
  </Card.Header>
  <Card.Content class="space-y-4">
    <ErrorAlert error={remove.error} />
    {#if app.resources.length === 0}
      <p class="text-sm text-muted-foreground">Add a resource before granting access to it.</p>
    {:else if groups.length === 0}
      <p class="text-sm text-muted-foreground">No apps have been granted access.</p>
    {:else}
      <Table.Root>
        <Table.Header>
          <Table.Row>
            <Table.Head>App</Table.Head>
            <Table.Head>Resource</Table.Head>
            <Table.Head>Access types</Table.Head>
            <Table.Head class="w-0"><span class="sr-only">Actions</span></Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each groups as group (group.key)}
            <Table.Row>
              <Table.Cell>
                {group.app.name} <code class="text-muted-foreground">{group.app.slug}</code>
              </Table.Cell>
              <Table.Cell title={group.resource.uri}>{group.resource.name}</Table.Cell>
              <Table.Cell>
                <div class="flex flex-wrap gap-1">
                  {#each group.grants as grant (grant.rule_id)}
                    <Badge
                      variant="secondary"
                      title={`Granted ${new Date(grant.created_at).toLocaleString()}`}
                      >{accessTypeLabel(grant.access_type)}</Badge
                    >
                  {/each}
                </div>
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
                    <DropdownMenu.Item onSelect={() => startEdit(group)}>Edit</DropdownMenu.Item>
                    <DropdownMenu.Item
                      variant="destructive"
                      disabled={remove.pending}
                      onSelect={() => onRevoke(group)}
                    >
                      Revoke
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
        <Dialog.Title>{editing ? "Edit access" : "Grant access"}</Dialog.Title>
        <Dialog.Description>
          Choose which kinds of access an app has to one of {app.name}'s resources.
        </Dialog.Description>
      </Dialog.Header>
      <div class="grid gap-2">
        <Label for="grant-app">App</Label>
        <Popover.Root bind:open={appPickerOpen}>
          <Popover.Trigger disabled={editing}>
            {#snippet child({ props })}
              <Button
                {...props}
                id="grant-app"
                variant="outline"
                role="combobox"
                aria-expanded={appPickerOpen}
                class="w-full justify-between font-normal"
              >
                <span class={selectedApp ? "" : "text-muted-foreground"}>
                  {selectedApp ? describeApp(selectedApp) : "Search apps…"}
                </span>
                <ChevronsUpDownIcon class="opacity-50" />
              </Button>
            {/snippet}
          </Popover.Trigger>
          <Popover.Content class="w-(--bits-popover-anchor-width) p-0" align="start">
            <Command.Root>
              <Command.Input placeholder="Search by name or slug…" />
              <Command.List>
                <Command.Empty>No apps found.</Command.Empty>
                <Command.Group>
                  {#each apps as a (a.app_id)}
                    <Command.Item
                      value={a.app_id}
                      keywords={[a.name, a.slug]}
                      data-checked={a.app_id === grantAppId}
                      onSelect={() => pickApp(a.app_id)}
                    >
                      {a.name} <code class="text-muted-foreground">{a.slug}</code>
                    </Command.Item>
                  {/each}
                </Command.Group>
              </Command.List>
            </Command.Root>
          </Popover.Content>
        </Popover.Root>
      </div>
      <div class="grid gap-2">
        <Label for="grant-resource">Resource</Label>
        <Select.Root
          type="single"
          value={resourceId}
          onValueChange={pickResource}
          disabled={editing}
          required
        >
          <Select.Trigger id="grant-resource" class="w-full">
            {selectedResource?.name ?? "Select a resource"}
          </Select.Trigger>
          <Select.Content>
            {#each app.resources as resource (resource.resource_id)}
              <Select.Item value={resource.resource_id} label={resource.name} />
            {/each}
          </Select.Content>
        </Select.Root>
      </div>
      <fieldset class="grid gap-3" disabled={!grantAppId || !resourceId}>
        <legend class="mb-2 text-sm font-medium">Access types</legend>
        {#each ACCESS_TYPES as t (t.value)}
          <div class="flex items-center gap-2">
            <Checkbox
              id={`grant-type-${t.value}`}
              checked={selected.includes(t.value)}
              onCheckedChange={(checked) => toggle(t.value, checked)}
              disabled={!grantAppId || !resourceId}
            />
            <Label for={`grant-type-${t.value}`} class="font-normal">{t.label}</Label>
          </div>
        {/each}
      </fieldset>
      <ErrorAlert error={save.error} />
      <Dialog.Footer>
        <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button
          type="submit"
          disabled={save.pending ||
            !grantAppId ||
            !resourceId ||
            (toCreate.length === 0 && toDelete.length === 0)}>Save</Button
        >
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>

<ConfirmDialog bind:request={confirming} />
