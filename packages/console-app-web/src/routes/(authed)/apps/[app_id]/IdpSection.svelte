<script lang="ts">
  import { invalidate } from "$app/navigation";
  import CheckIcon from "@lucide/svelte/icons/check";
  import CopyIcon from "@lucide/svelte/icons/copy";
  import EllipsisIcon from "@lucide/svelte/icons/ellipsis";
  import EyeIcon from "@lucide/svelte/icons/eye";
  import EyeOffIcon from "@lucide/svelte/icons/eye-off";
  import { deleteAppIdp, putAppIdp, type AppIdp, type AppListItem, type Idp } from "#lib/api.js";
  import { action } from "#lib/action.svelte.js";
  import ConfirmDialog, { type ConfirmRequest } from "#lib/components/confirm-dialog.svelte";
  import ErrorAlert from "#lib/components/error-alert.svelte";
  import { Button } from "#lib/components/ui/button/index.js";
  import * as Card from "#lib/components/ui/card/index.js";
  import * as Dialog from "#lib/components/ui/dialog/index.js";
  import * as DropdownMenu from "#lib/components/ui/dropdown-menu/index.js";
  import { Input } from "#lib/components/ui/input/index.js";
  import { Label } from "#lib/components/ui/label/index.js";
  import * as Select from "#lib/components/ui/select/index.js";
  import * as Table from "#lib/components/ui/table/index.js";

  let { app, idps }: { app: AppListItem; idps: Idp[] } = $props();

  let available = $derived(idps.filter((idp) => !app.idps.some((a) => a.idp_id === idp.idp_id)));

  let open = $state(false);
  // The IdP being edited, or null when adding a new one.
  let editing = $state<AppIdp | null>(null);
  let idpId = $state("");
  let clientId = $state("");
  let clientSecret = $state("");
  let confirming = $state<ConfirmRequest | null>(null);
  const save = action();
  const remove = action();

  let selectedName = $derived(available.find((idp) => idp.idp_id === idpId)?.name);
  let redirectUri = $derived(idps.find((idp) => idp.idp_id === idpId)?.redirect_uri);
  let copiedUri = $state<string | null>(null);
  let showSecret = $state(false);

  async function copyRedirectUri() {
    if (redirectUri) {
      await navigator.clipboard.writeText(redirectUri);
      copiedUri = redirectUri;
    }
  }

  function startAdd() {
    idpId = available[0]?.idp_id ?? "";
    clientId = "";
    clientSecret = "";
    editing = null;
    copiedUri = null;
    showSecret = false;
    save.clear();
    open = true;
  }

  function startEdit(appIdp: AppIdp) {
    idpId = appIdp.idp_id;
    clientId = appIdp.client_id;
    clientSecret = "";
    editing = appIdp;
    copiedUri = null;
    showSecret = false;
    save.clear();
    open = true;
  }

  async function onsubmit(event: SubmitEvent) {
    event.preventDefault();
    const saved = await save.run(() =>
      putAppIdp(app.app_id, idpId, { client_id: clientId, client_secret: clientSecret }),
    );
    if (saved) {
      open = false;
      await invalidate("app:apps");
    }
  }

  function onRemove(appIdp: AppIdp) {
    confirming = {
      title: `Remove "${appIdp.name}"?`,
      description:
        "Users will no longer be able to sign in to this app with this identity provider.",
      action: "Remove",
      onconfirm: async () => {
        const removed = await remove.run(async () => {
          await deleteAppIdp(app.app_id, appIdp.idp_id);
          return true;
        });
        if (removed) {
          await invalidate("app:apps");
        }
      },
    };
  }
</script>

<Card.Root>
  <Card.Header>
    <Card.Title>Identity providers</Card.Title>
    {#if available.length > 0}
      <Card.Action>
        <Button variant="outline" size="sm" onclick={startAdd}>Add identity provider</Button>
      </Card.Action>
    {/if}
  </Card.Header>
  <Card.Content class="space-y-4">
    <ErrorAlert error={remove.error} />
    {#if app.idps.length === 0}
      <p class="text-sm text-muted-foreground">No identity providers configured.</p>
    {:else}
      <Table.Root>
        <Table.Header>
          <Table.Row>
            <Table.Head>Name</Table.Head>
            <Table.Head>Client ID</Table.Head>
            <Table.Head class="w-0"><span class="sr-only">Actions</span></Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each app.idps as appIdp (appIdp.idp_id)}
            <Table.Row>
              <Table.Cell>{appIdp.name}</Table.Cell>
              <Table.Cell><code>{appIdp.client_id}</code></Table.Cell>
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
                    <DropdownMenu.Item onSelect={() => startEdit(appIdp)}>Edit</DropdownMenu.Item>
                    <DropdownMenu.Item
                      variant="destructive"
                      disabled={remove.pending}
                      onSelect={() => onRemove(appIdp)}
                    >
                      Remove
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
        <Dialog.Title>{editing ? `Edit ${editing.name}` : "Add identity provider"}</Dialog.Title>
        <Dialog.Description>
          Create an OAuth client at the identity provider, then paste its client ID and secret here.
        </Dialog.Description>
      </Dialog.Header>
      {#if !editing}
        <div class="grid gap-2">
          <Label for="idp-select">Identity provider</Label>
          <Select.Root type="single" bind:value={idpId} required>
            <Select.Trigger id="idp-select" class="w-full">
              {selectedName ?? "Select an identity provider"}
            </Select.Trigger>
            <Select.Content>
              {#each available as idp (idp.idp_id)}
                <Select.Item value={idp.idp_id} label={idp.name} />
              {/each}
            </Select.Content>
          </Select.Root>
        </div>
      {/if}
      {#if redirectUri}
        <div class="grid gap-2">
          <Label for="idp-redirect-uri">Redirect URL</Label>
          <div class="flex gap-2">
            <Input id="idp-redirect-uri" readonly value={redirectUri} />
            <Button
              variant="outline"
              size="icon"
              aria-label="Copy redirect URL"
              onclick={copyRedirectUri}
            >
              {#if copiedUri === redirectUri}<CheckIcon />{:else}<CopyIcon />{/if}
            </Button>
          </div>
          <p class="text-sm text-muted-foreground">Use this as the OAuth client's redirect URL.</p>
        </div>
      {/if}
      <div class="grid gap-2">
        <Label for="idp-client-id">Client ID</Label>
        <Input id="idp-client-id" bind:value={clientId} required autocomplete="off" />
      </div>
      <div class="grid gap-2">
        <Label for="idp-client-secret">Client secret</Label>
        <!-- A masked text input rather than type="password", so password managers
             don't offer to fill or save the secret. -->
        <div class="flex gap-2">
          <Input
            id="idp-client-secret"
            class={showSecret ? undefined : "[-webkit-text-security:disc]"}
            bind:value={clientSecret}
            required
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
          />
          <Button
            variant="outline"
            size="icon"
            aria-label={showSecret ? "Hide client secret" : "Show client secret"}
            aria-pressed={showSecret}
            onclick={() => (showSecret = !showSecret)}
          >
            {#if showSecret}<EyeOffIcon />{:else}<EyeIcon />{/if}
          </Button>
        </div>
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
