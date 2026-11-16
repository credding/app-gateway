<script lang="ts">
  import { Button } from "#lib/components/ui/button/index.js";
  import * as Card from "#lib/components/ui/card/index.js";
</script>

<svelte:head>
  <title>Dashboard · Console</title>
</svelte:head>

<h1 class="text-2xl font-semibold">Dashboard</h1>

<Card.Root>
  <Card.Header>
    <Card.Title>Apps</Card.Title>
    <Card.Description>Configure identity providers, clients, and resources.</Card.Description>
    <Card.Action>
      <Button variant="outline" href="/apps">Manage apps</Button>
    </Card.Action>
  </Card.Header>
</Card.Root>

<Card.Root>
  <Card.Header>
    <Card.Title>Catalog</Card.Title>
    <Card.Description>Browse apps and the resources they provide.</Card.Description>
    <Card.Action>
      <Button variant="outline" href="/catalog">Browse catalog</Button>
    </Card.Action>
  </Card.Header>
</Card.Root>
