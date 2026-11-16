<script lang="ts">
  import { Button } from "#lib/components/ui/button/index.js";
  import * as Card from "#lib/components/ui/card/index.js";
</script>

<main class="flex min-h-svh items-center justify-center p-6">
  <Card.Root class="w-full max-w-sm">
    <Card.Header>
      <Card.Title>App Gateway Console</Card.Title>
      <Card.Description>Manage your apps, clients, and resources.</Card.Description>
    </Card.Header>
    <Card.Footer>
      <Button class="w-full" href="/api/auth/login" data-sveltekit-reload>Log in</Button>
    </Card.Footer>
  </Card.Root>
</main>
