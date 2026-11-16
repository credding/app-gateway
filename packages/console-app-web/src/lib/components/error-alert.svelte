<script lang="ts">
  import * as Alert from "#lib/components/ui/alert/index.js";

  let { error }: { error: string | null } = $props();
</script>

{#if error}
  <Alert.Root variant="destructive">
    <Alert.Description>{error}</Alert.Description>
  </Alert.Root>
{/if}
