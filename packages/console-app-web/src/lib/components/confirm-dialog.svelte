<script lang="ts" module>
	export interface ConfirmRequest {
		title: string;
		description: string;
		action: string;
		onconfirm: () => unknown;
	}
</script>

<script lang="ts">
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';

	/** Set to a request to open the dialog; it's reset to null when closed. */
	let { request = $bindable() }: { request: ConfirmRequest | null } = $props();

	// Keep showing the last request while the dialog animates closed.
	let last: ConfirmRequest | null = null;
	let shown = $derived.by(() => (last = request ?? last));

	function confirm() {
		const current = request;
		request = null;
		current?.onconfirm();
	}
</script>

<AlertDialog.Root
	bind:open={() => request !== null, (open) => {
		if (!open) request = null;
	}}
>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>{shown?.title}</AlertDialog.Title>
			<AlertDialog.Description>{shown?.description}</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action variant="destructive" onclick={confirm}>{shown?.action}</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
