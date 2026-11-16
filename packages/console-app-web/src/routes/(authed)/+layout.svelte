<script lang="ts">
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();
</script>

<header>
	<p><strong>App Gateway</strong></p>
	<nav>
		<ul>
			<li><a href="/dashboard">Dashboard</a></li>
			<li><a href="/apps">Apps</a></li>
		</ul>
		<form method="post" action="/api/auth/logout">
			<button type="submit">Log out</button>
		</form>
	</nav>
</header>

{@render children()}
