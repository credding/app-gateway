<script lang="ts">
  import { page } from "$app/state";
  import MenuIcon from "@lucide/svelte/icons/menu";
  import { Button } from "#lib/components/ui/button/index.js";
  import * as DropdownMenu from "#lib/components/ui/dropdown-menu/index.js";
  import type { LayoutProps } from "./$types";

  let { children }: LayoutProps = $props();

  const links = [
    { href: "/dashboard", label: "Dashboard" },
    { href: "/apps", label: "Apps" },
    { href: "/catalog", label: "Catalog" },
  ];

  const isCurrent = (href: string) => page.url.pathname.startsWith(href);
</script>

<header class="border-b">
  <div class="mx-auto flex h-14 max-w-5xl items-center gap-4 px-6">
    <DropdownMenu.Root>
      <DropdownMenu.Trigger class="sm:hidden">
        {#snippet child({ props })}
          <Button {...props} variant="ghost" size="icon-sm" aria-label="Menu">
            <MenuIcon />
          </Button>
        {/snippet}
      </DropdownMenu.Trigger>
      <DropdownMenu.Content align="start" class="min-w-40">
        {#each links as link (link.href)}
          <DropdownMenu.Item>
            {#snippet child({ props })}
              <a
                {...props}
                href={link.href}
                aria-current={isCurrent(link.href) ? "page" : undefined}
                class="{props.class} aria-[current=page]:font-medium"
              >
                {link.label}
              </a>
            {/snippet}
          </DropdownMenu.Item>
        {/each}
      </DropdownMenu.Content>
    </DropdownMenu.Root>
    <span class="flex-1 font-semibold sm:flex-none">App Gateway</span>
    <nav class="hidden flex-1 gap-1 sm:flex">
      {#each links as link (link.href)}
        <Button
          variant="ghost"
          size="sm"
          href={link.href}
          aria-current={isCurrent(link.href) ? "page" : undefined}
        >
          {link.label}
        </Button>
      {/each}
    </nav>
    <form method="post" action="/api/auth/logout">
      <Button type="submit" variant="outline" size="sm">Log out</Button>
    </form>
  </div>
</header>

<main class="mx-auto max-w-5xl space-y-6 p-6">
  {@render children()}
</main>
