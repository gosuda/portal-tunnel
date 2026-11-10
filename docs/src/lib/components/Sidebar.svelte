<script lang="ts">
	import { page } from '$app/stores';
	import { base } from '$app/paths';
	import type { NavSection } from '$lib/nav';

	let { sections }: { sections: NavSection[] } = $props();

	const currentPath = $derived($page.url.pathname);

	let userToggles: Record<number, boolean | null> = $state({});

	function isItemActive(href: string): boolean {
		return (
			currentPath === `${base}${href}/` ||
			currentPath === `${base}${href}` ||
			currentPath.startsWith(`${base}${href}/`)
		);
	}

	function sectionHasActiveChild(sectionIndex: number): boolean {
		return sections[sectionIndex].items.some((item) => isItemActive(item.href));
	}

	function isSectionOpen(index: number): boolean {
		const userToggle = userToggles[index];
		if (userToggle !== null && userToggle !== undefined) {
			return userToggle;
		}
		return sectionHasActiveChild(index) || (sections[index].defaultOpen ?? false);
	}

	function toggleSection(index: number) {
		const currentlyOpen = isSectionOpen(index);
		userToggles[index] = !currentlyOpen;
	}

	$effect(() => {
		void currentPath;
		for (let i = 0; i < sections.length; i++) {
			if (sectionHasActiveChild(i)) {
				userToggles[i] = true;
			}
		}
	});
</script>

<nav class="space-y-1" aria-label="Documentation">
	{#each sections as section, index (section.title)}
		{@const isOpen = isSectionOpen(index)}
		<div>
			<button
				type="button"
				class="flex w-full cursor-pointer items-center justify-between rounded-md px-1 py-2 font-display text-xs font-semibold tracking-wider text-text-muted uppercase transition-colors hover:text-foreground"
				aria-expanded={isOpen}
				onclick={() => toggleSection(index)}
			>
				<span class="flex items-center gap-2">
					{section.title}
					{#if section.badge}
						<span
							class="rounded-full border border-amber-400/25 bg-amber-400/15 px-1.5 py-0.5 text-[10px] font-medium tracking-normal normal-case text-amber-600 dark:text-amber-400"
						>
							{section.badge}
						</span>
					{/if}
				</span>
				<svg
					class="h-3.5 w-3.5 shrink-0 transition-transform duration-200 {isOpen
						? 'rotate-90'
						: 'rotate-0'}"
					viewBox="0 0 16 16"
					fill="currentColor"
					aria-hidden="true"
				>
					<path
						d="M6.22 4.22a.75.75 0 0 1 1.06 0l3.25 3.25a.75.75 0 0 1 0 1.06l-3.25 3.25a.75.75 0 0 1-1.06-1.06L8.94 8 6.22 5.28a.75.75 0 0 1 0-1.06Z"
					/>
				</svg>
			</button>
			<div
				class="grid transition-[grid-template-rows] duration-200 ease-in-out {isOpen
					? 'grid-rows-[1fr]'
					: 'grid-rows-[0fr]'}"
			>
				<ul class="overflow-hidden">
					{#each section.items as item (item.href)}
						{@const isActive = isItemActive(item.href)}
						<li>
							<a
								href="{base}{item.href}"
								class="block rounded-lg px-3 py-2 text-sm transition-colors {isActive
									? 'bg-primary/10 font-medium text-primary dark:bg-primary-light/15 dark:text-primary-light'
									: 'text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-white/6'}"
								aria-current={isActive ? 'page' : undefined}
							>
								{item.title}
							</a>
						</li>
					{/each}
				</ul>
			</div>
		</div>
	{/each}
</nav>
