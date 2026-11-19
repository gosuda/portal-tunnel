<script lang="ts">
	import { resolve } from '$app/paths';
	import type { FlatNavItem } from '#lib/nav';

	interface Props {
		prev: FlatNavItem | null;
		next: FlatNavItem | null;
	}

	let { prev, next }: Props = $props();
</script>

{#if prev || next}
	<nav class="not-prose mt-12 grid grid-cols-1 gap-4 {prev && next ? 'sm:grid-cols-2' : ''}" aria-label="Page navigation">
		{#if prev}
			<a
				href={resolve(prev.href)}
				class="group flex items-center gap-4 rounded-lg border border-border/70 px-5 py-5 transition-colors hover:border-primary/40"
			>
				<svg
					class="size-5 shrink-0 text-text-muted transition-transform group-hover:-translate-x-0.5"
					xmlns="http://www.w3.org/2000/svg"
					fill="none"
					viewBox="0 0 24 24"
					stroke-width="2"
					stroke="currentColor"
					aria-hidden="true"
				>
					<path stroke-linecap="round" stroke-linejoin="round" d="M15.75 19.5 8.25 12l7.5-7.5" />
				</svg>
				<div class="min-w-0">
					<span class="block text-sm font-medium text-text-muted">Previous</span>
					<span class="block text-sm text-text-muted">{prev.section}</span>
					<span class="block truncate font-display text-base font-semibold text-foreground">
						{prev.title}
					</span>
				</div>
			</a>
		{/if}

		{#if next}
			<a
				href={resolve(next.href)}
				class="group flex items-center justify-end gap-4 rounded-lg border border-border/70 px-5 py-5 text-right transition-colors hover:border-primary/40"
			>
				<div class="min-w-0">
					<span class="block text-sm font-medium text-text-muted">Next</span>
					<span class="block text-sm text-text-muted">{next.section}</span>
					<span class="block truncate font-display text-base font-semibold text-foreground">
						{next.title}
					</span>
				</div>
				<svg
					class="size-5 shrink-0 text-text-muted transition-transform group-hover:translate-x-0.5"
					xmlns="http://www.w3.org/2000/svg"
					fill="none"
					viewBox="0 0 24 24"
					stroke-width="2"
					stroke="currentColor"
					aria-hidden="true"
				>
					<path stroke-linecap="round" stroke-linejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5" />
				</svg>
			</a>
		{/if}
	</nav>
{/if}
