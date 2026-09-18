<script lang="ts">
	import { goto } from '$app/navigation';
	import { base } from '$app/paths';
	import { tick } from 'svelte';

	let { open = $bindable(false) }: { open: boolean } = $props();

	interface SubResult {
		url: string;
		title: string;
		excerpt: string;
	}

	interface GroupedResult {
		pageTitle: string;
		pageUrl: string;
		subResults: SubResult[];
	}

	let query = $state('');
	let groups = $state<GroupedResult[]>([]);
	let totalCount = $state(0);
	let activeIndex = $state(0);
	let loading = $state(false);
	let searchUnavailable = $state(false);
	let pagefind: any = null;
	let inputEl: HTMLInputElement | undefined = $state();
	let debounceTimer: ReturnType<typeof setTimeout> | undefined;

	const flatResults = $derived(
		groups.flatMap((g) => g.subResults.map((sr) => sr.url))
	);

	async function initPagefind() {
		if (pagefind) return;
		try {
			const path = `${base}/pagefind/pagefind.js`;
			pagefind = await import(/* @vite-ignore */ path);
		} catch {
			searchUnavailable = true;
		}
	}

	async function search(q: string) {
		if (!pagefind || !q.trim()) {
			groups = [];
			totalCount = 0;
			return;
		}
		loading = true;
		try {
			const response = await pagefind.search(q);
			totalCount = response.results.length;
			const items = await Promise.all(
				response.results.slice(0, 6).map(async (r: any) => {
					const data = await r.data();
					const pageTitle = data.meta?.title || data.url;
					const pageUrl = data.url;
					const subs: SubResult[] = (data.sub_results || []).slice(0, 3).map((sr: any) => ({
						url: sr.url,
						title: sr.title || pageTitle,
						excerpt: sr.excerpt || ''
					}));
					if (subs.length === 0) {
						subs.push({
							url: pageUrl,
							title: pageTitle,
							excerpt: data.excerpt || ''
						});
					}
					return { pageTitle, pageUrl, subResults: subs } as GroupedResult;
				})
			);
			groups = items;
			activeIndex = 0;
		} catch {
			groups = [];
			totalCount = 0;
		} finally {
			loading = false;
		}
	}

	function handleInput(e: Event) {
		const value = (e.target as HTMLInputElement).value;
		query = value;
		clearTimeout(debounceTimer);
		debounceTimer = setTimeout(() => search(value), 200);
	}

	function clearQuery() {
		query = '';
		groups = [];
		totalCount = 0;
		inputEl?.focus();
	}

	function navigate(url: string) {
		const path = url.replace(/\.html$/, '').replace(/index$/, '');
		goto(`${base}${path}`);
		close();
	}

	function close() {
		open = false;
		query = '';
		groups = [];
		totalCount = 0;
		activeIndex = 0;
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			activeIndex = Math.min(activeIndex + 1, flatResults.length - 1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			activeIndex = Math.max(activeIndex - 1, 0);
		} else if (e.key === 'Enter' && flatResults[activeIndex]) {
			e.preventDefault();
			navigate(flatResults[activeIndex]);
		} else if (e.key === 'Escape') {
			e.preventDefault();
			close();
		}
	}

	$effect(() => {
		if (open) {
			initPagefind();
			tick().then(() => inputEl?.focus());
		}
	});
</script>

{#if open}
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
	class="fixed inset-0 z-50 flex items-start justify-center pt-[12vh]"
	onkeydown={handleKeydown}
>
	<!-- Backdrop -->
	<button
		class="absolute inset-0 bg-foreground/20 backdrop-blur-sm"
		onclick={close}
		aria-label="Close search"
		tabindex="-1"
	></button>

	<!-- Modal -->
	<div
		role="dialog"
		aria-modal="true"
		aria-label="Search documentation"
		class="relative z-10 mx-4 flex w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-border/80 bg-background/95 shadow-2xl backdrop-blur-xl"
	>
		<!-- Search input -->
		<div class="flex items-center gap-3 px-5 py-4">
			<svg class="h-5 w-5 shrink-0 text-text-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
				<path stroke-linecap="round" stroke-linejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
			</svg>
			<input
				bind:this={inputEl}
				type="text"
				placeholder="Search documentation..."
				value={query}
				oninput={handleInput}
				class="flex-1 bg-transparent text-lg text-foreground outline-none placeholder:text-text-muted/60"
			/>
			{#if query}
				<button onclick={clearQuery} class="rounded-md p-1 text-text-muted transition-colors hover:text-foreground" aria-label="Clear search">
					<svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
						<path stroke-linecap="round" stroke-linejoin="round" d="M6 18 18 6M6 6l12 12" />
					</svg>
				</button>
			{/if}
		</div>

		<!-- Results count -->
		{#if query && !loading && !searchUnavailable}
			<div class="border-t border-border/40 px-5 py-2 text-xs text-text-muted">
				{totalCount} result{totalCount !== 1 ? 's' : ''} for <span class="font-medium text-foreground">{query}</span>
			</div>
		{/if}

		<!-- Results -->
		<div class="max-h-[55vh] overflow-y-auto border-t border-border/40 px-3 py-3">
			{#if searchUnavailable}
				<div class="px-4 py-8 text-center text-sm text-text-muted">
					Search is available after building.<br />
					Run <code class="rounded bg-secondary px-1.5 py-0.5 text-xs">bun run build</code> to enable.
				</div>
			{:else if loading}
				<div class="px-4 py-8 text-center text-sm text-text-muted">Searching...</div>
			{:else if query && groups.length === 0}
				<div class="px-4 py-8 text-center text-sm text-text-muted">
					No results for "<span class="font-medium text-foreground">{query}</span>"
				</div>
			{:else if groups.length > 0}
				<div class="space-y-3">
					{#each groups as group}
						<div class="overflow-hidden rounded-xl border border-border/50 bg-secondary/30">
							<!-- Page title -->
							<div class="px-4 py-2.5">
								<span class="font-display text-sm font-bold text-foreground">{group.pageTitle}</span>
							</div>
							<!-- Sub-results -->
							<div class="divide-y divide-border/30">
								{#each group.subResults as sub}
									{@const flatIdx = flatResults.indexOf(sub.url)}
									{@const subPath = sub.url.replace(/\.html$/, '').replace(/index$/, '')}
									<a
										href="{base}{subPath}"
										class="block px-4 py-2.5 no-underline transition-colors {flatIdx === activeIndex
											? 'bg-primary/10'
											: 'hover:bg-secondary/60'}"
										onclick={(e) => { e.preventDefault(); navigate(sub.url); }}
										onmouseenter={() => (activeIndex = flatIdx)}
									>
										<div class="text-sm font-semibold text-foreground/90">{sub.title}</div>
										{#if sub.excerpt}
											<div class="mt-0.5 line-clamp-1 text-xs text-text-muted">
												{@html sub.excerpt}
											</div>
										{/if}
									</a>
								{/each}
							</div>
						</div>
					{/each}
				</div>
			{:else}
				<div class="px-4 py-8 text-center text-sm text-text-muted">
					Type to search documentation
				</div>
			{/if}
		</div>

		<!-- Footer -->
		<div class="flex items-center justify-between border-t border-border/40 px-5 py-2.5 text-[11px] text-text-muted">
			<div class="flex items-center gap-3">
				<span><kbd class="rounded border border-border/60 px-1 py-0.5">↑↓</kbd> navigate</span>
				<span><kbd class="rounded border border-border/60 px-1 py-0.5">↵</kbd> open</span>
				<span><kbd class="rounded border border-border/60 px-1 py-0.5">esc</kbd> close</span>
			</div>
			<span>Powered by Pagefind</span>
		</div>
	</div>
</div>
{/if}
