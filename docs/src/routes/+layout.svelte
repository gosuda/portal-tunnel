<script lang="ts">
	import { base } from '$app/paths';
	import { page } from '$app/stores';
	import { ModeWatcher } from 'mode-watcher';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';
	import MobileNav from '$lib/components/MobileNav.svelte';
	import TableOfContents from '$lib/components/TableOfContents.svelte';
	import PrevNextNav from '$lib/components/PrevNextNav.svelte';
	import { getPrevNext, guidesNavigation, referencesNavigation, isReferencePage } from '$lib/nav';
	import SearchButton from '$lib/components/SearchButton.svelte';
	import SearchModal from '$lib/components/SearchModal.svelte';
	import { copyCode } from '$lib/actions/copy-code';
	import { useEventListener } from 'runed';
	import '../app.css';

	let { children } = $props();
	let mobileNavOpen = $state(false);
	let searchOpen = $state(false);

	useEventListener(
		() => (typeof window !== 'undefined' ? window : null),
		'keydown',
		(e: Event) => {
			const ke = e as KeyboardEvent;
			if ((ke.metaKey || ke.ctrlKey) && ke.key === 'k') {
				ke.preventDefault();
				searchOpen = !searchOpen;
			}
		}
	);

	const isLandingPage = $derived(
		$page.url.pathname === `${base}/` || $page.url.pathname === base || $page.url.pathname === '/'
	);

	const prevNext = $derived(getPrevNext($page.url.pathname, base));
	const isReference = $derived(isReferencePage($page.url.pathname, base));
	const sidebarSections = $derived(isReference ? referencesNavigation : guidesNavigation);
</script>

<ModeWatcher defaultMode="system" />
<SearchModal bind:open={searchOpen} />

<div class="min-h-screen">
	<!-- Header — relay-style with glassmorphism for docs -->
	<header
		class="sticky top-0 z-30 w-full bg-background/95 py-5 backdrop-blur"
	>
		<div class="flex w-full items-center gap-4 px-6 py-2 sm:px-8 lg:px-10">
			{#if !isLandingPage}
			<!-- Mobile menu button (doc pages only) -->
			<button
				class="rounded-lg p-1.5 text-gray-500 hover:bg-gray-100 lg:hidden dark:text-gray-400 dark:hover:bg-white/8"
				onclick={() => (mobileNavOpen = true)}
				aria-label="Open navigation"
			>
				<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M4 6h16M4 12h16M4 18h16"
					/>
				</svg>
			</button>
			{/if}

			<!-- Logo -->
			<a href="{base}/" class="flex items-center gap-2">
				<div class="flex h-10 w-10 shrink-0 items-center justify-center">
					<svg
						xmlns="http://www.w3.org/2000/svg"
						width="24"
						height="24"
						viewBox="0 0 906.26 1457.543"
						class="h-6 w-6 text-primary"
					>
						<path
							fill="currentColor"
							d="M254.854 137.158c-34.46 84.407-88.363 149.39-110.934 245.675 90.926-187.569 308.397-483.654 554.729-348.685 135.487 74.216 194.878 270.78 206.058 467.566 21.924 385.996-190.977 853.604-467.585 943.057-174.879 56.543-307.375-86.447-364.527-198.115-176.498-344.82 2.041-910.077 182.259-1109.498zm198.13 7.918C202.61 280.257 4.622 968.542 207.322 1270.414c51.713 77.029 194.535 160.648 285.294 71.318-209.061 31.529-288.389-176.143-301.145-340.765 31.411 147.743 139.396 326.12 309.075 253.588 251.957-107.723 376.778-648.46 269.433-966.817 22.394 134.616 15.572 317.711-47.551 412.087 86.655-230.615 7.903-704.478-269.444-554.749z"
						/>
					</svg>
				</div>
				<span class="font-display text-xl font-extrabold tracking-tight text-foreground sm:text-2xl">
					PORTAL
				</span>
				<span class="inline-flex h-6 items-center rounded-full bg-secondary px-2.5 text-xs font-semibold text-text-muted">v2</span>
			</a>

			<SearchButton onclick={() => (searchOpen = true)} />

			<div class="flex-1"></div>

			<!-- Nav links (hidden on mobile, visible xl) -->
			<nav class="hidden items-center gap-6 text-base font-semibold text-gray-500 xl:flex dark:text-gray-400">
				<a href="{base}/what-is-portal" class="transition-colors {!isLandingPage && !isReference ? 'text-foreground' : 'hover:text-gray-900 dark:hover:text-white'}">
					Guides
				</a>
				<a href="{base}/cli-reference" class="transition-colors {isReference ? 'text-foreground' : 'hover:text-gray-900 dark:hover:text-white'}">
					References
				</a>
			</nav>

			<!-- GitHub icon button -->
			<a
				href="https://github.com/gosuda/portal-tunnel"
				target="_blank"
				rel="noopener noreferrer"
				class="inline-flex h-12 w-12 shrink-0 items-center justify-center rounded-full border border-border/70 bg-background/90 text-foreground shadow-sm transition-all hover:-translate-y-0.5 hover:border-primary/40 hover:text-primary"
				aria-label="View source on GitHub"
			>
				<svg height="22" width="22" viewBox="0 0 24 24" fill="currentColor" class="opacity-85 transition-opacity hover:opacity-100">
					<path
						d="M12 1C5.923 1 1 5.923 1 12c0 4.867 3.149 8.979 7.521 10.436.55.096.756-.233.756-.522 0-.262-.013-1.128-.013-2.049-2.764.509-3.479-.674-3.699-1.292-.124-.317-.66-1.293-1.127-1.554-.385-.207-.936-.715-.014-.729.866-.014 1.485.797 1.691 1.128.99 1.663 2.571 1.196 3.204.907.096-.715.385-1.196.701-1.471-2.448-.275-5.005-1.224-5.005-5.432 0-1.196.426-2.186 1.128-2.956-.111-.275-.496-1.402.11-2.915 0 0 .921-.288 3.024 1.128a10.193 10.193 0 0 1 2.75-.371c.936 0 1.871.123 2.75.371 2.104-1.43 3.025-1.128 3.025-1.128.605 1.513.221 2.64.111 2.915.701.77 1.127 1.747 1.127 2.956 0 4.222-2.571 5.157-5.019 5.432.399.344.743 1.004.743 2.035 0 1.471-.014 2.654-.014 3.025 0 .289.206.632.756.522C19.851 20.979 23 16.854 23 12c0-6.077-4.922-11-11-11Z"
					/>
				</svg>
			</a>

			<ThemeToggle />
		</div>
	</header>

	{#if !isLandingPage}
	<MobileNav bind:open={mobileNavOpen} sections={sidebarSections} />
	{/if}

	{#if isLandingPage}
	<!-- Landing page: max-width container with side borders (matches React frontend) -->
	<div class="mx-auto flex w-full max-w-6xl flex-1 flex-col border-x border-border/80">
		<main class="px-4 pt-6 pb-8 sm:px-6 sm:pb-10 md:px-8">
			{@render children()}
		</main>
	</div>
	<footer class="w-full border-t bg-secondary/35">
		<div class="flex w-full flex-col gap-6 px-6 py-8 sm:px-8 md:flex-row md:items-end md:justify-between lg:px-10">
			<div class="space-y-1.5">
				<a href="{base}/" class="inline-block text-lg font-bold tracking-tight text-foreground transition-colors hover:text-primary">
					PORTAL
				</a>
				<p class="text-sm text-text-muted">
					Public relay index and localhost tunnel launcher.
				</p>
			</div>
			<nav aria-label="Footer" class="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-text-muted md:justify-end">
				<a href="{base}/getting-started" class="transition-colors hover:text-foreground">Docs</a>
				<a href="https://github.com/gosuda/portal-tunnel" target="_blank" rel="noopener noreferrer" class="transition-colors hover:text-foreground">Source</a>
			</nav>
		</div>
	</footer>
	{:else}
	<!-- Doc pages: sidebars + prose -->
	<div class="mx-auto max-w-[90rem] lg:flex">
		<aside class="hidden w-64 shrink-0 border-r border-border lg:block">
			<div class="sticky top-[var(--header-h)] h-[calc(100vh-var(--header-h))] overflow-y-auto p-6">
				<Sidebar sections={sidebarSections} />
			</div>
		</aside>

		<main class="min-w-0 flex-1 px-4 py-8 lg:px-8">
			<aside role="note" data-disclaimer class="mx-auto mb-6 max-w-3xl rounded-xl border border-primary/20 bg-primary/[0.08] px-4 py-3 text-sm font-medium text-foreground/70 shadow-sm backdrop-blur-sm">
				This documentation is under active development. Some pages may be incomplete or change without notice.
			</aside>
			{#key $page.url.pathname}
			<article use:copyCode data-pagefind-body class="prose prose-gray dark:prose-invert mx-auto max-w-3xl">
				{@render children()}
			</article>
			{/key}
			<div class="mx-auto max-w-3xl">
				<PrevNextNav prev={prevNext.prev} next={prevNext.next} />
			</div>
		</main>

		<aside class="hidden w-56 shrink-0 border-l border-border xl:block">
			<div class="sticky top-[var(--header-h)] h-[calc(100vh-var(--header-h))] overflow-y-auto py-8 px-4">
				<TableOfContents />
			</div>
		</aside>
	</div>
	{/if}
</div>
