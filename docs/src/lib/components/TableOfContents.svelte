<script lang="ts">
	import { page } from '$app/stores';
	import { useIntersectionObserver } from 'runed';

	interface TocItem {
		id: string;
		text: string;
		level: number;
	}

	let items = $state<TocItem[]>([]);
	let activeId = $state('');
	let headingElements = $state<HTMLElement[]>([]);

	$effect(() => {
		$page.url.pathname;

		requestAnimationFrame(() => {
			const article = document.querySelector('article');
			if (!article) return;

			const headings = article.querySelectorAll<HTMLElement>('h2, h3');
			const newItems: TocItem[] = [];
			const newElements: HTMLElement[] = [];

			headings.forEach((heading) => {
				if (!heading.id) {
					heading.id =
						heading.textContent
							?.toLowerCase()
							.replace(/[^a-z0-9]+/g, '-')
							.replace(/(^-|-$)/g, '') ?? '';
				}
				newItems.push({
					id: heading.id,
					text: heading.textContent ?? '',
					level: parseInt(heading.tagName[1])
				});
				newElements.push(heading);
			});

			items = newItems;
			headingElements = newElements;
		});
	});

	useIntersectionObserver(
		() => headingElements,
		(entries) => {
			for (const entry of entries) {
				if (entry.isIntersecting) {
					activeId = (entry.target as HTMLElement).id;
					break;
				}
			}
		},
		{ rootMargin: '-80px 0px -60% 0px', threshold: 0 }
	);
</script>

{#if items.length > 0}
	<nav class="space-y-1 text-sm" aria-label="Table of contents">
		<h4
			class="font-display mb-3 text-xs font-semibold tracking-wider text-gray-500 uppercase dark:text-gray-400"
		>
			On this page
		</h4>
		{#each items as item}
			<a
				href="#{item.id}"
				class="block border-l-2 py-1 transition-colors {item.level === 3
					? 'pl-5'
					: 'pl-3'} {activeId === item.id
					? 'border-primary text-primary font-medium dark:border-primary-light dark:text-primary-light'
					: 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-400 dark:hover:border-gray-600 dark:hover:text-gray-300'}"
			>
				{item.text}
			</a>
		{/each}
	</nav>
{/if}
