<script lang="ts">
	import { onMount } from 'svelte';
	import { mode } from 'mode-watcher';

	let { code }: { code: string } = $props();

	let container: HTMLDivElement;
	let rendered = $state(false);

	async function renderDiagram() {
		if (!container) return;
		try {
			const { default: mermaid } = await import('mermaid');
			const theme = mode.current === 'dark' ? 'dark' : 'default';
			mermaid.initialize({
				startOnLoad: false,
				theme,
				fontFamily: 'Open Sans, sans-serif'
			});
			const id = `mermaid-${Math.random().toString(36).slice(2, 9)}`;
			const { svg } = await mermaid.render(id, code);
			container.innerHTML = svg;
			rendered = true;
		} catch (e) {
			console.error('[Mermaid] render failed:', e);
			container.innerHTML = `<pre class="text-sm text-red-500">Failed to render diagram</pre>`;
		}
	}

	onMount(() => {
		renderDiagram();
	});

	$effect(() => {
		const _ = mode.current;
		if (rendered) {
			renderDiagram();
		}
	});
</script>

<div class="not-prose my-6">
	<div bind:this={container} class="flex justify-center overflow-x-auto">
		<noscript>
			<pre class="rounded-lg border border-border bg-secondary p-4 text-sm"><code>{code}</code></pre>
		</noscript>
	</div>
</div>
