import rehypeSlug from 'rehype-slug';
 import adapter from '@sveltejs/adapter-static';
 import tailwindcss from '@tailwindcss/vite';
 import { mdsvex } from 'mdsvex';
 import { sveltekit } from '@sveltejs/kit/vite';
 import { defineConfig } from 'vite';

const base = process.env.BASE_PATH || '';

function legacyHeadingId(text: string) {
	return text
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/(^-|-$)/g, '');
}

interface HastNode {
	type: string;
	tagName?: string;
	properties?: Record<string, unknown>;
	children?: HastNode[];
	value?: string;
}

function headingText(node: HastNode): string {
	if (node.type === 'text') return node.value ?? '';
	return (node.children ?? []).map(headingText).join('');
}

function rehypeLegacyHeadingAliases() {
	return function (tree: HastNode) {
		const seen = new Set<string>();
		const headings: HastNode[] = [];
		const walk = (node: HastNode) => {
			if (node.type === 'element' && (node.tagName === 'h2' || node.tagName === 'h3')) {
				headings.push(node);
				const id = node.properties?.id;
				if (typeof id === 'string') seen.add(id);
			}
			for (const child of node.children ?? []) walk(child);
		};
		walk(tree);
		for (const heading of headings) {
			const id = heading.properties?.id;
			const legacy = legacyHeadingId(headingText(heading));
			if (typeof id !== 'string' || !legacy || legacy === id || seen.has(legacy)) continue;
			seen.add(legacy);
			heading.children = [
				{ type: 'element', tagName: 'span', properties: { id: legacy }, children: [] },
				...(heading.children ?? [])
			];
		}
	};
}

 // Markdown links share the deployment base used by Svelte navigation.
 function remarkBaseLinks() {
 	return function visit(node) {
 		if (['link', 'definition', 'image'].includes(node.type) &&
 			typeof node.url === 'string' && /^\/(?!\/)/.test(node.url)) {
			node.url = base + withTrailingSlash(node.url);
 		}
 		for (const child of node.children || []) visit(child);
 	};
 }

function withTrailingSlash(url: string) {
	const end = url.search(/[?#]/);
	const path = end === -1 ? url : url.slice(0, end);
	const rest = end === -1 ? '' : url.slice(end);
	if (path === '/' || path.endsWith('/')) return url;
	if (path.slice(path.lastIndexOf('/') + 1).includes('.')) return url;
	return path + '/' + rest;
}

export default defineConfig({
	plugins: [
		tailwindcss(),
		sveltekit({
			extensions: ['.svelte', '.md'],
			preprocess: [
				mdsvex({
					extensions: ['.md'],
					remarkPlugins: [remarkBaseLinks],
					rehypePlugins: [rehypeSlug, rehypeLegacyHeadingAliases]
				})
			],
			adapter: adapter({
				pages: 'build',
				assets: 'build',
				strict: true
			}),
			paths: {
				base,
				relative: false
			},
			prerender: {
				handleMissingId: 'fail'
			}
		})
	]
});
