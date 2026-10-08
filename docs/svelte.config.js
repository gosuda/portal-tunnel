import adapter from '@sveltejs/adapter-static';
import { mdsvex } from 'mdsvex';

const base = process.env.BASE_PATH || '';

// Markdown links share the deployment base used by Svelte navigation.
function remarkBaseLinks() {
	return function visit(node) {
		if (['link', 'definition', 'image'].includes(node.type) &&
			typeof node.url === 'string' && /^\/(?!\/)/.test(node.url)) {
			node.url = base + node.url;
		}
		for (const child of node.children || []) visit(child);
	};
}

/** @type {import('@sveltejs/kit').Config} */
const config = {
	extensions: ['.svelte', '.md'],
	preprocess: [
		mdsvex({
			extensions: ['.md'],
			remarkPlugins: [remarkBaseLinks]
		})
	],
	kit: {
		adapter: adapter({
			pages: 'build',
			assets: 'build',
			strict: true
		}),
		paths: {
			base
		},
		prerender: {
			handleMissingId: 'warn'
		}
	}
};

export default config;
