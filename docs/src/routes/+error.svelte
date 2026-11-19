<script lang="ts">
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
</script>

<div class="py-16 text-center">
	<h1 class="text-4xl font-bold text-gray-900 dark:text-white">{page.status}</h1>
	<p class="mt-4 text-lg text-gray-600 dark:text-gray-400">
		{page.error?.message || 'Page not found'}
	</p>
	<a
		href={resolve('/')}
		class="mt-8 inline-block rounded-lg bg-blue-600 px-6 py-3 text-sm font-medium text-white hover:bg-blue-700"
	>
		Back to Home
	</a>
</div>
