export function copyCode(node: HTMLElement) {
	const wrappers: HTMLDivElement[] = [];

	function addButtons() {
		removeButtons();

		const pres = node.querySelectorAll('pre');
		for (const pre of pres) {
			if (pre.parentElement?.hasAttribute('data-copy-wrapper')) continue;

			const wrapper = document.createElement('div');
			wrapper.setAttribute('data-copy-wrapper', '');
			wrapper.style.position = 'relative';
			pre.parentNode?.insertBefore(wrapper, pre);
			wrapper.appendChild(pre);

			const btn = document.createElement('button');
			btn.setAttribute('data-copy-btn', '');
			btn.setAttribute('aria-label', 'Copy code');
			btn.setAttribute('title', 'Copy');
			btn.className =
				'absolute top-2.5 right-2.5 z-10 inline-flex h-7 w-7 items-center justify-center rounded-md text-gray-400 transition-colors hover:text-gray-200';
			btn.innerHTML = `<svg class="h-[22px] w-[22px]" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>`;

			btn.addEventListener('click', async () => {
				const code = pre.querySelector('code');
				const text = code?.textContent ?? pre.textContent ?? '';
				try {
					await navigator.clipboard.writeText(text);
					btn.innerHTML = `<svg class="h-[22px] w-[22px] text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>`;
					btn.setAttribute('title', 'Copied!');
					setTimeout(() => {
						btn.innerHTML = `<svg class="h-[22px] w-[22px]" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>`;
						btn.setAttribute('title', 'Copy');
					}, 2000);
				} catch {
					// Fallback: silent fail
				}
			});

			wrapper.appendChild(btn);
			wrappers.push(wrapper);
		}
	}

	function removeButtons() {
		for (const wrapper of wrappers) {
			const pre = wrapper.querySelector('pre');
			if (pre && wrapper.parentNode) {
				wrapper.parentNode.insertBefore(pre, wrapper);
				wrapper.remove();
			}
		}
		wrappers.length = 0;
	}

	requestAnimationFrame(addButtons);

	return {
		update() {
			requestAnimationFrame(addButtons);
		},
		destroy() {
			removeButtons();
		}
	};
}
