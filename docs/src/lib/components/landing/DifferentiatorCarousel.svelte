<script lang="ts">
	import { onMount, tick } from 'svelte';

	const cards = [
		{
			key: 'login',
			title: 'No Login',
			description: 'Run the command immediately without accounts or auth flows.'
		},
		{
			key: 'billing',
			title: 'No Billing',
			description: 'No credit card, no plan gate, and no billing step before go-live.'
		},
		{
			key: 'cloud',
			title: 'No Cloud SaaS',
			description: 'No dashboard, region picker, or managed cloud setup to get started.'
		},
		{
			key: 'permissionless',
			title: 'Permissionless',
			description:
				'Use the public registry or attach your own relay. Each operator sets its approval policy.'
		}
	] as const;

	const cardCount = cards.length;
	const loopBoundaryIndex = cardCount + 1;
	const transitionDurationMs = 700;
	const slideGap = 16;

	const carouselSlides = [cards[cardCount - 1], ...cards, cards[0]];

	let trackIndex = $state(1);
	let transitionEnabled = $state(true);
	let slideSize = $state(328);
	let dragOffset = $state(0);
	let isDragging = $state(false);
	let reducedMotion = $state(false);

	let dragStartX: number | null = null;
	let dragOffsetRef = 0;
	let pointerIdRef: number | null = null;

	const renderedTrackIndex = $derived(
		Math.min(Math.max(trackIndex, 0), carouselSlides.length - 1)
	);
	const trackTranslateX = $derived(
		`calc(50% - ${slideSize / 2}px - ${renderedTrackIndex * (slideSize + slideGap)}px ${dragOffset >= 0 ? '+' : '-'} ${Math.abs(dragOffset)}px)`
	);

	// Reduced motion detection
	$effect(() => {
		if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
		const media = window.matchMedia('(prefers-reduced-motion: reduce)');
		const sync = () => {
			reducedMotion = media.matches;
		};
		sync();
		media.addEventListener('change', sync);
		return () => media.removeEventListener('change', sync);
	});

	// Slide size on resize
	$effect(() => {
		if (typeof window === 'undefined') return;
		const update = () => {
			if (window.innerWidth >= 1024) {
				slideSize = 560;
				return;
			}
			if (window.innerWidth >= 640) {
				slideSize = 472;
				return;
			}
			const maxMobileWidth = Math.min(window.innerWidth - 48, 368);
			slideSize = Math.max(maxMobileWidth, 288);
		};
		update();
		window.addEventListener('resize', update);
		return () => window.removeEventListener('resize', update);
	});

	// Auto-advance
	$effect(() => {
		if (reducedMotion || isDragging) return;
		const interval = window.setInterval(() => {
			transitionEnabled = true;
			trackIndex =
				trackIndex >= loopBoundaryIndex ? loopBoundaryIndex : trackIndex + 1;
		}, 2200);
		return () => window.clearInterval(interval);
	});

	// Boundary teleport
	$effect(() => {
		if (isDragging) return;
		if (trackIndex !== 0 && trackIndex !== loopBoundaryIndex) return;
		const timer = window.setTimeout(() => {
			transitionEnabled = false;
			trackIndex = trackIndex === 0 ? cardCount : 1;
		}, transitionDurationMs);
		return () => window.clearTimeout(timer);
	});

	// Re-enable transition after teleport
	$effect(() => {
		if (transitionEnabled) return;
		if (typeof window === 'undefined') return;
		let cancelled = false;
		tick().then(() => {
			if (cancelled) return;
			requestAnimationFrame(() => {
				if (cancelled) return;
				transitionEnabled = true;
			});
		});
		return () => {
			cancelled = true;
		};
	});

	function finishDrag(shouldAdvance: boolean, direction: 'next' | 'prev' | null) {
		dragStartX = null;
		dragOffsetRef = 0;
		pointerIdRef = null;
		isDragging = false;
		transitionEnabled = true;
		dragOffset = 0;

		if (!shouldAdvance || !direction) return;

		if (direction === 'next') {
			trackIndex =
				trackIndex >= loopBoundaryIndex ? loopBoundaryIndex : trackIndex + 1;
		} else {
			trackIndex = trackIndex <= 0 ? 0 : trackIndex - 1;
		}
	}

	function handlePointerDown(event: PointerEvent) {
		if (event.pointerType === 'mouse' && event.button !== 0) return;
		dragStartX = event.clientX;
		dragOffsetRef = 0;
		pointerIdRef = event.pointerId;
		isDragging = true;
		transitionEnabled = false;
		dragOffset = 0;
		(event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
	}

	function handlePointerMove(event: PointerEvent) {
		if (!isDragging || dragStartX === null || pointerIdRef !== event.pointerId) return;
		const nextOffset = event.clientX - dragStartX;
		dragOffsetRef = nextOffset;
		dragOffset = nextOffset;
	}

	function handlePointerEnd(event: PointerEvent) {
		if (!isDragging || pointerIdRef !== event.pointerId) return;
		const target = event.currentTarget as HTMLElement;
		if (target.hasPointerCapture(event.pointerId)) {
			target.releasePointerCapture(event.pointerId);
		}
		const threshold = Math.min(88, slideSize * 0.16);
		const shouldAdvance = Math.abs(dragOffsetRef) > threshold;
		const direction =
			dragOffsetRef < 0 ? 'next' : dragOffsetRef > 0 ? 'prev' : null;
		finishDrag(shouldAdvance, direction);
	}
</script>

<div class="relative -mx-4 mt-10 w-auto sm:-mx-6 md:-mx-8">
	<div class="overflow-hidden border-b bg-transparent" style="border-color: var(--border);">
		<div class="relative mx-auto max-w-7xl px-3 py-6 sm:px-6 sm:py-8">
			<!-- Glow -->
			<div
				class="pointer-events-none absolute inset-x-0 top-6 flex justify-center sm:top-8"
			>
				<div
					class="h-28 w-28 rounded-full bg-primary/[0.16] blur-3xl dark:bg-primary/[0.22]"
				></div>
			</div>
			<!-- Edge fades -->
			<div
				class="pointer-events-none absolute inset-y-0 left-0 z-20 w-12 bg-linear-to-r from-background via-background/[0.74] to-transparent dark:via-background/60 sm:w-24"
			></div>
			<div
				class="pointer-events-none absolute inset-y-0 right-0 z-20 w-12 bg-linear-to-l from-background via-background/[0.74] to-transparent dark:via-background/60 sm:w-24"
			></div>

			<div class="relative h-[328px] sm:h-[360px]">
				<!-- svelte-ignore a11y_no_static_element_interactions -->
				<div
					onpointerdown={handlePointerDown}
					onpointermove={handlePointerMove}
					onpointerup={handlePointerEnd}
					onpointercancel={handlePointerEnd}
					class="flex h-full items-start gap-4 px-1 pt-6 sm:px-4 sm:pt-8 {transitionEnabled &&
					!isDragging
						? 'transition-transform duration-700 ease-[cubic-bezier(0.22,1,0.36,1)]'
						: ''} {isDragging ? 'cursor-grabbing' : 'cursor-grab'}"
					style="transform: translateX({trackTranslateX}); touch-action: pan-y;"
				>
					{#each carouselSlides as card, index (card.key + '-' + index)}
						{@const distance = Math.abs(index - trackIndex)}
						{@const isActive = index === trackIndex}
						<article
							class="relative shrink-0 overflow-hidden rounded-[1.65rem] border px-5 py-5 text-left transition-[opacity,transform,box-shadow] duration-700 ease-[cubic-bezier(0.22,1,0.36,1)] h-[244px] sm:h-[268px] sm:px-7 sm:py-6
								{isActive
									? 'border-primary/[0.24] bg-white/[0.92] shadow-[0_24px_54px_rgba(15,23,42,0.08)] dark:bg-white/[0.08] dark:shadow-[0_26px_60px_rgba(0,0,0,0.22)]'
									: distance === 1
										? 'border-border/70 bg-background/[0.78] shadow-[0_14px_32px_rgba(15,23,42,0.04)] dark:bg-white/[0.04]'
										: 'border-border/60 bg-background/[0.70] shadow-none dark:bg-white/[0.03]'}"
							class:translate-y-0={isActive}
							class:scale-100={isActive}
							class:translate-y-5={!isActive}
							class:scale-95={!isActive}
							style="width: {slideSize}px; opacity: {isActive ? 1 : distance === 1 ? 0.62 : 0.3};"
							aria-hidden={!isActive}
						>
							<div
								class="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(75,195,230,0.12),transparent_36%)] dark:bg-[radial-gradient(circle_at_top_right,rgba(75,195,230,0.14),transparent_36%)]"
							></div>
							<div class="relative flex h-full flex-col">
								<div class="flex items-center gap-4">
									<span
										class="inline-flex rounded-full bg-primary/[0.12] px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-primary"
									>
										Portal
									</span>
								</div>
								<div class="mt-10 space-y-3">
									<h3
										class="max-w-[12ch] text-[1.9rem] font-semibold leading-[0.92] tracking-tight text-foreground sm:text-[2.2rem]"
									>
										{card.title}
									</h3>
									<p
										class="max-w-[34ch] text-[0.98rem] leading-6 text-text-muted sm:text-[1rem]"
									>
										{card.description}
									</p>
								</div>
								<div class="mt-auto pt-8">
									<div
										class="h-px w-16"
										style="background: var(--gradient-primary-fade);"
									></div>
								</div>
							</div>
						</article>
					{/each}
				</div>
			</div>
		</div>
	</div>
</div>
