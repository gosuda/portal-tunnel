<script lang="ts">
	import { onMount } from 'svelte';
	import {
		buildTunnelDisplayCommand,
		buildTunnelPreviewURL,
		RELAY_ORIGIN,
		type TunnelCommandOS
	} from '$lib/tunnel-command';
	import { buildDefaultExposeName } from '$lib/expose-name';
	import { classifyShareInput, type ShareKind } from '$lib/share-link';

	const SHARE_KIND_LABEL: Record<ShareKind, string> = { url: 'URL', file: 'File', port: 'Port' };
	const SHARE_PLACEHOLDER = 'file:///Users/me/site/index.html or 3000';

	// Empty by default so the field reads as "paste a link here" instead of
	// pre-committing the user to a local port.
	let target = $state('');
	let os: TunnelCommandOS = $state('unix');
	let name = $state('');
	let nameSeed = $state('');
	let copied = $state(false);

	onMount(() => {
		nameSeed = crypto.randomUUID();
	});

	const share = $derived(classifyShareInput(target));
	const generatedName = $derived(buildDefaultExposeName(share.seedTarget, nameSeed));
	const effectiveName = $derived(name.trim() || generatedName);

	const commandLines = $derived.by(() =>
		buildTunnelDisplayCommand({
			currentOrigin: RELAY_ORIGIN,
			target: share.target,
			name: effectiveName,
			nameSeed,
			relayUrls: [RELAY_ORIGIN],
			discovery: true,
			thumbnailURL: '',
			os,
			shareKind: share.kind,
			servePath: share.path
		}).split('\n')
	);

	// Install is the first line(s); the expose command is the rest.
	const installBlock = $derived(
		os === 'windows' ? commandLines.slice(0, 2).join('\n') : (commandLines[0] ?? '')
	);
	const runBlock = $derived(
		os === 'windows' ? commandLines.slice(2).join('\n') : commandLines.slice(1).join('\n')
	);

	const previewURL = $derived(
		buildTunnelPreviewURL(RELAY_ORIGIN, effectiveName, share.seedTarget, nameSeed)
	);

	function handleCopy() {
		const fullCommand = installBlock + '\n' + runBlock;
		navigator.clipboard.writeText(fullCommand).then(() => {
			copied = true;
			setTimeout(() => {
				copied = false;
			}, 2000);
		});
	}

	function handleShuffleName() {
		nameSeed = crypto.randomUUID();
		name = '';
	}

	function handleNameChange(event: Event) {
		name = (event.target as HTMLInputElement).value;
	}
</script>

<div id="quick-start" class="relative mt-8 scroll-mt-24 sm:mt-10">
	<div class="mx-auto w-full max-w-6xl text-left">
		<div class="space-y-2">
			<p
				class="text-sm font-semibold uppercase tracking-[0.3em]"
				style="color: var(--neon-cyan);"
			>
				Quick Start
			</p>
			<h2
				class="text-3xl font-semibold tracking-tight"
				style="color: var(--foreground);"
			>
				Expose service
			</h2>
		</div>

		<div
			class="relative mx-auto mt-4 w-full max-w-[520px] rounded-xl border px-4 py-5 sm:px-5 sm:py-6"
			style="background: var(--hero-terminal-bg); border-color: var(--hero-terminal-border); color: var(--hero-terminal-foreground); box-shadow: 0 30px 72px var(--hero-terminal-shadow);"
		>
			<div class="mb-5 flex min-w-0 items-center gap-3">
				<span
					aria-hidden="true"
					class="shrink-0 font-mono text-lg leading-none"
					style="color: var(--hero-terminal-accent);"
				>
					{'>'}
				</span>
				<h3
					id="tunnel-preview"
					class="min-w-0 text-xl font-bold tracking-tight sm:text-2xl"
				>
					Run this command
				</h3>
			</div>

			<div class="space-y-5">
				<!-- 1. Paste what you want to share -->
				<div class="space-y-2">
					<div class="space-y-1.5">
						<p class="text-[13px] font-semibold tracking-[0.04em] text-slate-100 sm:text-sm">
							1. Paste what you want to share
						</p>
						<p class="text-[12px] leading-5 text-slate-400">
							A local port such as
							<span class="mx-1 font-mono text-slate-200">3000</span>, a running URL
							such as
							<span class="mx-1 font-mono text-slate-200">http://localhost:3000</span>,
							or a file path such as
							<span class="mx-1 font-mono text-slate-200"
								>file:///Users/me/site/index.html</span
							>
							— file paths are served as a static site straight from that folder, so
							nothing needs to be running locally.
						</p>
					</div>
				</div>

				<!-- 2. Run this command -->
				<div class="space-y-3">
					<div class="flex flex-wrap items-center justify-between gap-3">
						<p class="text-[13px] font-semibold tracking-[0.04em] text-slate-100 sm:text-sm">
							2. Run this command
						</p>
						<div
							class="flex shrink-0 rounded-lg border p-0.5"
							style="border-color: rgba(255,255,255,0.06); background: rgba(255,255,255,0.035);"
						>
							<button
								type="button"
								onclick={() => {
									os = 'unix';
								}}
								class="min-w-[72px] whitespace-nowrap rounded-md px-2.5 py-1.5 text-[11px] font-semibold transition-colors {os ===
								'unix'
									? 'bg-white/[0.08] text-slate-200'
									: 'text-slate-500 hover:text-slate-300'}"
							>
								Linux
							</button>
							<button
								type="button"
								onclick={() => {
									os = 'windows';
								}}
								class="min-w-[72px] whitespace-nowrap rounded-md px-2.5 py-1.5 text-[11px] font-semibold transition-colors {os ===
								'windows'
									? 'bg-white/[0.08] text-slate-200'
									: 'text-slate-500 hover:text-slate-300'}"
							>
								Windows
							</button>
						</div>
					</div>

					<!-- Share + Name controls -->
					<div class="space-y-2">
						<div class="flex min-w-0 items-center gap-2">
							<span
								class="shrink-0 text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-500"
							>
								Share
							</span>
							<input
								type="text"
								bind:value={target}
								placeholder={SHARE_PLACEHOLDER}
								aria-label="Link, file path, or local port to share"
								class="h-auto min-w-0 flex-1 border-0 bg-transparent px-0 py-0 font-mono text-[13px] text-slate-200 shadow-none outline-none placeholder:text-slate-600"
							/>
							{#if target.trim() !== ''}
								<span
									class="shrink-0 rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-400"
									style="background: rgba(255,255,255,0.06);"
									title="Detected share type"
								>
									{SHARE_KIND_LABEL[share.kind]}
								</span>
							{/if}
						</div>
						<div class="flex min-w-0 items-center gap-2">
							<span
								class="shrink-0 text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-500"
							>
								Name
							</span>
							<input
								type="text"
								oninput={handleNameChange}
								placeholder={generatedName}
								aria-label="Public name"
								class="min-w-0 flex-1 border-0 bg-transparent px-0 py-0 text-[13px] text-slate-200 shadow-none outline-none placeholder:text-slate-600"
							/>
							<button
								type="button"
								onclick={handleShuffleName}
								class="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-slate-500 transition-colors hover:bg-white/[0.06] hover:text-slate-200"
								aria-label="Shuffle public name"
								title="Shuffle public name"
							>
								<svg
									class="h-4 w-4"
									fill="none"
									viewBox="0 0 24 24"
									stroke="currentColor"
									stroke-width="2"
									stroke-linecap="round"
									stroke-linejoin="round"
								>
									<polyline points="23 4 23 10 17 10" />
									<polyline points="1 20 1 14 7 14" />
									<path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10" />
									<path d="M20.49 15a9 9 0 0 1-14.85 3.36L1 14" />
								</svg>
							</button>
						</div>
					</div>

					<!-- Command block -->
					<div
						class="relative min-h-[148px] rounded-xl border px-4 py-4 pr-14 font-mono text-sm leading-7"
						style="border-color: rgba(255,255,255,0.1); background: rgba(0,0,0,0.55); color: white; box-shadow: inset 0 1px 0 rgba(255,255,255,0.05);"
					>
						<button
							type="button"
							onclick={handleCopy}
							class="absolute right-4 top-4 inline-flex h-8 w-8 items-center justify-center rounded-lg transition-colors hover:bg-emerald-400/10"
							style="color: rgba(110,231,183,0.75);"
							aria-label="Copy command"
							title={copied ? 'Copied' : 'Copy'}
						>
							{#if copied}
								<svg
									class="h-4 w-4"
									fill="none"
									viewBox="0 0 24 24"
									stroke="currentColor"
									stroke-width="2"
									stroke-linecap="round"
									stroke-linejoin="round"
								>
									<polyline points="20 6 9 17 4 12" />
								</svg>
							{:else}
								<svg
									class="h-4 w-4"
									fill="none"
									viewBox="0 0 24 24"
									stroke="currentColor"
									stroke-width="2"
									stroke-linecap="round"
									stroke-linejoin="round"
								>
									<rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
									<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
								</svg>
							{/if}
						</button>
						<pre class="overflow-x-auto whitespace-pre-wrap break-all"><span class="block">{installBlock}</span><span class="mt-2 block">{runBlock}</span></pre>
					</div>
				</div>

				<!-- 3. Open this public URL -->
				<div class="space-y-2 pt-1">
					<p class="text-[13px] font-semibold tracking-[0.04em] text-slate-100 sm:text-sm">
						3. Open this public URL
					</p>
					<div
						class="space-y-3 rounded-xl border px-3.5 py-3"
						style="border-color: rgba(255,255,255,0.08); background: rgba(255,255,255,0.045);"
					>
						<a
							href={previewURL}
							target="_blank"
							rel="noopener noreferrer"
							class="block overflow-x-auto whitespace-nowrap font-mono text-[15px] font-medium text-sky-300 underline-offset-4 hover:underline sm:text-base"
						>
							{previewURL}
						</a>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>
