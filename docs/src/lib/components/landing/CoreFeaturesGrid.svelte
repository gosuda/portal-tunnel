<script lang="ts">
	const features = [
		{
			eyebrow: 'Relay',
			title: 'Trustless relay transport',
			description:
				'Relays own routing and transport, while the tunnel process owns endpoint behavior.'
		},
		{
			eyebrow: 'TLS',
			title: 'Client-side tenant TLS',
			description:
				'Tenant TLS terminates locally with MITM detection, so relays cannot read plaintext.'
		},
		{
			eyebrow: 'HTTP',
			title: 'Tunnel-controlled HTTP routing',
			description:
				'Mount frontend, API, and other local HTTP services behind one public URL.'
		},
		{
			eyebrow: 'Ports',
			title: 'Raw TCP and UDP leases',
			description:
				'Expose game servers, custom TCP protocols, and datagram services through relay ports.'
		},
		{
			eyebrow: 'Mesh',
			title: 'Relay pools and multi-hop',
			description:
				'Use discovered relays for failover or chain relays to split path visibility.'
		},
		{
			eyebrow: 'Ops',
			title: 'Self-hosted or public relays',
			description:
				'Run your own relay, attach explicit relays, or use the public relay registry.'
		}
	] as const;
</script>

<div class="relative -mx-4 w-auto sm:-mx-6 md:-mx-8">
	<div class="mx-auto max-w-6xl px-4 pb-5 text-left sm:px-6">
		<div class="space-y-2">
			<p
				class="text-sm font-semibold uppercase tracking-[0.3em]"
				style="color: var(--neon-cyan);"
			>
				Core features
			</p>
			<h2
				class="text-3xl font-semibold tracking-tight"
				style="color: var(--foreground);"
			>
				Built for real localhost publishing
			</h2>
		</div>
	</div>
	<div class="overflow-hidden border-t" style="border-color: var(--border); background: color-mix(in oklch, var(--border) 70%, transparent);">
		<div class="grid gap-px sm:grid-cols-2 lg:grid-cols-3">
			{#each features as { eyebrow, title, description } (title)}
				<article
					class="flex min-h-52 bg-background/[0.88] p-6 text-left transition-colors duration-200 hover:bg-background/[0.92] sm:min-h-56 sm:p-7"
				>
					<div class="flex h-full flex-col space-y-3">
						<p
							class="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary/80"
						>
							{eyebrow}
						</p>
						<h3
							class="text-[1.2rem] font-semibold tracking-tight text-foreground sm:text-[1.32rem] sm:leading-tight"
						>
							{title}
						</h3>
						<p
							class="max-w-[28ch] text-[0.95rem] leading-6 text-text-muted"
						>
							{description}
						</p>
						<div class="mt-auto pt-4">
							<div
								class="h-px w-12"
								style="background: var(--gradient-primary-fade);"
							></div>
						</div>
					</div>
				</article>
			{/each}
		</div>
	</div>
</div>
