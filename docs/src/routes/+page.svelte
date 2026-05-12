<script lang="ts">
	import HeroSection from '$lib/components/landing/HeroSection.svelte';
	import DifferentiatorCarousel from '$lib/components/landing/DifferentiatorCarousel.svelte';
	import CoreFeaturesGrid from '$lib/components/landing/CoreFeaturesGrid.svelte';
	import TunnelCommandForm from '$lib/components/landing/TunnelCommandForm.svelte';
</script>

<svelte:head>
	<title>Portal - Expose Local Apps to the Public Internet</title>
	<meta
		name="description"
		content="Portal exposes local services through trustless relay transport with client-side tenant TLS, routed HTTP, raw TCP, UDP, relay pools, and multi-hop routing."
	/>
</svelte:head>

<div class="not-prose">
	<HeroSection />
	<DifferentiatorCarousel />
	<CoreFeaturesGrid />
	<TunnelCommandForm />
</div>
