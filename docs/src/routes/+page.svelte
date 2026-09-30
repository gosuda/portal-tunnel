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
		content="Expose local services with self-hosted relays, client-side tenant TLS, and IVNP-backed overlay networking: Portal selects endpoints, IVNP owns the path."
	/>
</svelte:head>

<div class="not-prose">
	<HeroSection />
	<DifferentiatorCarousel />
	<CoreFeaturesGrid />
	<TunnelCommandForm />
</div>
