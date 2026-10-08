<script lang="ts">
	import HeroSection from '$lib/components/landing/HeroSection.svelte';
	import TunnelCommandForm from '$lib/components/landing/TunnelCommandForm.svelte';
	import CoreFeaturesGrid from '$lib/components/landing/CoreFeaturesGrid.svelte';
</script>

<svelte:head>
	<title>Portal - Expose Local Apps to the Public Internet</title>
	<meta
		name="description"
		content="Expose local services with self-hosted relays, client-side tenant TLS, and IVNP-backed overlay networking: Portal selects endpoints, IVNP owns the path."
	/>
</svelte:head>

<div class="not-prose space-y-12">
	<HeroSection />
	<TunnelCommandForm />
	<CoreFeaturesGrid />
</div>
