package main

import "github.com/gosuda/portal-tunnel/v2/portal/acme"

// The deployment .env is shared by the relay and by Docker Compose itself.
// Checking a key against the relay's own flags alone would report the
// Compose-level ones as unknown, so the keys owned elsewhere are catalogued
// here.
//
// This table is the only place that knowledge lives. Relay-owned keys are not
// listed: they come from the flag definitions in main.go through
// utils.EnvVars().

const (
	ownerCompose   = "compose"
	ownerGoogleSDK = "Google Cloud SDK"
	ownerImage     = "container image"
)

// externalEnvVar is a deployment key this binary does not read.
//
// Pinned keys are recognised so that setting one is never reported as unknown,
// but they are left out of .env.example on purpose: the bundled topology fixes
// them, and listing them invites an override that breaks the wiring. Pinned is
// what keeps that decision from silently reverting the next time someone runs
// the drift check.
type externalEnvVar struct {
	Owner  string
	Usage  string
	Pinned bool
}

var externalEnvVars = map[string]externalEnvVar{
	"PPROF_PORT": {Owner: ownerCompose,
		Usage: "host port published for the pprof listener, when that mapping is uncommented in docker-compose.yml. Consumed when Compose parses the file, so it is not a container variable."},

	"GOOGLE_APPLICATION_CREDENTIALS": {Owner: ownerGoogleSDK,
		Usage: "service account file path. Read by the Google Cloud SDK directly rather than by a relay flag, so it is passed through untouched."},

	"TZ": {Owner: ownerImage, Pinned: true,
		Usage: "container time zone. Set to UTC by the image."},
}

// alsoConsumedBy notes extra consumers of keys the relay does read, so the
// report can say that changing one moves more than the relay.
var alsoConsumedBy = map[string]string{
	"IDENTITY_PATH":       "compose mounts ./.portal-certs at this path",
	"WIREGUARD_PORT":      "compose publishes this UDP port",
	"MIN_PORT":            "compose publishes this port range when the mapping is uncommented",
	"MAX_PORT":            "compose publishes this port range when the mapping is uncommented",
	"PORTAL_FRONTEND_DIR": "compose has a matching read-only mount to uncomment when replacing the SPA",
}

// pinnedByTopology are keys the bundled Compose stack fixes because the relay
// reaches itself at those ports through its own SNI router. Overriding one
// through .env breaks that wiring, so the report calls it out.
var pinnedByTopology = map[string]struct {
	Value  string
	Reason string
}{
	"API_PORT": {"4017", "the SNI router forwards root-host traffic to the internal API listener on this port"},
	"SNI_PORT": {"443", "this is the public port tunnel clients are told to reach"},
}

// dnsProviderCredential maps each supported ACME_DNS_PROVIDER value to the
// credential it requires. Providers whose credentials come from an ambient
// chain (an instance role, application default credentials) map to an empty
// list because there is nothing to require.
//
// The keys are acme's own exported constants rather than repeated strings, so
// a provider added there cannot silently go unreported here: acme.NewManager
// owns provider construction, and this map only adds the credential each one
// needs, which is knowledge the report owns.
var dnsProviderCredential = map[string][]string{
	// The embedded server is the default and needs no credentials: it answers
	// from the relay itself rather than through a provider API.
	acme.TypeEmbedded:   nil,
	acme.TypeCloudflare: {"CLOUDFLARE_TOKEN"},
	acme.TypeHetzner:    {"HETZNER_API_TOKEN"},
	acme.TypeNjalla:     {"NJALLA_TOKEN"},
	acme.TypeVultr:      {"VULTR_API_KEY"},
	acme.TypeRoute53:    nil,
	acme.TypeGCloud:     nil,
}
