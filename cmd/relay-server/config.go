package main

import (
	"bufio"
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	portalx402 "github.com/gosuda/portal-tunnel/v2/portal/x402"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// A feature is one capability the operator turned on or off, reported at
// startup and by the config subcommand. Logging the raw settings is not enough:
// "you switched this off" and "you switched this on but it cannot run" both
// show up as a false flag, and only the second one is a misconfiguration.
type featureState string

const (
	stateEnabled     featureState = "enabled"
	stateDisabled    featureState = "disabled"
	stateBlocked     featureState = "blocked"
	stateUnprotected featureState = "UNPROTECTED"
)

type feature struct {
	Name string
	// State reflects validated configuration, not listener readiness.
	State featureState
	// By is the setting that produced the state, e.g. "DISCOVERY=true".
	By string
	// Detail adds context for a working feature.
	Detail string
	// Missing says what has to be supplied, for blocked and unprotected states.
	Missing string
}

func (f feature) needsAttention() bool {
	return f.State == stateBlocked || f.State == stateUnprotected
}

func evaluateFeatures(cfg relayServerConfig) []feature {
	return []feature{
		discoveryFeature(cfg),
		acmeFeature(cfg),
		ensGaslessFeature(cfg),
		leaseTransportFeature("udp-transport", "UDP_ENABLED", cfg.UDPEnabled, cfg),
		leaseTransportFeature("tcp-transport", "TCP_ENABLED", cfg.TCPEnabled, cfg),
		adminAPIFeature(cfg),
		frontendFeature(cfg),
		landingPageFeature(cfg),
		proxyHeaderFeature(cfg),
		x402Feature(cfg),
		pprofFeature(cfg),
		httpRedirectFeature(cfg),
	}
}

func httpRedirectFeature(cfg relayServerConfig) feature {
	f := feature{Name: types.HTTPRedirectFeatureName, State: stateDisabled, By: types.HTTPRedirectEnabledEnv + "=false"}
	if !cfg.HTTPRedirect.Enabled {
		return f
	}
	f.By = types.HTTPRedirectEnabledEnv + "=true"
	redirect, err := utils.NormalizeHTTPRedirectConfig(cfg.HTTPRedirect, cfg.PortalURL)
	if err != nil {
		f.State, f.Missing = stateBlocked, err.Error()
		return f
	}
	f.State = stateEnabled
	f.Detail = "addr=" + redirect.Addr + "; canonical PORTAL_URL only; configuration valid; listener binding occurs at startup"
	if redirect.HSTS {
		f.Detail += "; HSTS header requested (browsers ignore it over HTTP)"
	}
	return f
}

func frontendFeature(cfg relayServerConfig) feature {
	f := feature{Name: "frontend"}
	dir := strings.TrimSpace(cfg.FrontendDir)
	if dir == "" {
		f.State, f.By = stateEnabled, "PORTAL_FRONTEND_DIR="
		f.Detail = "serving the SPA embedded in the binary"
		return f
	}
	index := filepath.Join(dir, "index.html")
	if _, err := os.Stat(index); err != nil {
		f.State, f.By = stateBlocked, "PORTAL_FRONTEND_DIR="+dir
		f.Missing = fmt.Sprintf("%s is not readable (%v); mount the directory or clear the variable to use the embedded SPA", index, err)
		return f
	}
	f.State, f.By = stateEnabled, "PORTAL_FRONTEND_DIR="+dir
	f.Detail = "serving a custom SPA instead of the embedded one"
	return f
}

func landingPageFeature(cfg relayServerConfig) feature {
	f := feature{Name: "landing-page"}
	if !cfg.LandingPageEnabled {
		f.State, f.By = stateDisabled, "LANDING_PAGE_ENABLED=false"
		f.Detail = "the dashboard opens directly on the relay view"
		return f
	}
	f.State, f.By = stateEnabled, "LANDING_PAGE_ENABLED=true"
	return f
}

func discoveryFeature(cfg relayServerConfig) feature {
	f := feature{Name: "discovery"}
	if !cfg.DiscoveryEnabled {
		f.State, f.By = stateDisabled, "DISCOVERY=false"
		return f
	}
	// The same normalization portal.NewServer applies, not a second opinion
	// about it. Checking only the parsed hostname would report PORTAL_URL=http://…
	// as enabled and then have the server reject it seconds later, which is
	// exactly the divergence this report exists to remove.
	if _, err := utils.NormalizeRelayURL(cfg.PortalURL); err != nil {
		f.State, f.By = stateBlocked, "DISCOVERY=true"
		f.Missing = fmt.Sprintf("PORTAL_URL is not usable as a relay URL: %v", err)
		return f
	}
	host := portalURLHost(cfg.PortalURL)
	if host == "" || utils.IsLocalRelayHost(host) {
		f.State, f.By = stateBlocked, "DISCOVERY=true"
		f.Missing = fmt.Sprintf(
			"PORTAL_URL host %q is local-only and public discovery rejects it; set PORTAL_URL to a publicly resolvable HTTPS origin",
			host)
		return f
	}
	bootstraps, err := utils.NormalizeRelayURLs(utils.SplitCSV(cfg.Bootstraps)...)
	if err != nil {
		f.State, f.By = stateBlocked, "DISCOVERY=true"
		f.Missing = fmt.Sprintf("BOOTSTRAPS is not usable: %v", err)
		return f
	}
	f.State, f.By = stateEnabled, "DISCOVERY=true"
	f.Detail = fmt.Sprintf("host=%s bootstraps=%d wireguard_port=%d",
		host, len(bootstraps), cfg.WireGuardPort)
	return f
}

func acmeFeature(cfg relayServerConfig) feature {
	f := feature{Name: "acme"}
	// Unset is not off. The relay falls back to the embedded authoritative DNS
	// server, so reporting "disabled" here would describe a relay that is in
	// fact serving its own zone and answering ACME challenges from it.
	provider := strings.ToLower(strings.TrimSpace(cfg.ACMEDNSProvider))
	provider = cmp.Or(provider, acme.TypeEmbedded)
	if provider == acme.TypeEmbedded {
		f.State, f.By = stateEnabled, "ACME_DNS_PROVIDER="+provider
		f.Detail = fmt.Sprintf(
			"the relay serves its own zone on port %d; delegate the base domain with an NS record and open 53/tcp+udp. "+
				"Manual fullchain.pem and privatekey.pem under IDENTITY_PATH are used instead when present",
			cfg.EmbeddedDNSPort)
		return f
	}

	// acme.NewManager returns before it builds a DNS provider when the base
	// domain is local-only, so managed issuance cannot run however well the
	// provider is configured. Reporting it as enabled here would describe an
	// automation that never starts.
	if host := portalURLHost(cfg.PortalURL); host == "" || utils.IsLocalRelayHost(host) {
		f.State, f.By = stateBlocked, "ACME_DNS_PROVIDER="+provider
		f.Missing = fmt.Sprintf(
			"PORTAL_URL host %q is local-only; managed issuance is skipped for local hosts and a development certificate is used instead",
			host)
		return f
	}

	required, supported := dnsProviderCredential[provider]
	if !supported {
		f.State, f.By = stateBlocked, "ACME_DNS_PROVIDER="+provider
		f.Missing = "unsupported provider; use cloudflare, gcloud, hetzner, njalla, route53 or vultr"
		return f
	}

	var empty []string
	for _, name := range required {
		if strings.TrimSpace(providerCredential(cfg, name)) == "" {
			empty = append(empty, name)
		}
	}
	if len(empty) > 0 {
		f.State, f.By = stateBlocked, "ACME_DNS_PROVIDER="+provider
		f.Missing = strings.Join(empty, ", ") + " is empty"
		return f
	}

	f.State, f.By = stateEnabled, "ACME_DNS_PROVIDER="+provider
	f.Detail = "managed issuance and renewal under IDENTITY_PATH"
	if len(required) == 0 {
		f.Detail += "; credentials come from the ambient provider chain"
	}
	return f
}

func ensGaslessFeature(cfg relayServerConfig) feature {
	f := feature{Name: "ens-gasless"}
	if !cfg.ENSGaslessEnabled {
		f.State, f.By = stateDisabled, "ENS_GASLESS_ENABLED=false"
		return f
	}
	// The embedded server cannot manage zone DNSSEC yet, and it is what an
	// unset ACME_DNS_PROVIDER selects, so this is the combination an operator
	// reaches by turning ENS on and changing nothing else.
	provider := strings.ToLower(strings.TrimSpace(cfg.ACMEDNSProvider))
	provider = cmp.Or(provider, acme.TypeEmbedded)
	if provider == acme.TypeEmbedded {
		f.State, f.By = stateBlocked, "ENS_GASLESS_ENABLED=true"
		f.Missing = "ACME_DNS_PROVIDER=" + provider +
			" cannot manage zone DNSSEC yet; ENS gasless automation needs one of the managed providers"
		return f
	}
	// ENS gasless drives the same provider ACME does, so it cannot work when
	// that provider cannot. Repeating only the "is it set" half of the check
	// here would report this as enabled while acme is blocked, which is exactly
	// the mismatch this report exists to surface.
	if acmeState := acmeFeature(cfg); acmeState.State == stateBlocked {
		f.State, f.By = stateBlocked, "ENS_GASLESS_ENABLED=true"
		f.Missing = "the DNS provider it shares with ACME is blocked: " + acmeState.Missing
		return f
	}
	f.State, f.By = stateEnabled, "ENS_GASLESS_ENABLED=true"
	f.Detail = "DNSSEC and ENS TXT automation through " + provider
	return f
}

func leaseTransportFeature(name, envName string, enabled bool, cfg relayServerConfig) feature {
	f := feature{Name: name}
	if !enabled {
		f.State, f.By = stateDisabled, envName+"=false"
		return f
	}
	if cfg.MinPort <= 0 || cfg.MaxPort <= 0 || cfg.MaxPort < cfg.MinPort {
		f.State, f.By = stateBlocked, envName+"=true"
		f.Missing = fmt.Sprintf(
			"MIN_PORT=%d MAX_PORT=%d is not a usable range; set both and publish the range in docker-compose.yml",
			cfg.MinPort, cfg.MaxPort)
		return f
	}
	f.State, f.By = stateEnabled, envName+"=true"
	f.Detail = fmt.Sprintf("ports=%d-%d", cfg.MinPort, cfg.MaxPort)
	return f
}

func adminAPIFeature(cfg relayServerConfig) feature {
	f := feature{Name: "admin-api"}
	if strings.TrimSpace(cfg.AdminToken) == "" {
		f.State = stateUnprotected
		f.Missing = "ADMIN_TOKEN is empty; the admin and policy APIs accept unauthenticated requests. Generate one with: openssl rand -hex 32"
		return f
	}
	f.State, f.By = stateEnabled, "ADMIN_TOKEN set"
	f.Detail = "bearer token required for /api/admin and /api/policy"
	return f
}

func proxyHeaderFeature(cfg relayServerConfig) feature {
	f := feature{Name: "proxy-headers"}
	if !cfg.TrustProxyHeaders {
		f.State, f.By = stateDisabled, "TRUST_PROXY_HEADERS=false"
		f.Detail = "client addresses come from the socket, which is correct when Portal owns the public port itself"
		return f
	}
	f.State, f.By = stateEnabled, "TRUST_PROXY_HEADERS=true"
	if cidrs := strings.TrimSpace(cfg.TrustedProxyCIDRs); cidrs != "" {
		f.Detail = "trusted=" + cidrs
	} else {
		f.Detail = "trusted=default private and loopback ranges (TRUSTED_PROXY_CIDRS empty)"
	}
	return f
}

func x402Feature(cfg relayServerConfig) feature {
	f := feature{Name: "x402"}
	if !cfg.X402Enabled {
		f.State, f.By = stateDisabled, "X402_ENABLED=false"
		return f
	}
	if strings.TrimSpace(cfg.X402PayTo) == "" {
		f.State, f.By = stateBlocked, "X402_ENABLED=true"
		f.Missing = "X402_PAY_TO is empty; the facilitator has no payment recipient"
		return f
	}
	f.State, f.By = stateEnabled, "X402_ENABLED=true"
	f.Detail = "network=" + portalx402.Network(cfg.X402Testnet)
	return f
}

func pprofFeature(cfg relayServerConfig) feature {
	f := feature{Name: "pprof"}
	if !cfg.PProfEnabled {
		f.State, f.By = stateDisabled, "PPROF_ENABLED=false"
		return f
	}
	f.State, f.By = stateEnabled, "PPROF_ENABLED=true"
	f.Detail = "addr=" + cfg.PProfAddr
	return f
}

func portalURLHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return utils.NormalizeHostname(parsed.Hostname())
}

func providerCredential(cfg relayServerConfig, name string) string {
	switch name {
	case "CLOUDFLARE_TOKEN":
		return cfg.CloudflareToken
	case "HETZNER_API_TOKEN":
		return cfg.HetznerAPIToken
	case "NJALLA_TOKEN":
		return cfg.NjallaToken
	case "VULTR_API_KEY":
		return cfg.VultrAPIKey
	default:
		return ""
	}
}

// logFeatureReport emits the same report the config subcommand renders, so the
// two can never describe the deployment differently.
func logFeatureReport(features []feature) {
	for _, f := range features {
		event := log.Info()
		if f.needsAttention() {
			event = log.Warn()
		}
		event = event.Str("feature", f.Name).Str("state", string(f.State))
		if f.By != "" {
			event = event.Str("by", f.By)
		}
		if f.Detail != "" {
			event = event.Str("detail", f.Detail)
		}
		if f.Missing != "" {
			event = event.Str("missing", f.Missing)
		}
		event.Msg("feature")
	}
}

// envFileEntry is one assignment read from an env file, kept in file order so
// the report follows the operator's own layout.
type envFileEntry struct {
	Name  string
	Value string
}

func loadEnvFile(path string) ([]envFileEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var entries []envFileEntry
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		// A line that is neither blank, a comment, nor an assignment is a
		// mistake, and skipping it would reproduce the silent misconfiguration
		// this command exists to expose: `DISCOVERY true` would simply vanish
		// and the feature would report its default with nothing to explain why.
		name, value, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("%s:%d: not an assignment: %q", path, lineNo, line)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("%s:%d: assignment has no name: %q", path, lineNo, line)
		}
		// Compose does not expand values read from an env file, so neither do we.
		value = strings.TrimSpace(value)
		doubleQuoted := len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"'
		singleQuoted := len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\''
		if doubleQuoted || singleQuoted {
			value = value[1 : len(value)-1]
		}
		entries = append(entries, envFileEntry{Name: name, Value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// knownEnvNames indexes every name the relay reads, including flag aliases.
func knownEnvNames() map[string]utils.EnvVar {
	index := make(map[string]utils.EnvVar)
	for _, entry := range utils.EnvVars() {
		index[entry.Name] = entry
		for _, alias := range entry.Aliases {
			index[alias] = entry
		}
	}
	return index
}

func secretEnvName(name string) bool {
	upper := strings.ToUpper(name)
	for _, marker := range []string{"TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIALS"} {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}

// valueMarker distinguishes a key that something supplied from one running on
// its default, so a long list can be skimmed for what the operator actually set.
func valueMarker(entry utils.EnvVar) string {
	if entry.SetBy == "" {
		return "--"
	}
	return "OK"
}

// valueSource names where the effective value came from. When an alias supplied
// it, the alias is named: "I set AWS_REGION, why is the value different?" is
// answered by seeing that AWS_DEFAULT_REGION was consulted first.
func valueSource(entry utils.EnvVar, supplied map[string]bool, envFile string) string {
	if entry.SetBy == "" {
		return fmt.Sprintf("default (%s)", defaultDisplay(entry.Default))
	}

	origin := "process environment"
	if supplied[entry.SetBy] {
		origin = envFile
	}
	if entry.SetBy != entry.Name {
		return fmt.Sprintf("%s, via the alias %s", origin, entry.SetBy)
	}
	return origin
}

func displayValue(name, value string) string {
	if strings.TrimSpace(value) == "" {
		return "<unset>"
	}
	if secretEnvName(name) {
		return "<set>"
	}
	return value
}

func writeConfigReport(w io.Writer, cfg relayServerConfig, entries []envFileEntry, source string) {
	relay := knownEnvNames()

	fmt.Fprintf(w, "Portal relay configuration (%s)\n", source)
	// Say what was inspected, because the two modes answer different questions
	// and only one of them describes a Compose deployment. Reading a file in
	// isolation applies relay defaults to every key the file omits, while
	// Compose supplies its own first: a file with only PORTAL_URL reports
	// MIN_PORT=0 here, and `docker compose up` would run it with 40000.
	if len(entries) > 0 {
		fmt.Fprint(w, "Keys absent from this file take relay defaults. A Compose deployment\n"+
			"supplies its own first; for that environment run the command inside the\n"+
			"container instead: docker compose run --rm -T portal config\n")
	}
	fmt.Fprintln(w)

	supplied := make(map[string]bool, len(entries))
	for _, entry := range entries {
		supplied[entry.Name] = true
	}

	// Every relay key is listed with the value the flag actually resolved to,
	// not the text of whichever line happened to appear in the file. A key that
	// an alias or a higher-priority name overrode would otherwise read as though
	// it were in effect, which is the confusion this report exists to remove.
	fmt.Fprintln(w, "Keys")
	for _, entry := range utils.EnvVars() {
		fmt.Fprintf(w, "  %-4s %-30s %-24s relay --%s\n",
			valueMarker(entry), entry.Name, displayValue(entry.Name, entry.Value), entry.Flag)
		fmt.Fprintf(w, "         source: %s\n", valueSource(entry, supplied, source))
		writeWrapped(w, entry.Usage)
		if pinned, ok := pinnedByTopology[entry.Name]; ok && entry.Value != pinned.Value {
			fmt.Fprintf(w, "         WARNING: pinned to %s by the bundled topology; %s\n",
				pinned.Value, pinned.Reason)
		}
		if note := alsoConsumedBy[entry.Name]; note != "" {
			fmt.Fprintf(w, "         also: %s\n", note)
		}
	}

	// Keys owned by another component are only shown when actually supplied:
	// the relay cannot resolve them, so there is no effective value to report.
	var unknown []envFileEntry
	for _, entry := range entries {
		if _, isRelay := relay[entry.Name]; isRelay {
			continue
		}
		external, isExternal := externalEnvVars[entry.Name]
		if !isExternal {
			unknown = append(unknown, entry)
			continue
		}
		fmt.Fprintf(w, "  OK   %-30s %-24s %s\n",
			entry.Name, displayValue(entry.Name, entry.Value), external.Owner)
		writeWrapped(w, external.Usage)
	}

	if len(unknown) > 0 {
		fmt.Fprintf(w, "\nUNKNOWN  %d key(s) are not read by any component and are silently ignored:\n", len(unknown))
		for _, entry := range unknown {
			if suggestion := nearestEnvName(entry.Name, relay); suggestion != "" {
				fmt.Fprintf(w, "  %-30s did you mean %s?\n", entry.Name, suggestion)
				continue
			}
			fmt.Fprintf(w, "  %-30s no equivalent key exists\n", entry.Name)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Features")
	for _, f := range evaluateFeatures(cfg) {
		marker := " "
		if f.needsAttention() {
			marker = "!"
		}
		fmt.Fprintf(w, " %s %-16s %-12s %s\n", marker, f.Name, f.State, f.By)
		if f.Detail != "" {
			writeWrapped(w, f.Detail)
		}
		if f.Missing != "" {
			writeWrapped(w, "missing: "+f.Missing)
		}
	}

	if issues := utils.EnvIssues(); len(issues) > 0 {
		fmt.Fprintln(w, "\nInvalid values")
		for _, issue := range issues {
			fmt.Fprintf(w, "  %s=%s  %s\n", issue.Name, displayValue(issue.Name, issue.Value), issue.Problem)
		}
	}
}

// writeWrapped prints an indented, soft-wrapped continuation line.
func writeWrapped(w io.Writer, text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	const width = 72
	const indent = "         "
	line := indent
	for _, word := range strings.Fields(text) {
		if len(line)+len(word)+1 > width && strings.TrimSpace(line) != "" {
			fmt.Fprintln(w, line)
			line = indent
		}
		if strings.TrimSpace(line) == "" {
			line += word
			continue
		}
		line += " " + word
	}
	if strings.TrimSpace(line) != "" {
		fmt.Fprintln(w, line)
	}
}

// nearestEnvName suggests the closest known key for a typo. Deployment drift
// usually looks like ADMIN_WALLETS for ADMIN_TOKEN: close enough to look right,
// far enough that nothing reads it.
func nearestEnvName(name string, relay map[string]utils.EnvVar) string {
	candidates := make([]string, 0, len(relay)+len(externalEnvVars))
	for candidate := range relay {
		candidates = append(candidates, candidate)
	}
	for candidate := range externalEnvVars {
		candidates = append(candidates, candidate)
	}
	sort.Strings(candidates)

	best := ""
	bestDistance := len(name)/2 + 2
	for _, candidate := range candidates {
		if distance := editDistance(name, candidate); distance < bestDistance {
			best, bestDistance = candidate, distance
		}
	}
	return best
}

func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous, current = current, previous
	}
	return previous[len(b)]
}

// writeEnvReference emits every key the deployment understands, grouped by
// owner. It is generated from the flag definitions and the catalog, so it
// cannot drift from the code the way a hand-written list does.
func writeEnvReference(w io.Writer) {
	fmt.Fprintln(w, "# Generated by `relay-server config --format env`. Do not edit by hand.")
	fmt.Fprintln(w, "# Every key the bundled deployment understands, grouped by the component")
	fmt.Fprintln(w, "# that reads it. See .env.example for a commented starting point.")

	fmt.Fprintln(w, "\n# ── relay ──")
	for _, entry := range utils.EnvVars() {
		fmt.Fprintf(w, "\n# %s  [relay --%s]  default: %s\n", entry.Name, entry.Flag, defaultDisplay(entry.Default))
		if len(entry.Aliases) > 0 {
			fmt.Fprintf(w, "#   also accepted: %s\n", strings.Join(entry.Aliases, ", "))
		}
		writeCommentWrapped(w, entry.Usage)
		fmt.Fprintf(w, "%s=%s\n", entry.Name, entry.Default)
	}

	owners := make([]string, 0, len(externalEnvVars))
	byOwner := map[string][]string{}
	for name, external := range externalEnvVars {
		if _, seen := byOwner[external.Owner]; !seen {
			owners = append(owners, external.Owner)
		}
		byOwner[external.Owner] = append(byOwner[external.Owner], name)
	}
	sort.Strings(owners)
	for _, owner := range owners {
		names := byOwner[owner]
		sort.Strings(names)
		fmt.Fprintf(w, "\n# ── %s ──\n", owner)
		for _, name := range names {
			fmt.Fprintf(w, "\n# %s  [%s]\n", name, owner)
			writeCommentWrapped(w, externalEnvVars[name].Usage)
			fmt.Fprintf(w, "# %s=\n", name)
		}
	}
}

// writeEnvNames lists the keys an operator is expected to set, one per line, so
// `make check-env-example` can assert .env.example still documents all of them.
// A flag added without a matching .env.example entry is exactly how the
// documented configuration drifts away from the code.
//
// Keys the bundled topology pins in the image are excluded: they are recognised
// everywhere else, but documenting them would invite an override that breaks
// the wiring between nginx and the services behind it.
func writeEnvNames(w io.Writer) {
	names := make([]string, 0, len(externalEnvVars))
	for _, entry := range utils.EnvVars() {
		if _, pinned := pinnedByTopology[entry.Name]; pinned {
			continue
		}
		names = append(names, entry.Name)
	}
	for name, external := range externalEnvVars {
		if external.Pinned {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range slices.Compact(names) {
		fmt.Fprintln(w, name)
	}
}

func defaultDisplay(value string) string {
	if value == "" {
		return "(empty)"
	}
	return value
}

func writeCommentWrapped(w io.Writer, text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	const width = 74
	line := "#  "
	for _, word := range strings.Fields(text) {
		if len(line)+len(word)+1 > width && strings.TrimSpace(line) != "#" {
			fmt.Fprintln(w, line)
			line = "#  "
		}
		if line == "#  " {
			line += word
			continue
		}
		line += " " + word
	}
	if strings.TrimSpace(line) != "#" {
		fmt.Fprintln(w, line)
	}
}

// applyEnvFileInIsolation makes the file the whole environment for the pass
// that follows, and returns a function restoring what was there before.
//
// Setting only the file's own keys is not enough. A relay variable absent from
// the file would stay inherited from the shell, and a higher-priority alias in
// the shell would beat a value the file does supply — process AWS_REGION over
// file AWS_DEFAULT_REGION, for instance. The report would then describe a mix
// of file and shell, not the file against relay defaults. Isolation is for
// that mix. It does not reproduce Compose; Compose injects its own defaults.
// For that environment run the command inside the container.
func applyEnvFileInIsolation(entries []envFileEntry) (func(), error) {
	// A first pass populates the registry, which is how the set of names the
	// deployment understands is known at all.
	if _, err := resolveRelayServerConfig(nil); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(externalEnvVars))
	for _, entry := range utils.EnvVars() {
		names = append(names, entry.Name)
		names = append(names, entry.Aliases...)
	}
	for name := range externalEnvVars {
		names = append(names, name)
	}
	for _, entry := range entries {
		names = append(names, entry.Name)
	}

	type saved struct {
		value string
		set   bool
	}
	previous := make(map[string]saved, len(names))
	restore := func() {
		for name, prior := range previous {
			if prior.set {
				_ = os.Setenv(name, prior.value)
				continue
			}
			_ = os.Unsetenv(name)
		}
	}

	for _, name := range names {
		if _, recorded := previous[name]; recorded {
			continue
		}
		value, set := os.LookupEnv(name)
		previous[name] = saved{value: value, set: set}
		if err := os.Unsetenv(name); err != nil {
			restore()
			return nil, fmt.Errorf("isolate %s: %w", name, err)
		}
	}

	for _, entry := range entries {
		if err := os.Setenv(entry.Name, entry.Value); err != nil {
			restore()
			return nil, fmt.Errorf("apply %s: %w", entry.Name, err)
		}
	}
	return restore, nil
}

func runConfigCommand(args []string) error {
	var (
		envFilePath string
		format      string
	)
	fs := utils.NewFlagSet("relay-server config", printConfigUsage)
	utils.StringFlag(fs, &envFilePath, "env-file", "",
		"read this file in place of the process environment, against relay defaults. "+
			"Compose supplies its own defaults on top of a file, so to see what a Compose "+
			"deployment will actually run, omit this flag and let Compose build the environment: "+
			"docker compose run --rm -T portal config")
	utils.StringFlag(fs, &format, "format", "text", "output format: text, env or names")

	if err := utils.ParseFlagSet(fs, args, printConfigUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "relay-server config"); err != nil {
		printConfigUsage(os.Stderr)
		return err
	}

	var entries []envFileEntry
	source := "process environment"
	if strings.TrimSpace(envFilePath) != "" {
		loaded, err := loadEnvFile(envFilePath)
		if err != nil {
			return fmt.Errorf("read env file: %w", err)
		}
		restore, err := applyEnvFileInIsolation(loaded)
		if err != nil {
			return err
		}
		defer restore()
		entries = loaded
		source = envFilePath
	}

	cfg, err := resolveRelayServerConfig(nil)
	if err != nil {
		return err
	}

	switch strings.TrimSpace(format) {
	case "", "text":
		writeConfigReport(os.Stdout, cfg, entries, source)
		return nil
	case "env":
		writeEnvReference(os.Stdout)
		return nil
	case "names":
		writeEnvNames(os.Stdout)
		return nil
	default:
		printConfigUsage(os.Stderr)
		return fmt.Errorf("unknown format %q", format)
	}
}

func printConfigUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"relay-server config [--env-file PATH] [--format text|env]",
		},
		[]string{
			"docker compose run --rm -T portal config    # what Compose will run",
			"relay-server config                         # this process environment",
			"relay-server config --env-file .env         # one file, against relay defaults",
			"relay-server config --format env > env.reference",
		},
	)
}

// envIssueError turns recorded parse failures into a startup error. A value
// that cannot be parsed is always a mistake, and falling back silently is what
// let deployments run for months with settings nothing read.
func envIssueError() error {
	issues := utils.EnvIssues()
	if len(issues) == 0 {
		return nil
	}
	messages := make([]string, 0, len(issues))
	for _, issue := range issues {
		messages = append(messages, fmt.Sprintf("%s=%q: %s", issue.Name, issue.Value, issue.Problem))
	}
	slices.Sort(messages)
	return errors.New("invalid environment values: " + strings.Join(messages, "; "))
}
