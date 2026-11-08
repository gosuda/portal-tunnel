# Embedding the Portal SDK in a Go app

Use this reference only when the app is written in Go and the user wants the tunnel to live inside the app process instead of running the `portal` CLI next to it. For every other language, and for most Go apps, the CLI path in `SKILL.md` is the right answer: it is what the relay websites, the docs, and the agent config all assume.

Last checked against `gosuda/portal-tunnel` release `v2.7.3` (commit `e10679a5`) on 2026-11-08 (module `github.com/gosuda/portal-tunnel/v2`, `go 1.27.3`). The Go API is described in `docs/maintainer/architecture.md` and by the code's doc comments, and the docs site's SDK API page (`docs/src/routes/api-reference/sdk/+page.md`) covers the sign-in gate; read `sdk/expose.go`, `sdk/http.go`, `sdk/proxy.go`, `sdk/appauth/`, `cmd/demo-app/main.go`, and `cmd/payment-app/` when something here does not match.

## Smallest working program

```go
package main

import (
	"cmp"
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// name applies only when the identity file does not exist yet.
	id, err := identity.LoadOrCreate("my-app", os.Getenv("PORTAL_IDENTITY_PATH"), os.Getenv("IDENTITY_JSON"))
	if err != nil {
		log.Fatal(err)
	}

	exposure, err := sdk.Expose(ctx, id, nil,
		sdk.WithDiscovery(3), // bootstrap relays plus discovery; nil relays is allowed only with this option
		sdk.WithMetadata(types.LeaseMetadata{Description: "my app"}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer exposure.Close() // RunHTTP does not close the exposure for you

	go func() {
		if relays, err := exposure.WaitReady(ctx); err == nil {
			log.Printf("open: %s", cmp.Or(relays[0].AliasURL, relays[0].PublicURL))
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hello")) })
	if err := sdk.RunHTTP(ctx, exposure, mux, ""); err != nil { // "" = no extra local listener
		log.Fatal(err)
	}
}
```

```
module example.com/myapp

go 1.27.3

require github.com/gosuda/portal-tunnel/v2 v2.7.3
```

The sign-in gate below needs `v2.7.3` or later.

`sdk.Exposure` is a `net.Listener`, so `http.Serve(exposure, handler)` also works; `sdk.RunHTTP` adds header and idle timeouts, an optional second local listener, and a five-second graceful shutdown.

## Identity

- `identity.LoadOrCreate(name, path, rawJSON)`: an in-memory JSON payload wins, then an existing file at `path` is parsed as-is, and only when neither exists is a new identity generated with `name` (which may be empty for an unnamed service) and written to `path` with mode `0600`. An existing file supplies the public name; `name` never renames it. One identity file per public name.
- The file holds private key material (`private_key` or `mnemonic` plus `derivation_path`). Keep it outside the repository and out of images and logs. Empty `path` keeps the identity in memory only, which means a new hostname on every start.
- `sdk.Expose` requires a fully resolved identity with name, address, and keys. Always go through `identity.LoadOrCreate`, `identity.Parse`, or `identity.Generate`; a hand-built struct is rejected.
- Names are normalized to a DNS label whose ASCII form is limited to 63 characters, or empty for an unnamed service. Relays that predate long-name support accept at most 22. Relays return the address-only canonical hostname (`<address>.<relay-host>`) when name is empty, or both the friendly hostname and the full-address canonical hostname when named; SDK readiness URLs use the returned canonical hostname as the stable browser origin.

## Relays and readiness

- Explicit relays are always kept. `sdk.WithDiscovery(n)` adds the bootstrap set from `registry.json` and keeps at most `n` auto-selected relays connected (default 3 when `n <= 0`). Without the option at least one explicit relay is required, and nothing else is ever contacted, which keeps tests hermetic.
- `sdk.WithOverlay()` is the `--overlay` equivalent.
- Read the public URL from `exposure.WaitReady(ctx)`, from `exposure.Relays()` (sorted snapshot), or from `exposure.Updates()` (buffered channel of size one; slow readers miss intermediate states and should re-read `Relays()`). The SDK also logs `service ready at <url>` with field `public_url`, exactly like the CLI.
- `RelayStatus.Approval` is `pending` or `refused` while the relay refuses the lease, and `Message()` gives the wording to show. Empty never means approved. See the SDK API reference for old and new SDK and relay pairs.
- `RelayStatus` carries `RelayURL`, `PublicURL`, `AliasURL`, `AliasSince` (when the exposure came to hold `AliasURL`), `TCPAddr`, `UDPAddr`, `Version`, `State` (`connecting`, `ready`, `failed`), and `Failure` (`runtime`, `terminal`, `mitm`). One failed relay does not stop an exposure that has healthy ones.
- `PublicURL` is the identity-bound canonical URL; it always routes to this exposure. `AliasURL` is `<name>.<root host>` when the relay granted that alias to the lease, and empty when another identity owns the name or the exposure is unnamed. Both URLs stay set while the lease is held, including `connecting` while reverse sessions reconnect; a failed relay clears `AliasURL`. While `State` is `ready`, prefer `AliasURL` for user-facing links and sharing, falling back to `PublicURL` when empty. Never derive an alias by stripping the address suffix. The friendly alias always reaches the live origin; the opt-in relay cache serves only the canonical hostname.
- Lease renewal, re-registration after a relay restart, and reverse-session pooling are handled inside the SDK. The app does nothing for them.

## What the handler sees

- Tenant TLS is terminated inside the SDK using the relay's certificate through the keyless signer; session keys never leave the process, and the handler receives plain HTTP. This is the same end-to-end property the CLI gives.
- `r.TLS` is always nil, because the terminated connection is not a `crypto/tls` conn. Do not gate Secure cookies or scheme detection on it; the public scheme is always `https` for the tunnel hostname.
- `r.Host` is the real public hostname. `r.RemoteAddr` is the relay end of the SDK's own outbound connection, never the browser. `sdk.RunHTTP` sets `X-Forwarded-Proto: https` on tunneled requests, and Portal adds no `X-Forwarded-For` or `X-Real-IP`, so the real client IP is not available in-process.
- WebSockets and other upgrades work; the tunnel is a byte-transparent `net.Conn`.
- To proxy to local services instead of handling in-process: `sdk.NewHTTPRoutes([]sdk.HTTPRouteConfig{{Prefix: "/", Upstream: "127.0.0.1:3000"}})` returns an `http.Handler`; `StaticRoot` serves a directory as an SPA. `sdk.Proxy(ctx, exposure, "127.0.0.1:3000")` forwards raw streams and closes the exposure when it returns, so do not also `defer exposure.Close()` on that path.

## Sign-in for visitors

Use `github.com/gosuda/portal-tunnel/v2/sdk/appauth` when only chosen people should open the app. It is the gate of `portal expose --auth`, as an `http.Handler`, and takes the same providers: `credential`, `siwe`, `oidc`, `saml`, and `email`. Read `application-auth.md` to choose a provider and to set up the provider side; only the wiring differs.

```go
cfg := appauth.Config{
	Provider:    appauth.ProviderCredential,
	Allow:       []string{"alice"},
	PublicHosts: publicHosts(exposure),
}
gate, err := appauth.New(mux, id, cfg) // an error here is a mistake in cfg
if err != nil {
	log.Fatal(err)
}
if err := sdk.RunHTTP(ctx, exposure, gate, ""); err != nil {
	log.Fatal(err)
}
```

```go
// publicHosts lists the hosts the exposure holds now. The gate calls it on every request.
func publicHosts(exposure *sdk.Exposure) func() []appauth.PublicHost {
	return func() []appauth.PublicHost {
		var hosts []appauth.PublicHost
		for _, relay := range exposure.Relays() {
			hosts = append(hosts,
				appauth.PublicHost{URL: relay.PublicURL},
				appauth.PublicHost{URL: relay.AliasURL, Since: relay.AliasSince})
		}
		return hosts
	}
}
```

- Set `Config.PublicHosts` for every provider, as above. With it the gate answers `421` for any host the exposure does not hold now, and a session or a sign-in on the alias must be newer than `AliasSince`, so visitors on the alias sign in again after a restart or a re-registration, while sessions on `PublicURL` stay. Without it the gate believes the request's `Host`, and `appauth.New` refuses `email`. Credentials are not dated, so issue them for `PublicURL`.
- `appauth.New` reads no network. Call `appauth.Check(ctx, cfg)` at startup and show the result: a provider that cannot be reached still serves existing sessions.
- The handler reads the visitor with `appauth.PrincipalFromContext(r.Context())`, which returns `Provider`, `Subject` and `Email`. It works without identity headers. Set `Config.IdentityHeaders` only when the handler proxies to something else that needs the `X-Portal-*` headers.
- List `Allow` for `siwe` and `credential`, and `EmailList` for `oidc`, `saml` and `email`. `oidc`, `saml` and `email` refuse an empty list, but an empty `Allow` opens `siwe` to any wallet and `credential` to any credential issued from the identity, so always list who may open the app.
- A gate built with the same identity and provider settings keeps existing sessions. Prefer one gate with `next` swapped behind it: a rebuild ends a SIWE login in progress and unused email links.
- Store the identity with `identity.Marshal`, never `json.Marshal`, which leaves out the `TokenSecret` that session keys derive from.
- Serve no routes of your own under `appauth.ReservedPathPrefix` (`/_portal/auth/`).
- The gate protects the handler it wraps and nothing else. Do not combine it with `sdk.WithStaticRelayCache`, `sdk.WithTCP` or `sdk.WithUDP`: their traffic never passes through the handler, and `appauth.New` cannot see them.
- An identity provider needs one registered callback per host: `https://<host>/_portal/auth/callback` for the canonical host on each relay, and for the alias if you share it.

## Raw TCP and UDP

- `sdk.WithTCP()` requests a public TCP port; `exposure.WaitTCPReady(ctx)` returns snapshots with `TCPAddr`. Raw connections arrive on `exposure.Accept()` untouched, with no TLS, so do not serve such an exposure with `sdk.RunHTTP`: it labels every request it receives `https`, raw ones included.
- `sdk.WithUDP()` enables datagrams; `exposure.WaitDatagramReady(ctx)` returns `UDPAddr`. The app receives `types.DatagramFrame` values from `exposure.AcceptDatagram()` and must reuse the accepted frame, replace only its `Payload`, and pass it to `exposure.SendDatagram` for replies; this preserves its local `LeaseDone` ownership token, and a fresh frame with only the flow ID and address is refused. A reply on a lease that has ended fails with an error wrapping `net.ErrClosed`, even after a new lease has reconnected: drop that reply and keep receiving. `sdk.ProxyUDP` does all this against a local UDP target. Flows idle for five minutes are dropped; datagrams above 1238 bytes are dropped.
- Both wait functions error when the matching option was not set.

A UDP reply inside the receive loop:

```go
frame.Payload = reply
if err := exposure.SendDatagram(frame); err != nil {
	if errors.Is(err, net.ErrClosed) {
		continue // the lease that delivered frame has ended
	}
	return err
}
```

## Options and their limits

- `sdk.WithMetadata(types.LeaseMetadata{Description, Owner, Thumbnail, Tags, Hide})` sets the listing entry; `exposure.UpdateMetadata` changes it at the next renewal. `Hide: true` keeps the service out of `/api/state` and the public directory.
- `sdk.WithStaticRelayCache(path, ttl)` lets the selected relays store a static site and terminate browser TLS for it. It cannot be combined with TCP, UDP, or MITM blocking, and it changes the trust boundary in the same way `--cache` does.
- `sdk.WithMITMProtection(true)` is `--ban-mitm`: the SDK self-probes its public URL and bans a relay whose exported TLS keying material does not match. It fails at start against a relay whose tenant TLS stack cannot export keying material.

## Shutdown and errors

- Cancel the context or call `exposure.Close()`; each listener unregisters its lease with a five-second budget, so hostnames free up on clean exit.
- The SDK exports no sentinel errors. Match `net.ErrClosed` and `context.Canceled` as normal shutdown, and relay API failures with `errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeHostnameConflict})` and the other codes in `types/error.go`. Any `4xx` at registration or renewal ends that relay with `Failure` `terminal`, for example `hostname_conflict`, `feature_unavailable`, `transport_mismatch`, `udp_disabled`, or `tcp_port_disabled`. The exceptions: `rate_limited` waits for `Retry-After`, and `lease_not_found` or `unauthorized` for a lease already held make the SDK register again. Network errors, `5xx`, and a reverse connection refused while approval is pending are retried for you.

## Paid routes

The SDK is payment-agnostic. The x402 gateway lives in `cmd/portal-tunnel/agent`, which is CLI composition, not an SDK contract; do not import it into an app. An app that needs x402 wires `github.com/gosuda/x402-facilitator` directly, the way `cmd/payment-app/handler.go` does: build `PaymentRequirements`, create the Sui facilitator, wrap only the paid handler with `x402http.New(...).Wrap(...)`, and mount `suihttp.ClientHandler()` at `/x402/client.js` and `suihttp.NewPrepareHandler(...)` at `/x402/prepare` so browser and native clients can pay. On the consumer side, `portal-connect` recognizes and reports a `402`; paying it is a planned separate skill.

## Verify like the CLI

Whatever the app logs, verify from outside exactly as `SKILL.md` step 6 says: one bounded request to the URL being handed off (`AliasURL` when granted, otherwise `PublicURL`), `401` or `403` counted as reachable, and the lease visible in `GET <relay>/api/state` with `ready > 0`.
