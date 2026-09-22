# Embedding the Portal SDK in a Go app

Use this reference only when the app is written in Go and the user wants the tunnel to live inside the app process instead of running the `portal` CLI next to it. For every other language, and for most Go apps, the CLI path in `SKILL.md` is the right answer: it is what the relay websites, the docs, and the agent config all assume.

Last checked against `gosuda/portal-tunnel` main commit `d38001ad` on 2026-09-22 (module `github.com/gosuda/portal-tunnel/v2`, release `v2.5.0`, `go 1.27`). The Go API is described in `docs/architecture.md` and by the code's doc comments; the published docs site covers the CLI and the relay wire protocol, so read `sdk/expose.go`, `sdk/http.go`, `sdk/proxy.go`, `cmd/demo-app/main.go`, and `cmd/payment-app/` when something here does not match.

## Smallest working program

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func main() {
	ctx, stop := utils.SignalContext() // cancels on SIGINT/SIGTERM
	defer stop()

	// name applies only when the identity file does not exist yet.
	id, err := identity.LoadOrCreate("my-app", "", os.Getenv("PORTAL_IDENTITY_PATH"), os.Getenv("IDENTITY_JSON"))
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
			log.Printf("public url: %s", relays[0].PublicURL)
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

go 1.27.0

require github.com/gosuda/portal-tunnel/v2 v2.5.0
```

`sdk.Exposure` is a `net.Listener`, so `http.Serve(exposure, handler)` also works; `sdk.RunHTTP` adds header and idle timeouts, an optional second local listener, and a five-second graceful shutdown.

## Identity

- `identity.LoadOrCreate(name, target, path, rawJSON)`: an in-memory JSON payload wins, then an existing file at `path` is parsed as-is, and only when neither exists is a new identity generated with `name` and written to `path` with mode `0600`. An existing file supplies the public name; `name` never renames it. One identity file per public name.
- The file holds private key material (`private_key` or `mnemonic` plus `derivation_path`). Keep it outside the repository and out of images and logs. Empty `path` keeps the identity in memory only, which means a new hostname on every start.
- `sdk.Expose` requires a fully resolved identity with name, address, and keys. Always go through `identity.LoadOrCreate`, `identity.Parse`, or `identity.Generate`; a hand-built struct is rejected.

## Relays and readiness

- Explicit relays are always kept. `sdk.WithDiscovery(n)` adds the bootstrap set from `registry.json` and keeps at most `n` auto-selected relays connected (default 3 when `n <= 0`). Without the option at least one explicit relay is required, and nothing else is ever contacted, which keeps tests hermetic.
- `sdk.WithOverlay()` is the `--overlay` equivalent.
- Read the public URL from `exposure.WaitReady(ctx)`, from `exposure.Relays()` (sorted snapshot), or from `exposure.Updates()` (buffered channel of size one; slow readers miss intermediate states and should re-read `Relays()`). The SDK also logs `service ready at <url>` with field `public_url`, exactly like the CLI.
- `RelayStatus` carries `RelayURL`, `PublicURL`, `TCPAddr`, `UDPAddr`, `Version`, `State` (`connecting`, `ready`, `failed`), and `Failure` (`runtime`, `terminal`, `mitm`). One failed relay does not stop an exposure that has healthy ones.
- Lease renewal, re-registration after a relay restart, and reverse-session pooling are handled inside the SDK. The app does nothing for them.

## What the handler sees

- Tenant TLS is terminated inside the SDK using the relay's certificate through the keyless signer; session keys never leave the process, and the handler receives plain HTTP. This is the same end-to-end property the CLI gives.
- `r.TLS` is always nil, because the terminated connection is not a `crypto/tls` conn. Do not gate Secure cookies or scheme detection on it; the public scheme is always `https` for the tunnel hostname.
- `r.Host` is the real public hostname. `r.RemoteAddr` is the relay end of the SDK's own outbound connection, never the browser. Portal injects no `X-Forwarded-*` headers on tunneled traffic, so the real client IP is not available in-process.
- WebSockets and other upgrades work; the tunnel is a byte-transparent `net.Conn`.
- To proxy to local services instead of handling in-process: `sdk.NewHTTPRoutes([]sdk.HTTPRouteConfig{{Prefix: "/", Upstream: "127.0.0.1:3000"}})` returns an `http.Handler`; `StaticRoot` serves a directory as an SPA. `sdk.Proxy(ctx, exposure, "127.0.0.1:3000")` forwards raw streams and closes the exposure when it returns, so do not also `defer exposure.Close()` on that path.

## Raw TCP and UDP

- `sdk.WithTCP()` requests a public TCP port; `exposure.WaitTCPReady(ctx)` returns snapshots with `TCPAddr`. Raw connections arrive on `exposure.Accept()` untouched, with no TLS.
- `sdk.WithUDP()` enables datagrams; `exposure.WaitDatagramReady(ctx)` returns `UDPAddr`. The app receives `types.DatagramFrame` values from `exposure.AcceptDatagram()` and must echo the same frame's `FlowID`, `RelayURL`, and `Address` into `exposure.SendDatagram` for replies. `sdk.ProxyUDP` does this against a local UDP target. Flows idle for five minutes are dropped; datagrams above 1350 bytes are dropped.
- Both wait functions error when the matching option was not set.

## Options and their limits

- `sdk.WithMetadata(types.LeaseMetadata{Description, Owner, Thumbnail, Tags, Hide})` sets the listing entry; `exposure.UpdateMetadata` changes it at the next renewal. `Hide: true` keeps the service out of `/api/state` and landing pages.
- `sdk.WithStaticRelayCache(path, ttl)` lets the selected relays store a static site and terminate browser TLS for it. It cannot be combined with TCP, UDP, or MITM blocking, and it changes the trust boundary in the same way `--cache` does.
- `sdk.WithMITMProtection(true)` is `--ban-mitm`: the SDK self-probes its public URL and bans a relay whose exported TLS keying material does not match. It fails at start against a relay whose tenant TLS stack cannot export keying material.

## Shutdown and errors

- Cancel the context or call `exposure.Close()`; each listener unregisters its lease with a five-second budget, so hostnames free up on clean exit.
- The SDK exports no sentinel errors. Match `net.ErrClosed` and `context.Canceled` as normal shutdown, and relay API failures with `errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeHostnameConflict})` and the other codes in `types/error.go`. `hostname_conflict`, `feature_unavailable`, `transport_mismatch`, `udp_disabled`, and `tcp_port_disabled` are terminal for that relay; `lease_not_found`, `unauthorized`, `rate_limited`, and network errors are retried for you.

## Paid routes

The SDK is payment-agnostic. The x402 gateway lives in `cmd/portal-tunnel/agent`, which is CLI composition, not an SDK contract; do not import it into an app. An app that needs x402 wires `github.com/gosuda/x402-facilitator` directly, the way `cmd/payment-app/handler.go` does: build `PaymentRequirements`, create the Sui facilitator, wrap only the paid handler with `x402http.New(...).Wrap(...)`, and mount `suihttp.ClientHandler()` at `/x402/client.js` and `suihttp.NewPrepareHandler(...)` at `/x402/prepare` so browser and native clients can pay. The consumer side of that flow is documented in the `portal-connect` skill.

## Verify like the CLI

Whatever the app logs, verify from outside exactly as `SKILL.md` step 6 says: one bounded request to the `public_url`, `401` or `403` counted as reachable, and the lease visible in `GET <relay>/api/state` with `ready > 0`.
