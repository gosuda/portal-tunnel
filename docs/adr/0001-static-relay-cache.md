# Opt-in static relay cache

The origin declares cache permission in its authenticated registration. The
relay owns admission, disk storage, eviction, and the offline TTL ceiling. No
deployment database, object service, or independent hosting lifecycle is added.

`portal/cache` owns the feature on both sides of the wire. Its `Manager` owns
cache configuration, eligibility, lease events, admission, storage, expiry/LRU,
and serving. The lease registry supplies immutable
`cache.Lease` observations on registration, renewal, and detach; the manager
never receives a `*leaseRecord`. Server integration authenticates SDK requests,
uses the manager's ingress hint, and supplies reverse-stream origin fallback.
The manager consults the existing policy runtime for identity routing policy.
Wire messages remain in `types`; manifest validation, digest computation, and
byte accounting are private cache-domain operations in `portal/cache`.
The relay independently validates every received manifest, regardless of
preflight validation on the client.

`portal expose --serve ./dist --cache` periodically hashes the regular files in
the static root, including its SPA entry. One exposure-owned `cache.Source`
produces a shared immutable manifest every 30 seconds while cache-capable relays
subscribe.
The source bounds discovery by their advertised limits; each `cache.Syncer`
enforces its relay's limits before checking/uploading that manifest. Joining relays
use the current generation, and exposure shutdown stops the source. Each
syncer compares the manifest with its relay. SDK listeners supply current
transport and lease credentials after waiting for the next source generation,
so token renewal remains owned by the SDK. An unchanged snapshot needs no
artifact upload. A changed snapshot invalidates the old cache and is streamed as bounded
multipart data to `/sdk/cache`; the relay validates content hashes and publishes
the complete snapshot atomically. Symlinks and special files are ineligible.
Disk filenames are SHA-256 digests, never client-controlled extraction paths.

Admission is optional. Disabled or older relays, full storage, upload pressure,
disk errors, and rejected snapshots leave the existing origin tunnel usable.
Failed refreshes attempt to invalidate the old snapshot. Cache updates are
eventually visible; files should be immutable between builds. This version
uploads the complete changed snapshot and does not deduplicate across sites.

Staging bytes, retained snapshots, and evicted files still being read all count
toward the relay's payload-byte budget. Deletion failures retain their charge.
Expiration precedes LRU eviction, with hostname order breaking ties. Metadata
is bounded to 2,048 files per snapshot and 128 total snapshots, including
staging and retired snapshots whose files have not been deleted.
Operators configure only enablement, the total payload-byte budget, and the
maximum offline TTL. The manager derives an exposure limit of one quarter of
the total budget, capped at 64 MiB with a one-byte minimum. Objects are bounded
to 10 MiB or the exposure limit, whichever is smaller. Independent internal
pools admit at most two uploads and two manifest checks concurrently.
Upload bodies have a two-minute read deadline;
manifest checks retain a 1 MiB body limit and a ten-second read deadline.
Slow checks cannot consume upload slots. Filesystem block
allocation and metadata overhead require additional disk headroom. The cache
directory lives under the relay state directory as `static-cache` and must be
exclusive to one relay process; generated snapshot directories
are discarded on startup. Cached bytes are disposable, including after a crash.

A successful lease renewal sets the cached snapshot's expiry to
`min(ExpiresAt, LastSeenAt + observationWindow) + CacheTTL`, where the manager's
`observationWindow` is two minutes and `CacheTTL` is the effective, relay-clamped offline
TTL. Unregister may shorten this deadline to the unregister time plus that TTL,
but never extends the existing deadline. After an abrupt disconnect, no renewal
advances the bounded deadline, even if the origin requested a long tunnel lease.
The origin may request a shorter TTL; the relay clamps it to its configured maximum.
Visitor traffic never extends validity. Lease replacement invalidates the old
snapshot, including when the new exposure does not opt in. Upload publication
rechecks the lease instance to prevent late uploads restoring stale content.
Identity approval, denial, and bans apply to cache serving too.

## TLS boundary

The SNI router forwards a hostname to the relay HTTP listener only while an
eligible cached snapshot exists. Ordinary exposures and pre-admission traffic
keep the original TLS passthrough. Cached HTTP GET/HEAD requests use the same
SPA fallback as `--serve`, with ETags, conditional requests, and byte ranges.
Browser responses require revalidation; offline TTL is solely a relay policy.

Once a connection is routed to the cache, the relay terminates its TLS. A miss
caused by concurrent eviction, a missing disk object, or an unsupported method
uses the live reverse stream with authenticated TLS to the origin. **That
connection still trusts the relay; it cannot regain browser-to-origin E2E TLS
after termination.** New connections without an eligible snapshot go through
normal TLS passthrough. The relay never dials a client-supplied origin URL.
Snapshot readers are released before origin fallback. Missing, unreadable, or
truncated disk content invalidates that snapshot so the next manifest check
requests a fresh upload. A failed reader of an older snapshot cannot invalidate
a newer replacement.

Tenant TLS names and HTTP Host headers must match. Tenant requests never reach
control-plane handlers, even for `/sdk`, `/api`, or a forged root Host. ECH and
MITM blocking are incompatible with this explicit trust exception. Selecting
`--cache` trusts every selected relay; use explicit `--relays` together with
`--discovery=false` to choose exactly which relay receives the static content.
