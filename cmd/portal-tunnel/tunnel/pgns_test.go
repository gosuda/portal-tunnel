package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/pgns"
	"github.com/gosuda/portal-tunnel/v2/pgns/sequencer"
	"github.com/gosuda/portal-tunnel/v2/pgns/witness"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
)

func TestDerivePGNSSiteIdentity(t *testing.T) {
	master, err := identity.Generate("web")
	if err != nil {
		t.Fatal(err)
	}
	priv1, fqdn1, svc1, err := derivePGNSSiteIdentity(master.PrivateKey, "portal.example", "web", "", "")
	if err != nil {
		t.Fatalf("derivePGNSSiteIdentity(default): %v", err)
	}
	if svc1 != "web" || !strings.HasPrefix(fqdn1, "web.") || !strings.HasSuffix(fqdn1, ".id.portal.example") {
		t.Fatalf("unexpected default id FQDN/service: fqdn=%q svc=%q", fqdn1, svc1)
	}
	priv2, fqdn2, _, err := derivePGNSSiteIdentity(master.PrivateKey, "portal.example", "api", "", "default")
	if err != nil {
		t.Fatalf("derivePGNSSiteIdentity(api, default): %v", err)
	}
	tag1 := strings.Split(fqdn1, ".")[1]
	tag2 := strings.Split(fqdn2, ".")[1]
	if tag1 != tag2 || hex.EncodeToString(priv1.Serialize()) != hex.EncodeToString(priv2.Serialize()) {
		t.Fatalf("same site label across services must share site key and id-tag: %s vs %s", fqdn1, fqdn2)
	}
	_, fqdnIsolated, _, err := derivePGNSSiteIdentity(master.PrivateKey, "portal.example", "web", "", "isolated")
	if err != nil {
		t.Fatalf("derivePGNSSiteIdentity(isolated): %v", err)
	}
	tagIsolated := strings.Split(fqdnIsolated, ".")[1]
	if tagIsolated == tag1 {
		t.Fatalf("distinct site labels must produce unlinkable id-tags: %s == %s", tagIsolated, tag1)
	}
	_, fqdnApp, svcApp, err := derivePGNSSiteIdentity(master.PrivateKey, "portal.example", "ignored", "myapp", "")
	if err != nil {
		t.Fatalf("derivePGNSSiteIdentity(app): %v", err)
	}
	if fqdnApp != "myapp.app.portal.example" || svcApp != "myapp" {
		t.Fatalf("app derivation mismatch: fqdn=%q svc=%q", fqdnApp, svcApp)
	}
}

func TestPGNSControllerEvaluateFailoverAndFailback(t *testing.T) {
	const r1 = "https://r1.portal.example"
	const r2 = "https://r2.portal.example"
	t0 := time.Unix(1_700_000_000, 0).UTC()
	ctrl := &pgnsController{
		relays: []pgnsRelayEndpoint{
			{url: r1, ep: pgns.Endpoint{RelayID: [20]byte{1}, IPv4: [4]byte{93, 184, 216, 34}, Port: 443}},
			{url: r2, ep: pgns.Endpoint{RelayID: [20]byte{2}, IPv4: [4]byte{1, 1, 1, 1}, Port: 443}},
		},
		preferredPrimary: r1,
		currentPrimary:   r1,
		failCounts:       make(map[string]int),
		failbackCooldown: 5 * time.Minute,
		currentLeaf:      pgns.PortalLeafRecord{Seq: 1},
		hasLeaf:          true,
	}

	// Single probe failure must not flap primary.
	if next, _, changed := ctrl.evaluateFailover(t0, map[string]bool{r1: false, r2: true}); changed {
		t.Fatalf("single failure triggered premature failover to %s", next)
	}

	// Two consecutive failures promotes healthy standby r2 at seq+1.
	t1 := t0.Add(6 * time.Second)
	next, seq, changed := ctrl.evaluateFailover(t1, map[string]bool{r1: false, r2: true})
	if !changed || next != r2 || seq != 2 {
		t.Fatalf("second failure = (next=%q, seq=%d, changed=%v), want (%q, 2, true)", next, seq, changed, r2)
	}
	ctrl.currentLeaf.Seq = seq

	// Healthy preferred primary before cooldown elapses must not failback immediately.
	t2 := t1.Add(2 * time.Minute)
	if next, _, changed := ctrl.evaluateFailover(t2, map[string]bool{r1: true, r2: true}); changed {
		t.Fatalf("failback occurred before cooldown elapsed: %s", next)
	}

	// After cooldown elapses while preferred primary is healthy, failback occurs cleanly.
	t3 := t1.Add(ctrl.failbackCooldown + time.Second)
	next, seq, changed = ctrl.evaluateFailover(t3, map[string]bool{r1: true, r2: true})
	if !changed || next != r1 || seq != 3 {
		t.Fatalf("post-cooldown failback = (next=%q, seq=%d, changed=%v), want (%q, 3, true)", next, seq, changed, r1)
	}
}

func TestPGNSControllerRegistrationAndACMELifecycle(t *testing.T) {
	const zone = "portal.example"
	var ws pgns.WitnessSet
	ws.Threshold = 2
	var witnessSpecs []string
	var witnessURLs []string
	for _, name := range []string{"w1", "w2", "w3"} {
		seed := sha256.Sum256([]byte("tunnel-pgns-witness:" + name))
		priv := ed25519.NewKeyFromSeed(seed[:])
		w, err := witness.New(witness.Config{Name: name, PrivateKey: priv})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(w.Handler())
		t.Cleanup(srv.Close)
		ws.Witnesses = append(ws.Witnesses, w.Key())
		witnessSpecs = append(witnessSpecs, name+"="+hex.EncodeToString(w.Key().PublicKey))
		witnessURLs = append(witnessURLs, srv.URL)
	}

	seq, err := sequencer.New(sequencer.Config{
		Zone:             zone,
		WitnessSet:       ws,
		WitnessEndpoints: witnessURLs,
		ActiveInterval:   30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	seqCtx, cancelSeq := context.WithCancel(context.Background())
	defer cancelSeq()
	go func() { _ = seq.Run(seqCtx) }()
	seqSrv := httptest.NewServer(seq.Handler())
	t.Cleanup(seqSrv.Close)

	master, err := identity.Generate("web")
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "pgns-state")
	spec := Spec{
		PGNS: &PGNSConfig{
			Zone:             zone,
			Sequencers:       []string{seqSrv.URL},
			Witnesses:        witnessSpecs,
			WitnessThreshold: 2,
			StateDir:         stateDir,
			ACMECAIssuer:     "pki.goog",
			Persist01:        true,
			RelayEndpoints:   []string{"https://r1.portal.example=93.184.216.34:443"},
		},
		Identity:  IdentitySpec{Name: "web"},
		Transport: TransportSpec{Target: "127.0.0.1:8080"},
		HTTP:      &HTTPConfig{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctrl, siteIdentity, err := preparePGNSRuntime(ctx, spec, master, []string{"https://r1.portal.example"})
	if err != nil {
		t.Fatalf("preparePGNSRuntime: %v", err)
	}
	if siteIdentity.Address == master.Address {
		t.Fatal("PGNS derived site identity should differ from master identity")
	}
	_, initialLeaf, _, err := ctrl.fetchVerifiedResolve(ctx)
	if err != nil {
		t.Fatalf("fetchVerifiedResolve(initial): %v", err)
	}
	if initialLeaf.Seq != 1 || initialLeaf.FQDN != ctrl.fqdn {
		t.Fatalf("initial leaf = %+v", initialLeaf)
	}

	nextSPKI := sha256.Sum256([]byte("next-cert-spki"))
	const accountURI = "https://dv.acme-v02.api.pki.goog/acme/acct/773"
	provider := &pgnsDNS01Provider{
		ctx:        ctx,
		ctrl:       ctrl,
		nextSPKI:   nextSPKI,
		accountURI: accountURI,
	}
	const keyAuth = "token123.thumbprint456"
	wantDigest := sha256.Sum256([]byte(keyAuth))
	if err := provider.Present(ctrl.fqdn, "token123", keyAuth); err != nil {
		t.Fatalf("DNS-01 Present: %v", err)
	}
	_, stagedLeaf, _, err := ctrl.fetchVerifiedResolve(ctx)
	if err != nil {
		t.Fatalf("fetchVerifiedResolve(staged): %v", err)
	}
	if stagedLeaf.ACMEDNS01Digest != wantDigest || stagedLeaf.NextTLSSPKISHA256 != nextSPKI ||
		stagedLeaf.ACMECAIssuer != "pki.goog" || stagedLeaf.ACMEAccountURI != accountURI ||
		stagedLeaf.Flags&pgns.FlagPersist01Enabled == 0 {
		t.Fatalf("staged ACME leaf mismatch: %+v", stagedLeaf)
	}

	if err := provider.CleanUp(ctrl.fqdn, "token123", keyAuth); err != nil {
		t.Fatalf("DNS-01 CleanUp: %v", err)
	}
	_, cleanedLeaf, _, err := ctrl.fetchVerifiedResolve(ctx)
	if err != nil {
		t.Fatalf("fetchVerifiedResolve(cleaned): %v", err)
	}
	if cleanedLeaf.ACMEDNS01Digest != ([32]byte{}) || cleanedLeaf.NextTLSSPKISHA256 != nextSPKI {
		t.Fatalf("cleaned leaf should zero digest and preserve nextSPKI: %+v", cleanedLeaf)
	}

	if err := ctrl.promoteACMEKey(ctx, nextSPKI, accountURI); err != nil {
		t.Fatalf("promoteACMEKey: %v", err)
	}
	_, promotedLeaf, _, err := ctrl.fetchVerifiedResolve(ctx)
	if err != nil {
		t.Fatalf("fetchVerifiedResolve(promoted): %v", err)
	}
	if promotedLeaf.TLSSPKISHA256 != nextSPKI || promotedLeaf.NextTLSSPKISHA256 != ([32]byte{}) {
		t.Fatalf("promoted leaf mismatch: %+v", promotedLeaf)
	}
}
