package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/pgns"
	"github.com/gosuda/portal-tunnel/v2/pgns/sequencer"
	"github.com/gosuda/portal-tunnel/v2/pgns/witness"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
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

func TestResolveACMEIssuerAndUnnamedSiteIdentity(t *testing.T) {
	if got, err := resolveACMEIssuer("", "https://acme-v02.api.letsencrypt.org/directory"); err != nil || got != "letsencrypt.org" {
		t.Fatalf("resolveACMEIssuer(letsencrypt) = (%q, %v), want (letsencrypt.org, nil)", got, err)
	}
	if got, err := resolveACMEIssuer("", "https://dv.acme-v02.api.pki.goog/directory"); err != nil || got != "pki.goog" {
		t.Fatalf("resolveACMEIssuer(pki.goog) = (%q, %v), want (pki.goog, nil)", got, err)
	}
	if got, err := resolveACMEIssuer("Custom.CA.Example.", "https://acme.custom-ca.example/directory"); err != nil || got != "custom.ca.example" {
		t.Fatalf("resolveACMEIssuer(explicit) = (%q, %v), want (custom.ca.example, nil)", got, err)
	}
	if _, err := resolveACMEIssuer("", "https://acme.custom-ca.example/directory"); !errors.Is(err, errPGNSACMEIssuerRequired) {
		t.Fatalf("resolveACMEIssuer(unknown host) = %v, want errPGNSACMEIssuerRequired", err)
	}

	master, err := identity.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	sitePriv, fqdn, svc, err := derivePGNSSiteIdentity(master.PrivateKey, "portal.example", "", "", "")
	if err != nil {
		t.Fatalf("derivePGNSSiteIdentity(unnamed): %v", err)
	}
	if svc != types.UnnamedServiceLabel || !strings.HasPrefix(fqdn, types.UnnamedServiceLabel+".") {
		t.Fatalf("unnamed derivation = (%q, %q), want default.<id-tag>.id.portal.example", fqdn, svc)
	}
	unnamedSite, err := buildSiteIdentity(sitePriv, svc)
	if err != nil {
		t.Fatalf("buildSiteIdentity(unnamed): %v", err)
	}
	if unnamedSite.Name != "" {
		t.Fatalf("unnamed site identity Name = %q, want empty string", unnamedSite.Name)
	}
	namedSite, err := buildSiteIdentity(sitePriv, "api")
	if err != nil {
		t.Fatalf("buildSiteIdentity(api): %v", err)
	}
	if namedSite.Name != "api" {
		t.Fatalf("named site identity Name = %q, want api", namedSite.Name)
	}
}

func TestPGNSControllerEvaluateFailoverAndFailback(t *testing.T) {
	const r1 = "https://r1.portal.example"
	const rNon443 = "https://r8443.portal.example:8443"
	const r2 = "https://r2.portal.example"
	t0 := time.Unix(1_700_000_000, 0).UTC()
	ctrl := &pgnsController{
		relays: []pgnsRelayEndpoint{
			{url: r1, ep: pgns.Endpoint{RelayID: [20]byte{1}, IPv4: [4]byte{93, 184, 216, 34}, Port: 443}},
			{url: rNon443, ep: pgns.Endpoint{RelayID: [20]byte{3}, IPv4: [4]byte{8, 8, 8, 8}, Port: 8443}},
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
	if next, _, _, changed := ctrl.selectPrimarySwitch(t0, map[string]bool{r1: false, rNon443: true, r2: true}); changed {
		t.Fatalf("single failure triggered premature failover to %s", next)
	}

	// If the only healthy standby is on non-443, failover must not select it as primary.
	t1 := t0.Add(6 * time.Second)
	if next, _, _, changed := ctrl.selectPrimarySwitch(t1, map[string]bool{r1: false, rNon443: true, r2: false}); changed {
		t.Fatalf("non-443 standby selected as primary: %s", next)
	}

	// Once port-443 standby r2 is healthy, selectPrimarySwitch picks r2 (skipping rNon443) without mutating currentPrimary prematurely.
	t2 := t1.Add(6 * time.Second)
	next, seq, isFailback, changed := ctrl.selectPrimarySwitch(t2, map[string]bool{r1: false, rNon443: true, r2: true})
	if !changed || isFailback || next != r2 || seq != 2 {
		t.Fatalf("selectPrimarySwitch = (next=%q, seq=%d, isFailback=%v, changed=%v), want (%q, 2, false, true)", next, seq, isFailback, changed, r2)
	}
	if ctrl.currentPrimary != r1 {
		t.Fatalf("selectPrimarySwitch mutated currentPrimary before publish confirmation: %s", ctrl.currentPrimary)
	}
	ctrl.commitPrimarySwitch(t2, next, isFailback)
	ctrl.failbackCooldown = 5 * time.Minute
	ctrl.currentLeaf.Seq = seq

	// Healthy preferred primary before cooldown elapses must not failback immediately.
	t3 := t2.Add(2 * time.Minute)
	if next, _, _, changed := ctrl.selectPrimarySwitch(t3, map[string]bool{r1: true, rNon443: true, r2: true}); changed {
		t.Fatalf("failback occurred before cooldown elapsed: %s", next)
	}

	// After cooldown elapses while preferred primary is healthy, failback occurs cleanly.
	t4 := t2.Add(ctrl.failbackCooldown + time.Second)
	next, seq, isFailback, changed = ctrl.selectPrimarySwitch(t4, map[string]bool{r1: true, rNon443: true, r2: true})
	if !changed || !isFailback || next != r1 || seq != 3 {
		t.Fatalf("post-cooldown failback = (next=%q, seq=%d, isFailback=%v, changed=%v), want (%q, 3, true, true)", next, seq, isFailback, changed, r1)
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
		w, err := witness.New(witness.Config{Zone: zone, Name: name, PrivateKey: priv})
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

	var blockSubmit atomic.Bool
	seqHandler := seq.Handler()
	seqSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if blockSubmit.Load() && r.URL.Path == types.PathV1Submit {
			http.Error(w, "sequencer busy", http.StatusServiceUnavailable)
			return
		}
		seqHandler.ServeHTTP(w, r)
	}))
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
			RelayEndpoints: []string{
				"https://r1.portal.example=93.184.216.34:443",
				"https://r2.portal.example=1.1.1.1:443",
			},
		},
		Identity:  IdentitySpec{Name: "web"},
		Transport: TransportSpec{Target: "127.0.0.1:8080"},
		HTTP:      &HTTPConfig{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctrl, siteIdentity, err := preparePGNSRuntime(ctx, spec, master, []string{"https://r1.portal.example", "https://r2.portal.example"})
	if err != nil {
		t.Fatalf("preparePGNSRuntime: %v", err)
	}
	t.Cleanup(func() { _ = ctrl.close() })
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

	// Verify commit-after-confirm failover retry when publish fails transiently on the first switch attempt.
	const r1 = "https://r1.portal.example"
	const r2 = "https://r2.portal.example"
	tSwitch := time.Now().UTC()
	if ctrl.trySwitchPrimary(ctx, tSwitch, map[string]bool{r1: false, r2: true}) {
		t.Fatal("single failure should not switch primary")
	}
	blockSubmit.Store(true)
	shortCtx, cancelShort := context.WithTimeout(ctx, 150*time.Millisecond)
	switched := ctrl.trySwitchPrimary(shortCtx, tSwitch.Add(6*time.Second), map[string]bool{r1: false, r2: true})
	cancelShort()
	blockSubmit.Store(false)
	if switched || ctrl.currentPrimary != r1 {
		t.Fatalf("failed publish must not commit primary switch: switched=%v currentPrimary=%s", switched, ctrl.currentPrimary)
	}
	if !ctrl.trySwitchPrimary(ctx, tSwitch.Add(12*time.Second), map[string]bool{r1: false, r2: true}) {
		t.Fatal("retry after failed publish should succeed and commit primary switch")
	}
	if ctrl.currentPrimary != r2 {
		t.Fatalf("currentPrimary after retry = %s, want %s", ctrl.currentPrimary, r2)
	}
}
