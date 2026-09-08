package acme

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// fakeZone models what the real providers do to a zone rather than which calls
// they received, so a test can assert on the records an operator would see.
//
// EnsureTXTRecord appends when the value differs, matching cloudflare, njalla
// and route53. DNS-01 depends on that, and it is also what lets ENS records
// pile up, so a fake that replaced instead would hide the bug under test.
type fakeZone struct {
	mu  sync.Mutex
	txt map[string][]string
	a   map[string]string
}

func newFakeZone() *fakeZone {
	return &fakeZone{txt: map[string][]string{}, a: map[string]string{}}
}

func (z *fakeZone) txtValues(name string) []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string(nil), z.txt[name]...)
}

func (z *fakeZone) hasARecord(name string) bool {
	z.mu.Lock()
	defer z.mu.Unlock()
	_, ok := z.a[name]
	return ok
}

func (z *fakeZone) Name() string { return TypeEmbedded }

func (z *fakeZone) ChallengeProvider(context.Context) (challenge.Provider, error) {
	return nil, nil
}

func (z *fakeZone) EnsureARecords(_ context.Context, baseDomain, publicIPv4 string) error {
	return z.EnsureARecord(context.Background(), baseDomain, publicIPv4)
}

func (z *fakeZone) EnsureARecord(_ context.Context, name, publicIPv4 string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.a[name] = publicIPv4
	return nil
}

func (z *fakeZone) DeleteARecord(_ context.Context, name string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	delete(z.a, name)
	return nil
}

func (z *fakeZone) EnsureTXTRecord(_ context.Context, name, value string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if slices.Contains(z.txt[name], value) {
		return nil
	}
	z.txt[name] = append(z.txt[name], value)
	return nil
}

func (z *fakeZone) DeleteTXTRecords(_ context.Context, name, matchPrefix string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	kept := z.txt[name][:0]
	for _, value := range z.txt[name] {
		if !strings.HasPrefix(value, matchPrefix) {
			kept = append(kept, value)
		}
	}
	if len(kept) == 0 {
		delete(z.txt, name)
		return nil
	}
	z.txt[name] = kept
	return nil
}

func (z *fakeZone) EnsureHTTPSRecord(context.Context, string, dnsrecord.HTTPSRecord) error {
	return nil
}

func (z *fakeZone) DeleteHTTPSRecord(context.Context, string) error { return nil }

func (z *fakeZone) EnsureDNSSEC(context.Context, string) (string, string, string, error) {
	return "", "", "", nil
}

func newTestENSManager(cfg Config, dns DNSProvider) *Manager {
	cfg.BaseDomain = utils.NormalizeBaseDomain(cfg.BaseDomain)
	return &Manager{
		cfg:         cfg,
		dns:         dns,
		stopCh:      make(chan struct{}),
		echCommands: make(chan echDNSCommand, 8),
		ensCommands: make(chan ensDNSCommand, 8),
		ensStatus:   utils.NewSnapshot(newENSStatus(cfg, dns)),
	}
}

func ensTXTValues(t *testing.T, zone *fakeZone, name string) []string {
	t.Helper()
	var ens []string
	for _, value := range zone.txtValues(name) {
		if strings.HasPrefix(value, gaslessENSTXTPrefix) {
			ens = append(ens, value)
		}
	}
	return ens
}

// A hostname carries exactly one ENS1 record. Publishing a second address must
// leave that one record holding the new address, not two records disagreeing.
func TestENSGaslessAddressChangeLeavesOneRecord(t *testing.T) {
	const host = "portal.example.com"
	const challengeValue = "acme-challenge-token"

	zone := newFakeZone()
	if err := zone.EnsureTXTRecord(context.Background(), host, challengeValue); err != nil {
		t.Fatalf("seed DNS-01 record: %v", err)
	}

	manager := newTestENSManager(Config{
		BaseDomain:        host,
		KeyDir:            t.TempDir(),
		ENSGaslessEnabled: true,
	}, zone)

	first := "0x1111111111111111111111111111111111111111"
	second := "0x2222222222222222222222222222222222222222"
	for _, address := range []string{first, second} {
		err := manager.applyENSCommand(context.Background(), ensDNSCommand{hostname: host, address: address})
		if err != nil {
			t.Fatalf("applyENSCommand(%s): %v", address, err)
		}
	}

	ens := ensTXTValues(t, zone, host)
	if len(ens) != 1 {
		t.Fatalf("ENS1 records = %v, want exactly one", ens)
	}
	if !strings.HasSuffix(ens[0], second) {
		t.Fatalf("ENS1 record = %q, want the current address %s", ens[0], second)
	}

	if !slices.Contains(zone.txtValues(host), challengeValue) {
		t.Fatalf("TXT records = %v, want the DNS-01 record left untouched", zone.txtValues(host))
	}
}

// Disabling the feature must let the relay withdraw what it published; gating
// removal on the same flag leaves the zone frozen with no path back.
func TestENSGaslessLeaseRemovalRunsWhenDisabled(t *testing.T) {
	const host = "lease.portal.example.com"

	zone := newFakeZone()
	manager := newTestENSManager(Config{
		BaseDomain:        "portal.example.com",
		KeyDir:            t.TempDir(),
		ENSGaslessEnabled: false,
	}, zone)

	// State a previous run left behind while the feature was still enabled.
	ctx := context.Background()
	if err := zone.EnsureTXTRecord(ctx, host, gaslessENSTXTPrefix+"resolver 0x3333"); err != nil {
		t.Fatalf("seed ENS record: %v", err)
	}
	if err := zone.EnsureARecord(ctx, host, "203.0.113.10"); err != nil {
		t.Fatalf("seed A record: %v", err)
	}

	if err := manager.DeleteENSGaslessHostname(ctx, host); err != nil {
		t.Fatalf("DeleteENSGaslessHostname(): %v", err)
	}

	var command ensDNSCommand
	select {
	case command = <-manager.ensCommands:
	default:
		t.Fatal("DeleteENSGaslessHostname() queued nothing; every published record would stay orphaned")
	}
	if err := manager.applyENSCommand(ctx, command); err != nil {
		t.Fatalf("applyENSCommand(): %v", err)
	}

	if ens := ensTXTValues(t, zone, host); len(ens) != 0 {
		t.Fatalf("ENS1 records = %v, want them withdrawn", ens)
	}
	if zone.hasARecord(host) {
		t.Fatalf("A record for %s survived the removal", host)
	}
}

// The startup reconcile is the only thing that reaches hostnames tracked by an
// earlier run, so it has to keep running after the feature is switched off.
func TestENSGaslessReconcileRunsWhenDisabled(t *testing.T) {
	const host = "lease.portal.example.com"

	keyDir := t.TempDir()
	trackedPath := filepath.Join(keyDir, ensGaslessHostnamesFileName)
	if err := utils.WriteJSONFile(trackedPath, []string{host}, 0o600); err != nil {
		t.Fatalf("seed tracked hostnames: %v", err)
	}

	ctx := context.Background()
	zone := newFakeZone()
	if err := zone.EnsureTXTRecord(ctx, host, gaslessENSTXTPrefix+"resolver 0x4444"); err != nil {
		t.Fatalf("seed ENS record: %v", err)
	}
	if err := zone.EnsureARecord(ctx, host, "203.0.113.11"); err != nil {
		t.Fatalf("seed A record: %v", err)
	}

	manager := newTestENSManager(Config{
		BaseDomain:        "portal.example.com",
		KeyDir:            keyDir,
		ENSGaslessEnabled: false,
	}, zone)

	if err := manager.reconcileTrackedENSGaslessHostnames(ctx); err != nil {
		t.Fatalf("reconcileTrackedENSGaslessHostnames(): %v", err)
	}

	if ens := ensTXTValues(t, zone, host); len(ens) != 0 {
		t.Fatalf("ENS1 records = %v, want them withdrawn", ens)
	}
	if zone.hasARecord(host) {
		t.Fatalf("A record for %s survived the reconcile", host)
	}
	if _, err := os.Stat(trackedPath); !os.IsNotExist(err) {
		t.Fatalf("tracked hostnames file still present (stat err = %v), want it cleared", err)
	}
}
