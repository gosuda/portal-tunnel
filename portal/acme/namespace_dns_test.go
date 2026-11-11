package acme

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestCanonicalDNSLifecycleWithoutENS(t *testing.T) {
	const root = "relay.delegated.example.com"
	address := "0x" + strings.Repeat("a", 40)
	first, _ := utils.LocalTLSLeaseHostname("blog", address, root)
	second, _ := utils.LocalTLSLeaseHostname("api", address, root)
	zone := newFakeZone()
	manager := newTestENSManager(Config{BaseDomain: root, KeyDir: t.TempDir()}, zone)
	previous := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPTransport{ip: "203.0.113.10"}}
	t.Cleanup(func() { utils.DefaultHTTPClient = previous })
	ctx := t.Context()
	for _, host := range []string{first, second} {
		if err := manager.SyncLeaseHostname(ctx, host, address); err != nil {
			t.Fatal(err)
		}
		command := <-manager.ensCommands
		if err := manager.applyENSCommand(ctx, command); err != nil {
			t.Fatal(err)
		}
		if !zone.hasARecord(host) || len(zone.txtValues(host)) != 0 {
			t.Fatalf("address-only DNS missing or ENS enabled for %s", host)
		}
	}
	tracked, err := manager.trackedENSGaslessHostnames()
	if err != nil || !slices.Contains(tracked, first) || !slices.Contains(tracked, second) {
		t.Fatalf("tracking: %v %v", tracked, err)
	}
	state := &maintenanceLoopState{lastPublicIPs: map[bool]string{}}
	if err := manager.syncChangedAddressRecords(ctx, state, []string{"203.0.113.11"}); err != nil {
		t.Fatal(err)
	}
	if zone.a[first] != "203.0.113.11" || zone.a[second] != "203.0.113.11" {
		t.Fatal("canonical addresses not refreshed with ENS disabled")
	}
	if err := zone.EnsureTXTRecord(ctx, second, "unrelated TXT"); err != nil {
		t.Fatal(err)
	}
	if err := manager.DeleteLeaseHostname(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := manager.applyENSCommand(ctx, <-manager.ensCommands); err != nil {
		t.Fatal(err)
	}
	if zone.hasARecord(first) || !zone.hasARecord(second) || len(zone.txtValues(second)) != 1 {
		t.Fatal("removal crossed sibling service boundary")
	}
	restarted := newTestENSManager(manager.cfg, zone)
	if err := restarted.reconcileTrackedENSGaslessHostnames(ctx); err != nil {
		t.Fatal(err)
	}
	if zone.hasARecord(second) {
		t.Fatal("restart did not withdraw stale lease address")
	}
	if len(zone.txtValues(second)) != 1 {
		t.Fatal("restart removed unrelated TXT")
	}
}
