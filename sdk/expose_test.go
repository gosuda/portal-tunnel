package sdk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/localtls"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestPublicURLForLeaseUsesRelayAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		relayURL string
		want     string
	}{
		{"default HTTPS port", "https://relay.example.com", "https://demo.relay.example.com:443"},
		{"explicit default port", "https://relay.example.com:443", "https://demo.relay.example.com:443"},
		{"explicit public port", "https://relay.example.com:9443", "https://demo.relay.example.com:9443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			relayURL, err := url.Parse(tc.relayURL)
			if err != nil {
				t.Fatal(err)
			}
			l := &listener{api: &apiClient{relayURL: relayURL}}
			got := l.publicURLForLease(listenerSnapshot{
				hostname: "demo.relay.example.com",
			})
			if got != tc.want {
				t.Fatalf("publicURLForLease() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAliasSinceDatesTheCurrentHold(t *testing.T) {
	const relayURL, public, alias = "https://relay.example", "https://long.relay.example", "https://short.relay.example"
	fixture := newAliasSinceHoldFixture(t, relayURL, public, alias)
	checkAliasSinceHoldInitial(t, fixture)
	checkAliasSinceHoldBurst(t, fixture)
	checkAliasSinceHoldLoss(t, fixture)
	checkAliasSinceHoldReacquire(t, fixture)
}

type aliasSinceHoldFixture struct {
	exposure  *Exposure
	relayURL  string
	publicURL string
	aliasURL  string
	first     time.Time
}

func newAliasSinceHoldFixture(t *testing.T, relayURL, publicURL, aliasURL string) *aliasSinceHoldFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	exposure := &Exposure{
		cancel:         cancel,
		done:           ctx.Done(),
		accepted:       make(chan net.Conn, 1),
		relayListeners: make(map[string]*listener),
	}
	return &aliasSinceHoldFixture{exposure: exposure, relayURL: relayURL, publicURL: publicURL, aliasURL: aliasURL}
}

func checkAliasSinceHoldInitial(t *testing.T, fixture *aliasSinceHoldFixture) {
	t.Helper()
	fixture.exposure.applyRelayStatus(fixture.relayURL, listenerStatus{state: RelayReady, publicURL: fixture.publicURL, aliasURL: fixture.aliasURL}, nil)
	first := fixture.exposure.statuses[fixture.relayURL].AliasSince
	if first.IsZero() {
		t.Fatal("a held alias has no date")
	}
	fixture.first = first
}

func checkAliasSinceHoldBurst(t *testing.T, fixture *aliasSinceHoldFixture) {
	t.Helper()
	held := fixture.exposure.statuses[fixture.relayURL]
	held.AliasSince = fixture.first.Add(-time.Hour)
	fixture.exposure.statuses[fixture.relayURL] = held
	fixture.first = held.AliasSince
	fixture.exposure.applyRelayStatus(fixture.relayURL, listenerStatus{state: RelayConnecting, publicURL: fixture.publicURL, aliasURL: fixture.aliasURL}, nil)
	if got := fixture.exposure.statuses[fixture.relayURL].AliasSince; !got.Equal(fixture.first) {
		t.Fatalf("a burst moved the date from %v to %v", fixture.first, got)
	}
}

func checkAliasSinceHoldLoss(t *testing.T, fixture *aliasSinceHoldFixture) {
	t.Helper()
	fixture.exposure.applyRelayStatus(fixture.relayURL, listenerStatus{state: RelayConnecting}, nil)
	if got := fixture.exposure.statuses[fixture.relayURL]; got.AliasURL != "" || !got.AliasSince.IsZero() {
		t.Fatalf("a lost alias kept %q since %v", got.AliasURL, got.AliasSince)
	}
}

func checkAliasSinceHoldReacquire(t *testing.T, fixture *aliasSinceHoldFixture) {
	t.Helper()
	fixture.exposure.applyRelayStatus(fixture.relayURL, listenerStatus{state: RelayReady, publicURL: fixture.publicURL, aliasURL: fixture.aliasURL}, nil)
	if got := fixture.exposure.statuses[fixture.relayURL].AliasSince; got.IsZero() || got.Equal(fixture.first) {
		t.Fatalf("an alias that came back has date %v, the old hold's was %v", got, fixture.first)
	}
}

func TestProxyValidationDoesNotCloseExposure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	exposure := &Exposure{
		cancel:         cancel,
		done:           ctx.Done(),
		accepted:       make(chan net.Conn, 1),
		relayListeners: make(map[string]*listener),
	}
	if err := ProxyWithConfig(ctx, exposure, ProxyConfig{}); err == nil {
		t.Fatal("ProxyWithConfig() succeeded without a target")
	}
	select {
	case <-ctx.Done():
		t.Fatal("ProxyWithConfig() closed exposure during validation")
	default:
	}
	_ = exposure.Close()
}

func TestRelayApprovalReadsTheRefusalCode(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want RelayApproval
	}{
		{&types.APIRequestError{Code: types.APIErrorCodeLeaseRejected}, RelayApprovalPending},
		{fmt.Errorf("open: %w", &types.APIRequestError{Code: types.APIErrorCodeLeaseDenied}), RelayApprovalRefused},
		{&types.APIRequestError{Code: types.APIErrorCodeRateLimited}, ""},
		{&types.APIRequestError{Code: types.APIErrorCodeUnauthorized}, ""},
		{io.EOF, ""},
	} {
		if got := relayApprovalFromError(tc.err); got != tc.want {
			t.Fatalf("relayApprovalFromError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func newRefusalListener(t *testing.T) (*listener, func() listenerStatus, func()) {
	t.Helper()
	relayURL, err := url.Parse("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	l := &listener{
		api:           &apiClient{relayURL: relayURL},
		statusUpdates: make(chan listenerStatus, 8),
		lease: utils.NewSnapshot(listenerSnapshot{
			accessToken: "token",
			hostname:    "demo.relay.example",
			tcpAddr:     "demo.relay.example:40000",
		}),
	}
	update := func() listenerStatus {
		t.Helper()
		select {
		case status := <-l.statusUpdates:
			return status
		default:
			t.Fatal("no status update")
			return listenerStatus{}
		}
	}
	quiet := func() {
		t.Helper()
		select {
		case status := <-l.statusUpdates:
			t.Fatalf("unexpected status update: %+v", status)
		default:
		}
	}
	return l, update, quiet
}

func TestListenerReportsARefusalUntilAStreamOpens(t *testing.T) {
	fixture := newListenerRefusalFixture(t)
	checkListenerRefusalWaiting(t, fixture)
	checkListenerRefusalDenied(t, fixture)
	checkListenerRefusalReady(t, fixture)
	checkListenerRefusalReconnecting(t, fixture)
}

type listenerRefusalFixture struct {
	l       *listener
	update  func() listenerStatus
	quiet   func()
	pending *types.APIRequestError
	denied  *types.APIRequestError
}

func newListenerRefusalFixture(t *testing.T) *listenerRefusalFixture {
	t.Helper()
	l, update, quiet := newRefusalListener(t)
	return &listenerRefusalFixture{
		l:       l,
		update:  update,
		quiet:   quiet,
		pending: &types.APIRequestError{Code: types.APIErrorCodeLeaseRejected},
		denied:  &types.APIRequestError{Code: types.APIErrorCodeLeaseDenied},
	}
}

func checkListenerRefusalWaiting(t *testing.T, fixture *listenerRefusalFixture) {
	t.Helper()
	fixture.l.reportRefusal(fixture.pending)
	if got := fixture.update(); got.state != RelayConnecting || got.approval != RelayApprovalPending || got.publicURL != "" || got.tcpAddr != "" {
		t.Fatalf("waiting status = %+v", got)
	}
}

func checkListenerRefusalDenied(t *testing.T, fixture *listenerRefusalFixture) {
	t.Helper()
	fixture.l.reportRefusal(fixture.pending)
	fixture.quiet()
	fixture.l.reportRefusal(fixture.denied)
	if got := fixture.update(); got.approval != RelayApprovalRefused {
		t.Fatalf("denied status = %+v", got)
	}
}

func checkListenerRefusalReady(t *testing.T, fixture *listenerRefusalFixture) {
	t.Helper()
	fixture.l.reportStreamReady()
	if got := fixture.update(); got.state != RelayReady || got.approval != "" || got.publicURL == "" {
		t.Fatalf("ready status = %+v", got)
	}
	fixture.l.reportRefusal(fixture.pending)
	fixture.quiet()
}

func checkListenerRefusalReconnecting(t *testing.T, fixture *listenerRefusalFixture) {
	t.Helper()
	fixture.l.reportStreamClosed()
	if got := fixture.update(); got.state != RelayConnecting || got.approval != "" {
		t.Fatalf("reconnecting status = %+v", got)
	}
	fixture.l.reportRefusal(fixture.pending)
	if got := fixture.update(); got.approval != RelayApprovalPending {
		t.Fatalf("revoked status = %+v", got)
	}
	fixture.l.clearLease("")
	fixture.l.reportRefusal(fixture.pending)
	fixture.quiet()
}

func TestApprovalKeepsARelayOutOfTheActiveSet(t *testing.T) {
	const relayURL = "https://relay.example"
	exposure := &Exposure{done: make(chan struct{}), updates: make(chan RelayStatus, 8)}
	exposure.setRelayStatus(relayURL, listenerStatus{state: RelayReady, publicURL: "https://demo.relay.example", tcpAddr: "demo.relay.example:40000"})
	if got := exposure.ActiveRelays(); len(got) != 1 {
		t.Fatalf("ActiveRelays() = %v", got)
	}
	exposure.setRelayStatus(relayURL, listenerStatus{state: RelayConnecting, approval: RelayApprovalPending})
	status := exposure.Relays()[0]
	if status.Approval != RelayApprovalPending || status.PublicURL != "" || status.TCPAddr != "" || status.Active() {
		t.Fatalf("waiting status = %+v", status)
	}
	if got := exposure.ActiveRelays(); len(got) != 0 {
		t.Fatalf("ActiveRelays() = %v while the relay refuses the lease", got)
	}
	exposure.setRelayStatus(relayURL, listenerStatus{state: RelayConnecting, approval: RelayApprovalRefused})
	if status := exposure.Relays()[0]; status.Approval != RelayApprovalRefused {
		t.Fatalf("refused status = %+v", status)
	}
	exposure.setRelayStatus(relayURL, listenerStatus{state: RelayReady, publicURL: "https://demo.relay.example"})
	if status := exposure.Relays()[0]; status.Approval != "" || status.State != RelayReady {
		t.Fatalf("approved status = %+v", status)
	}
}

func TestRelaySetChangeKeepsTheStatus(t *testing.T) {
	const waiting, ready = "https://waiting.example", "https://ready.example"
	exposure := &Exposure{done: make(chan struct{}), updates: make(chan RelayStatus, 8)}
	exposure.setRelayStatus(waiting, listenerStatus{state: RelayConnecting, approval: RelayApprovalPending})
	exposure.setRelayStatus(ready, listenerStatus{state: RelayReady, publicURL: "https://demo.ready.example", tcpAddr: "ready.example:40000"})
	before := exposure.Relays()

	exposure.syncRelayStatuses([]string{waiting, ready, "https://added.example"})

	statuses := make(map[string]RelayStatus)
	for _, status := range exposure.Relays() {
		statuses[status.RelayURL] = status
	}
	if len(statuses) != 3 {
		t.Fatalf("Relays() = %+v", statuses)
	}
	for _, status := range before {
		if got := statuses[status.RelayURL]; !relayStatusEqual(got, status) {
			t.Fatalf("status of %s = %+v; want %+v", status.RelayURL, got, status)
		}
	}
}

func TestExposureMetadataCopiesDoNotShareMutableState(t *testing.T) {
	fixture := newExposureMetadataFixture()
	checkExposureMetadataCopyIsolated(t, fixture)
	checkExposureMetadataPropagates(t, fixture)
	checkMetadataRejectsOversize(t, fixture)
}

type exposureMetadataFixture struct {
	exposure *Exposure
	ln       *listener
}

func newExposureMetadataFixture() *exposureMetadataFixture {
	ln := &listener{
		metadata: types.LeaseMetadata{Tags: []string{"initial"}},
	}
	exposure := &Exposure{
		metadata:       types.LeaseMetadata{Tags: []string{"initial"}},
		relayListeners: map[string]*listener{"https://relay.example": ln},
	}
	return &exposureMetadataFixture{exposure: exposure, ln: ln}
}

func checkExposureMetadataCopyIsolated(t *testing.T, fixture *exposureMetadataFixture) {
	t.Helper()
	metadata := fixture.exposure.metadata.Copy()
	metadata.Tags[0] = "mutated"
	if got := fixture.exposure.metadata.Tags[0]; got != "initial" {
		t.Fatalf("Metadata.Tags[0] = %q, want initial", got)
	}
}

func checkExposureMetadataPropagates(t *testing.T, fixture *exposureMetadataFixture) {
	t.Helper()
	if err := fixture.exposure.UpdateMetadata(types.LeaseMetadata{Tags: []string{"updated"}}); err != nil {
		t.Fatalf("UpdateMetadata() error = %v", err)
	}
	if got := fixture.ln.metadataSnapshot().Tags[0]; got != "updated" {
		t.Fatalf("listener Metadata.Tags[0] = %q, want updated", got)
	}
}

func checkMetadataRejectsOversize(t *testing.T, fixture *exposureMetadataFixture) {
	t.Helper()
	if err := fixture.exposure.UpdateMetadata(types.LeaseMetadata{Description: strings.Repeat("a", 4097)}); err == nil {
		t.Fatal("UpdateMetadata() accepted oversized metadata")
	}
	if fixture.exposure.metadata.Description != "" || fixture.exposure.metadata.Tags[0] != "updated" || fixture.ln.metadataSnapshot().Tags[0] != "updated" {
		t.Fatal("rejected metadata update changed exposure or listener metadata")
	}
}

func TestExposeRejectsInvalidLocalTLSOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{"certificate only", []Option{WithTLSCertificate("cert.pem", "")}},
		{"key only", []Option{WithTLSCertificate("", "key.pem")}},
		{"raw TCP", []Option{WithTLSCertificate("cert.pem", "key.pem"), WithTCP()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Expose(t.Context(), types.Identity{}, []string{"https://relay.example"}, tc.opts...)
			if err == nil || !strings.Contains(err.Error(), "TLS") {
				t.Fatalf("expected local TLS option error, got %v", err)
			}
		})
	}
}

func TestExposeRejectsInvalidAutomaticTLSOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{"missing state", []Option{WithAutomaticTLS("", false)}},
		{"blank state", []Option{WithAutomaticTLS(" ", true)}},
		{"manual files", []Option{WithAutomaticTLS("state", false), WithTLSCertificate("cert.pem", "key.pem")}},
		{"raw TCP", []Option{WithAutomaticTLS("state", true), WithTCP()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Expose(t.Context(), types.Identity{}, []string{"https://relay.example"}, tc.opts...)
			if err == nil || !strings.Contains(err.Error(), "TLS") {
				t.Fatalf("expected automatic TLS option error, got %v", err)
			}
		})
	}
}

func TestExposeRejectsInvalidCertificateFiles(t *testing.T) {
	clientIdentity, err := identity.Generate("local-tls")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.pem")
	if err := os.WriteFile(corrupt, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{filepath.Join(dir, "missing.pem"), corrupt} {
		t.Run(filepath.Base(file), func(t *testing.T) {
			exposure, err := Expose(t.Context(), clientIdentity, []string{"https://127.0.0.1:1"}, WithTLSCertificate(file, file))
			if exposure != nil {
				_ = exposure.Close()
				t.Fatal("Expose started with invalid manual certificate files")
			}
			if !errors.Is(err, localtls.ErrLocalCertificate) {
				t.Fatalf("Expose() = %v, want local certificate error before relay registration", err)
			}
		})
	}
}

func TestTerminalRelayErrorsPreserveTransportRetries(t *testing.T) {
	for _, tc := range []struct {
		err      error
		terminal bool
	}{
		{fmt.Errorf("manual TLS: %w", localtls.ErrLocalCertificate), true},
		{context.Canceled, false},
		{context.DeadlineExceeded, false},
		{io.EOF, false},
		{&net.OpError{Op: "dial", Net: "tcp", Err: io.EOF}, false},
	} {
		if got := isTerminalRelayError(tc.err); got != tc.terminal {
			t.Fatalf("isTerminalRelayError(%v) = %v, want %v", tc.err, got, tc.terminal)
		}
	}
}

func TestWaitReadyOnlyReturnsFailuresWhenAllRelaysAreTerminal(t *testing.T) {
	const badRelay, otherRelay = "https://bad.example", "https://other.example"
	exposure := &Exposure{done: make(chan struct{}), updates: make(chan RelayStatus, 1)}
	readyCtx, readyCancel := context.WithTimeout(t.Context(), time.Second)
	defer readyCancel()
	exposure.setRelayStatus(badRelay, listenerStatus{state: RelayFailed, failure: RelayFailureTerminal, err: localtls.ErrLocalCertificate})
	if _, err := exposure.WaitReady(readyCtx); !errors.Is(err, localtls.ErrLocalCertificate) {
		t.Fatalf("terminal relay returned %v", err)
	}
	exposure.syncRelayStatuses([]string{badRelay, otherRelay})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := exposure.WaitReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("connecting relay was discarded: %v", err)
	}
	exposure.setRelayStatus(otherRelay, listenerStatus{state: RelayReady, publicURL: "https://tenant.other.example"})
	ready, err := exposure.WaitReady(readyCtx)
	if err != nil || len(ready) != 1 || ready[0].RelayURL != otherRelay {
		t.Fatalf("healthy relay was discarded: %v, %v", ready, err)
	}
}

func TestExposeRejectsInvalidCertificateMonitoringOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{"missing state", []Option{WithCertificateMonitoring("", "", "")}},
		{"blank state", []Option{WithCertificateMonitoring(" ", "", "")}},
		{"invalid resolver", []Option{WithCertificateMonitoring("evidence", "", "dns.example:53")}},
		{"relay cache", []Option{WithCertificateMonitoring("evidence", "", ""), WithStaticRelayCache(".", time.Hour)}},
		{"raw TCP", []Option{WithCertificateMonitoring("evidence", "", ""), WithTCP()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Expose(t.Context(), types.Identity{}, []string{"https://relay.example"}, tc.opts...)
			if err == nil || errors.Is(err, errPortalSDKIdentityMustIncludeAddress) {
				t.Fatalf("expected certificate monitoring option error, got %v", err)
			}
		})
	}
}

func TestCanonicalWithdrawalUpdatesSnapshotsAndWaiters(t *testing.T) {
	const relay = "https://relay.example"
	const legacy = "https://legacy.relay.example"
	owner := &listener{lease: utils.NewSnapshot(listenerSnapshot{
		accessToken: "token", tenantTLS: &namespaceTLS{local: &localtls.Client{}},
	})}
	e := &Exposure{
		relayListeners: map[string]*listener{relay: owner},
		statuses:       map[string]RelayStatus{relay: {RelayURL: relay, State: RelayReady, PublicURL: "https://service.address.relay.example", LegacyURL: legacy}},
		done:           make(chan struct{}),
		updates:        make(chan RelayStatus, 1),
		stateChanged:   make(chan struct{}),
	}
	changed := e.stateChanged
	e.setListenerRelayStatus(relay, owner, listenerStatus{state: RelayReady, legacyURL: legacy})
	status := e.Relays()[0]
	if status.PublicURL != "" || status.State != RelayReady || status.LegacyURL != legacy {
		t.Fatalf("unavailable canonical status: %+v", status)
	}
	ready, _, err := e.readyRelays(func(status RelayStatus) bool { return status.State == RelayReady && status.PublicURL != "" }, true)
	if err != nil || len(ready) != 0 {
		t.Fatalf("unavailable canonical marked ready: %+v, %v", ready, err)
	}
	select {
	case <-changed:
	default:
		t.Fatal("canonical withdrawal did not wake readiness waiters")
	}
	select {
	case update := <-e.Updates():
		if !relayStatusEqual(update, status) {
			t.Fatalf("update = %+v, snapshot = %+v", update, status)
		}
	default:
		t.Fatal("canonical withdrawal did not publish an update")
	}
	// A report constructed while material was usable may arrive after the
	// withdrawal. It must not restore a URL against unavailable local material.
	e.setListenerRelayStatus(relay, owner, listenerStatus{
		state: RelayReady, legacyURL: legacy, publicURL: "https://service.address.relay.example",
	})
	if status := e.Relays()[0]; status.PublicURL != "" || status.LegacyURL != legacy {
		t.Fatalf("late ready report restored the canonical: %+v", status)
	}
	ready, _, err = e.readyRelays(func(status RelayStatus) bool { return status.State == RelayReady && status.PublicURL != "" }, true)
	if err != nil || len(ready) != 0 {
		t.Fatalf("late ready report made canonical ready: %+v, %v", ready, err)
	}
	select {
	case update := <-e.Updates():
		if update.PublicURL != "" {
			t.Fatalf("late ready report advertised the canonical: %+v", update)
		}
	default:
	}
}
