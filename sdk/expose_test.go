package sdk

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"

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

// AliasSince dates the current hold of an alias: a burst of connecting keeps it,
// and an alias that came back is a new hold, because another identity may have
// held the name in between.
func TestAliasSinceDatesTheCurrentHold(t *testing.T) {
	const relayURL, public, alias = "https://relay.example", "https://long.relay.example", "https://short.relay.example"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exposure := &Exposure{
		cancel:         cancel,
		done:           ctx.Done(),
		accepted:       make(chan net.Conn, 1),
		relayListeners: make(map[string]*listener),
	}
	status := func() RelayStatus { return exposure.statuses[relayURL] }

	exposure.applyRelayStatus(relayURL, listenerStatus{state: RelayReady, publicURL: public, aliasURL: alias}, nil)
	first := status().AliasSince
	if first.IsZero() {
		t.Fatal("a held alias has no date")
	}
	exposure.applyRelayStatus(relayURL, listenerStatus{state: RelayConnecting, publicURL: public, aliasURL: alias}, nil)
	if got := status().AliasSince; !got.Equal(first) {
		t.Fatalf("a burst moved the date from %v to %v", first, got)
	}
	exposure.applyRelayStatus(relayURL, listenerStatus{state: RelayConnecting}, nil)
	if got := status(); got.AliasURL != "" || !got.AliasSince.IsZero() {
		t.Fatalf("a lost alias kept %q since %v", got.AliasURL, got.AliasSince)
	}
	exposure.applyRelayStatus(relayURL, listenerStatus{state: RelayReady, publicURL: public, aliasURL: alias}, nil)
	if got := status().AliasSince; got.IsZero() || got.Equal(first) {
		t.Fatalf("an alias that came back has date %v, the old hold's was %v", got, first)
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

func TestListenerReportsARefusalUntilAStreamOpens(t *testing.T) {
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
		}, listenerSnapshot.snapshot),
	}
	pending := &types.APIRequestError{Code: types.APIErrorCodeLeaseRejected}
	denied := &types.APIRequestError{Code: types.APIErrorCodeLeaseDenied}
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

	l.reportRefusal(pending)
	if got := update(); got.state != RelayConnecting || got.approval != RelayApprovalPending || got.publicURL != "" || got.tcpAddr != "" {
		t.Fatalf("waiting status = %+v", got)
	}
	l.reportRefusal(pending) // the second session slot says the same
	quiet()
	l.reportRefusal(denied)
	if got := update(); got.approval != RelayApprovalRefused {
		t.Fatalf("denied status = %+v", got)
	}

	l.reportStreamReady()
	if got := update(); got.state != RelayReady || got.approval != "" || got.publicURL == "" {
		t.Fatalf("ready status = %+v", got)
	}
	// The other slot's answer can arrive after a stream opened.
	l.reportRefusal(pending)
	quiet()

	l.reportStreamClosed()
	if got := update(); got.state != RelayConnecting || got.approval != "" {
		t.Fatalf("reconnecting status = %+v", got)
	}
	l.reportRefusal(pending)
	if got := update(); got.approval != RelayApprovalPending {
		t.Fatalf("revoked status = %+v", got)
	}

	l.clearLease("")
	l.reportRefusal(pending) // a lease that is gone has nothing to report
	quiet()
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

// A relay that stays in the set keeps its whole status: a listener reports only
// changes, so nothing else would restore what a set change dropped.
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
	ln := &listener{
		metadata: types.LeaseMetadata{Tags: []string{"initial"}},
	}
	exposure := &Exposure{
		metadata:       types.LeaseMetadata{Tags: []string{"initial"}},
		relayListeners: map[string]*listener{"https://relay.example": ln},
	}
	metadata := exposure.metadata.Copy()
	metadata.Tags[0] = "mutated"
	if got := exposure.metadata.Tags[0]; got != "initial" {
		t.Fatalf("Metadata.Tags[0] = %q, want initial", got)
	}
	if err := exposure.UpdateMetadata(types.LeaseMetadata{Tags: []string{"updated"}}); err != nil {
		t.Fatalf("UpdateMetadata() error = %v", err)
	}
	if got := ln.metadataSnapshot().Tags[0]; got != "updated" {
		t.Fatalf("listener Metadata.Tags[0] = %q, want updated", got)
	}
	if err := exposure.UpdateMetadata(types.LeaseMetadata{Description: strings.Repeat("a", 4097)}); err == nil {
		t.Fatal("UpdateMetadata() accepted oversized metadata")
	}
	if exposure.metadata.Description != "" || exposure.metadata.Tags[0] != "updated" || ln.metadataSnapshot().Tags[0] != "updated" {
		t.Fatal("rejected metadata update changed exposure or listener metadata")
	}
}
