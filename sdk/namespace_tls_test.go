package sdk

import (
	"bytes"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/localtls"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestCanonicalBindingCoversSiblingNonceAndExporter(t *testing.T) {
	id, err := identity.Generate("blog")
	if err != nil {
		t.Fatal(err)
	}
	host, err := utils.LocalTLSLeaseHostname("blog", id.Address, "relay.example")
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := utils.LocalTLSLeaseHostname("api", id.Address, "relay.example")
	if err != nil {
		t.Fatal(err)
	}
	nonce, exporter := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	sig, err := signChannelBindingPayload(host, nonce, exporter, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyChannelBindingSigner(host, nonce, exporter, id.Address, sig); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, host      string
		nonce, exporter []byte
	}{
		{"sibling service", sibling, nonce, exporter},
		{"different nonce", host, bytes.Repeat([]byte{3}, 32), exporter},
		{"different TLS session", host, nonce, bytes.Repeat([]byte{4}, 32)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyChannelBindingSigner(test.host, test.nonce, test.exporter, id.Address, sig); err == nil {
				t.Fatal("substituted binding accepted")
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
