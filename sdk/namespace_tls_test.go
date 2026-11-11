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

func TestRelaySnapshotsHideUnavailableCanonical(t *testing.T) {
	const relay = "https://relay.example"
	const legacy = "https://legacy.relay.example"
	e := &Exposure{
		statuses:       map[string]RelayStatus{relay: {RelayURL: relay, State: RelayReady, PublicURL: "https://service.address.relay.example", LegacyURL: legacy}},
		relayListeners: map[string]*listener{relay: {lease: utils.NewSnapshot(listenerSnapshot{accessToken: "token", tenantTLS: &namespaceTLS{local: &localtls.Client{}}})}},
	}
	status := e.Relays()[0]
	if status.PublicURL != "" || status.State != RelayConnecting || status.LegacyURL != legacy {
		t.Fatalf("unavailable canonical status: %+v", status)
	}
	ready, _, err := e.readyRelays(func(status RelayStatus) bool { return status.State == RelayReady })
	if err != nil || len(ready) != 0 {
		t.Fatalf("unavailable canonical marked ready: %+v, %v", ready, err)
	}
}
