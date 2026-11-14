package keyless

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestExpiredRelayCertificateRecovers(t *testing.T) {
	issuer := newTestIssuer(t)
	expired := issuer.issue(t, 2)
	expired.leaf.NotBefore = time.Now().Add(-2 * time.Hour)
	expired.leaf.NotAfter = time.Now().Add(-time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, expired.leaf, issuer.cert, expired.leaf.PublicKey, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	expired.leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	expired.tls.Certificate[0] = der
	relay := newRelayStandIn(t, expired)
	client := relay.newClient(t)
	renewed := issuer.issue(t, 3)
	relay.renew(renewed, true)
	if _, err := relay.visit(t, client, issuer.pool); !errors.Is(err, errTenantCertificateNotValid) {
		t.Fatalf("expired handshake = %v, want the expired generation refused", err)
	}
	if leaf, err := relay.visit(t, client, issuer.pool); err != nil || !leaf.Equal(renewed.leaf) {
		t.Fatalf("next handshake: leaf %v, error %v; want the renewed certificate", leaf, err)
	}
}
