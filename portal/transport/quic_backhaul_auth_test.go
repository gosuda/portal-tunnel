package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestQUICControlFirstStreamDeadline(t *testing.T) {
	t.Parallel()
	conn, _ := newAuthTestConnections(t)
	started := time.Now()
	_, err := AcceptQUICBackhaulControl(context.Background(), conn)
	if err == nil {
		t.Fatal("accepted a connection without a control stream")
	}
	if elapsed := time.Since(started); elapsed > quicBackhaulControlTimeout+2*time.Second {
		t.Fatalf("first-stream wait exceeded authentication budget: %s", elapsed)
	}
}

func TestQUICControlPartialCredentialsDeadline(t *testing.T) {
	t.Parallel()
	server, client := newAuthTestConnections(t)
	stream, err := client.OpenStreamSync(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte(`{"access_token":"`)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := AcceptQUICBackhaulControl(ctx, server); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted incomplete credentials")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not interrupt authentication")
	}
}

func newAuthTestConnections(t *testing.T, configs ...*quic.Config) (*quic.Conn, *quic.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ListenQUICBackhaul("127.0.0.1:0", tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	clientConfig := quicBackhaulConfig()
	if len(configs) > 0 {
		clientConfig = configs[0]
	}
	client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{quicBackhaulALPN}}, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "test finished") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseWithError(0, "test finished") })
	return server, client
}
