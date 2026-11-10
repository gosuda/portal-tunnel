package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

func TestAutomaticTenantCertificate(t *testing.T) {
	for _, requireLocal := range []bool{false, true} {
		name := "bootstrap"
		if requireLocal {
			name = "require-local"
		}
		t.Run(name, func(t *testing.T) {
			logs := captureSDKLogs(t)
			certDir := t.TempDir()
			h := newHarness(t, sdk.WithAutomaticTLS(certDir, requireLocal), sdk.WithMITMProtection(true))
			publicURL := h.waitForPublicURL()
			relayPEM, err := os.ReadFile(h.certificate)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(relayPEM) {
				t.Fatal("invalid relay CA")
			}
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, h.sniAddr)
				},
				DisableKeepAlives: true,
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			get := func() (*x509.Certificate, error) {
				response, err := client.Get(publicURL + "/marker")
				if err != nil {
					return nil, err
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					return nil, err
				}
				if string(body) != marker {
					t.Fatalf("unexpected tenant response %q", body)
				}
				return response.TLS.PeerCertificates[0], nil
			}
			deadline := time.Now().Add(20 * time.Second)
			tick := time.NewTicker(50 * time.Millisecond)
			defer tick.Stop()
			var issued *x509.Certificate
			for {
				leaf, err := get()
				if err == nil && !leaf.IsCA {
					issued = leaf
					break
				}
				if requireLocal && err == nil {
					t.Fatal("require-local served relay bootstrap certificate")
				}
				if time.Now().After(deadline) {
					t.Fatalf("automatic local activation failed: %v; %s", err, logs.snapshot())
				}
				<-tick.C
			}
			if got := h.get(publicURL); got != marker {
				t.Fatal(got)
			}
			for !logs.contains("tls passthrough self-probe passed") {
				if time.Now().After(deadline) {
					t.Fatalf("automatic exporter probe failed: %s", logs.snapshot())
				}
				<-tick.C
			}

			// Replacing relay leases must reuse the already persisted tenant key
			// and certificate, rather than ordering again per connection/lease.
			restart := func() {
				stopCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				if err := h.server.Shutdown(stopCtx); err != nil {
					t.Fatal(err)
				}
				if err := h.server.Wait(); err != nil {
					t.Fatal(err)
				}
				restarted, err := portal.NewServer(portal.ServerConfig{
					PortalURL: "https://" + h.sniAddr, StateDir: h.stateDir,
					TenantCertificates: true,
					SNIListenAddr:      h.sniAddr, SNIPort: h.sniPort,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := restarted.Start(t.Context(), relayHandler(restarted, nil)); err != nil {
					t.Fatal(err)
				}
				h.server = restarted
			}
			restart()
			deadline = time.Now().Add(45 * time.Second)
			for {
				leaf, err := get()
				if err == nil {
					if !bytes.Equal(issued.Raw, leaf.Raw) {
						t.Fatal("lease replacement changed valid persisted certificate")
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("automatic TLS did not recover: %v", err)
				}
				<-tick.C
			}

			// Put a valid, near-expiry certificate in the durable bundle using
			// the real local-development CA, then restart the lease. The owner
			// must renew it through the real CSR endpoint and retain its key.
			files, err := filepath.Glob(filepath.Join(certDir, "*.json"))
			if err != nil || len(files) != 1 {
				t.Fatalf("certificate state files: %v, %v", files, err)
			}
			data, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			var bundle map[string]string
			if err := json.Unmarshal(data, &bundle); err != nil {
				t.Fatal(err)
			}
			caPair, err := tls.LoadX509KeyPair(h.certificate, filepath.Join(h.stateDir, "privatekey.pem"))
			if err != nil {
				t.Fatal(err)
			}
			ca, err := x509.ParseCertificate(caPair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			nearExpiry, err := x509.ParseCertificate(issued.Raw)
			if err != nil {
				t.Fatal(err)
			}
			nearExpiry.NotBefore = time.Now().Add(-2 * time.Hour)
			nearExpiry.NotAfter = time.Now().Add(20 * time.Minute)
			der, err := x509.CreateCertificate(rand.Reader, nearExpiry, ca, issued.PublicKey, caPair.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			bundle["certificate_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(relayPEM)
			data, err = json.Marshal(bundle)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(files[0], data, 0600); err != nil {
				t.Fatal(err)
			}
			restart()
			deadline = time.Now().Add(45 * time.Second)
			for {
				leaf, err := get()
				if err == nil && !bytes.Equal(leaf.Raw, issued.Raw) && !bytes.Equal(leaf.Raw, der) {
					if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, issued.RawSubjectPublicKeyInfo) {
						t.Fatal("renewal replaced the persisted tenant key")
					}
					if time.Until(leaf.NotAfter) < time.Hour {
						t.Fatal("renewal did not extend certificate lifetime")
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("renewal failed: %v; %s", err, logs.snapshot())
				}
				<-tick.C
			}
		})
	}
}
