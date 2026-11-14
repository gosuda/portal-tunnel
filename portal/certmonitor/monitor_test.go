package certmonitor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func testMonitor(t *testing.T) *certificateMonitor {
	t.Helper()
	m, err := newCertificateMonitor("tenant.example", MonitorConfig{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		t.Fatal(err)
	}
	return m
}

func monitorDNS(t *testing.T, handler func(*dns.Msg)) string {
	t.Helper()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: connection, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)
		reply.RecursionAvailable = true
		handler(reply)
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return connection.LocalAddr().String()
}

func TestMonitorCAAEffectivePolicy(t *testing.T) {
	cases := []struct {
		name    string
		answers map[string][]string
		owner   string
		want    []caaRecord
	}{
		{"direct", map[string][]string{"tenant.example.": {`tenant.example. 60 IN CAA 128 ISSUE "ca.example"`}}, "tenant.example.", []caaRecord{{128, "issue", "ca.example"}}},
		{"parent", map[string][]string{"example.": {`example. 10 IN CAA 0 issue "ca.example"`}}, "example.", []caaRecord{{0, "issue", "ca.example"}}},
		{"alias", map[string][]string{"tenant.example.": {"tenant.example. 30 IN CNAME alias.other."}, "alias.other.": {`alias.other. 1 IN CAA 0 issue "ca.example"`}}, "alias.other.", []caaRecord{{0, "issue", "ca.example"}}},
		{"empty alias uses original parent", map[string][]string{"tenant.example.": {"tenant.example. 30 IN CNAME alias.other."}, "other.": {`other. 5 IN CAA 0 issue "wrong.example"`}, "example.": {`example. 5 IN CAA 0 issue "correct.example"`}}, "example.", []caaRecord{{0, "issue", "correct.example"}}},
		{"dname", map[string][]string{"tenant.example.": {"example. 30 IN DNAME other."}, "tenant.other.": {`tenant.other. 1 IN CAA 0 issue "ca.example"`}}, "tenant.other.", []caaRecord{{0, "issue", "ca.example"}}},
		{"removed", nil, "", []caaRecord{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := testMonitor(t)
			m.config.DNSResolver = monitorDNS(t, func(reply *dns.Msg) {
				for _, text := range tc.answers[reply.Question[0].Name] {
					rr, err := dns.NewRR(text)
					if err != nil {
						t.Error(err)
						return
					}
					reply.Answer = append(reply.Answer, rr)
				}
			})
			got := m.observeCAA(t.Context())
			if got.Error != "" || got.Owner != tc.owner || !slices.Equal(got.Records, tc.want) || got.Records == nil {
				t.Fatalf("observation=%+v, want owner %s records %+v", got, tc.owner, tc.want)
			}
		})
	}
}

func TestMonitorCAAErrorsAreUnknownNotRemoval(t *testing.T) {
	for _, kind := range []string{"servfail", "refused", "referral", "alias loop", "conflicting aliases", "contradictory", "question", "invalid octets", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			m := testMonitor(t)
			m.config.DNSResolver = monitorDNS(t, func(reply *dns.Msg) {
				switch kind {
				case "servfail":
					reply.Rcode = dns.RcodeServerFailure
				case "refused":
					reply.Rcode = dns.RcodeRefused
				case "referral":
					reply.RecursionAvailable = false
				case "alias loop":
					reply.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: reply.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "tenant.example."}}
				case "conflicting aliases":
					reply.Answer = []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: reply.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "other.example."},
						&dns.DNAME{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET}, Target: "elsewhere."},
					}
				case "contradictory":
					reply.Rcode = dns.RcodeNameError
					reply.Answer = []dns.RR{&dns.CAA{Hdr: dns.RR_Header{Name: reply.Question[0].Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET}, Tag: "issue", Value: "ca.example"}}
				case "question":
					reply.Question[0].Name = "other.example."
				case "invalid octets":
					reply.Answer = []dns.RR{&dns.CAA{Hdr: dns.RR_Header{Name: reply.Question[0].Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET}, Tag: "issue", Value: string([]byte{0xff})}}
				}
			})
			ctx := t.Context()
			if kind == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got := m.observeCAA(ctx)
			if got.Error == "" || got.Records != nil {
				t.Fatalf("unavailable observation looked authoritative: %+v", got)
			}
		})
	}
}

func TestMonitorCTPageBudgetResumesWithoutStarvingHistory(t *testing.T) {
	m := testMonitor(t)
	cert := monitorCertificate(t, nil, m.hostname, false)
	monitorHTTP(t, m, func(w http.ResponseWriter, r *http.Request) {
		number := 0
		if cursor := r.URL.Query().Get("after"); cursor != "" {
			number, _ = strconv.Atoi(strings.TrimPrefix(cursor, "page-"))
		}
		if number == certificateMonitorPages+2 {
			fmt.Fprint(w, "[]")
			return
		}
		json.NewEncoder(w).Encode([]ctIssuance{{ID: fmt.Sprintf("page-%d", number+1), TBSSHA256: strings.Repeat("a", 64), CertDER: cert.Raw}})
	})
	evidence, _ := m.loadEvidence()
	if err := m.pollCT(t.Context(), &evidence); err == nil || evidence.Cursor != fmt.Sprintf("page-%d", certificateMonitorPages) || evidence.CTError == "" {
		t.Fatalf("budget did not preserve incomplete cursor: %+v %v", evidence, err)
	}
	restarted, _ := m.loadEvidence()
	if err := m.pollCT(t.Context(), &restarted); err != nil || restarted.Cursor != "" || restarted.CTLastComplete.IsZero() || len(restarted.Certificates) != 1 {
		t.Fatalf("large traversal did not complete after restart: %+v %v", restarted, err)
	}
}

func TestMonitorCTMalformedLaterEntryDoesNotCommitPartialPage(t *testing.T) {
	m := testMonitor(t)
	cert := monitorCertificate(t, nil, m.hostname, false)
	monitorHTTP(t, m, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]ctIssuance{
			{ID: "good", TBSSHA256: strings.Repeat("a", 64), CertDER: cert.Raw},
			{ID: "bad", TBSSHA256: strings.Repeat("b", 64), CertDER: []byte("malformed DER")},
		})
	})
	evidence, _ := m.loadEvidence()
	if err := m.pollCT(t.Context(), &evidence); err == nil {
		t.Fatal("malformed later entry succeeded")
	}
	restored, err := m.loadEvidence()
	if err != nil || restored.Cursor != "" || len(restored.Certificates) != 0 || restored.CTError == "" {
		t.Fatalf("partial page committed: %+v %v", restored, err)
	}
}

func TestMonitorCTGroupingDoesNotApproveDifferentKey(t *testing.T) {
	m := testMonitor(t)
	local := monitorCertificate(t, nil, m.hostname, true)
	other := monitorCertificate(t, nil, m.hostname, false)
	m.rememberLocalCertificate(local)
	monitorHTTP(t, m, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") != "" {
			fmt.Fprint(w, "[]")
			return
		}
		json.NewEncoder(w).Encode([]ctIssuance{
			{ID: "first", TBSSHA256: strings.Repeat("a", 64), CertDER: local.Raw},
			{ID: "second", TBSSHA256: strings.Repeat("a", 64), CertDER: other.Raw},
		})
	})
	evidence, _ := m.loadEvidence()
	if err := m.pollCT(t.Context(), &evidence); err != nil || len(evidence.Certificates) != 2 {
		t.Fatal("provider grouping suppressed contradictory DER")
	}
	keys, _ := m.knownKeys(nil)
	if keys[evidence.Certificates[publicSHA256(other.Raw)].SPKISHA256] || !keys[evidence.Certificates[publicSHA256(local.Raw)].SPKISHA256] {
		t.Fatal("provider grouping approved an unrelated public key")
	}
}

func TestMonitorCTLegacyCommonNameDoesNotBlockLaterCertificates(t *testing.T) {
	m := testMonitor(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	legacy := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: m.hostname}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	legacyDER, err := x509.CreateCertificate(rand.Reader, legacy, legacy, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	covering := monitorCertificate(t, nil, m.hostname, false)
	monitorHTTP(t, m, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") != "" {
			fmt.Fprint(w, "[]")
			return
		}
		json.NewEncoder(w).Encode([]ctIssuance{
			{ID: "legacy", TBSSHA256: strings.Repeat("a", 64), CertDER: legacyDER},
			{ID: "modern", TBSSHA256: strings.Repeat("b", 64), CertDER: covering.Raw},
		})
	})
	evidence, _ := m.loadEvidence()
	if err := m.pollCT(t.Context(), &evidence); err != nil || evidence.Cursor != "" || len(evidence.Certificates) != 2 {
		t.Fatalf("legacy CN wedged scan: %+v %v", evidence, err)
	}
	if evidence.Certificates[publicSHA256(legacyDER)].CoversHostname || !evidence.Certificates[publicSHA256(covering.Raw)].CoversHostname {
		t.Fatal("legacy CN was treated as modern SAN coverage")
	}
}

func TestMonitorEvidenceLimitPreservesCursorAndHistory(t *testing.T) {
	m := testMonitor(t)
	cert := monitorCertificate(t, nil, m.hostname, false)
	monitorHTTP(t, m, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]ctIssuance{{ID: "new", TBSSHA256: strings.Repeat("a", 64), CertDER: cert.Raw}})
	})
	evidence, _ := m.loadEvidence()
	for i := range 10000 {
		evidence.Certificates[fmt.Sprint(i)] = ctObservation{}
	}
	evidence.Cursor = "old"
	if err := m.saveEvidence(evidence); err != nil {
		t.Fatal(err)
	}
	if err := m.pollCT(t.Context(), &evidence); err == nil {
		t.Fatal("full evidence store silently advanced")
	}
	restored, err := m.loadEvidence()
	if err != nil || restored.Cursor != "old" || len(restored.Certificates) != 10000 || restored.CTError == "" {
		t.Fatalf("storage full discarded evidence: count=%d cursor=%s error=%v", len(restored.Certificates), restored.Cursor, err)
	}
}

func TestMonitorCloseCancelsIndependentWorker(t *testing.T) {
	m := testMonitor(t)
	m.config.DNSResolver = monitorDNS(t, func(*dns.Msg) {})
	started := make(chan struct{})
	monitorHTTP(t, m, func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	})
	observer := m.start()
	defer observer.Close()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("monitor did not reach local HTTP fixture")
	}
	done := make(chan error, 1)
	go func() { observer.Close(); done <- nil }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel monitor request")
	}
}

func TestMonitorBaselineExplicitAcceptance(t *testing.T) {
	m := testMonitor(t)
	if baseline, err := m.readBaseline(); err == nil || baseline != nil {
		t.Fatal("missing baseline was accepted")
	}
	m.config.BaselineFile = filepath.Join(t.TempDir(), "accepted.json")
	for _, data := range []string{
		`{"hostname":"other.example","caa":[]}`,
		`{"hostname":"tenant.example"}`,
		`{"hostname":"tenant.example","caa":null}`,
		`{"hostname":"tenant.example","caa":[],"approved_spki_sha256":["not-a-hash"]}`,
		`{"hostname":"tenant.example","caa":[]} {}`,
	} {
		os.WriteFile(m.config.BaselineFile, []byte(data), 0600)
		if _, err := m.readBaseline(); err == nil {
			t.Fatalf("accepted invalid baseline %s", data)
		}
	}
	accepted := monitorBaseline{Hostname: m.hostname, CAA: []caaRecord{{0, "ISSUE", "CA.example"}, {0, "issue", "CA.example"}, {128, "iodef", "mailto:test@example"}}}
	data, _ := json.Marshal(accepted)
	os.WriteFile(m.config.BaselineFile, data, 0600)
	baseline, err := m.readBaseline()
	if err != nil || len(baseline.CAA) != 2 || baseline.CAA[0].Tag != "issue" || baseline.CAA[0].Value != "CA.example" {
		t.Fatalf("canonical baseline=%+v error=%v", baseline, err)
	}
	// Deliberate edits are read again; absence/removal isn't accepted by observation.
	os.WriteFile(m.config.BaselineFile, []byte(`{"hostname":"tenant.example","caa":[]}`), 0600)
	baseline, err = m.readBaseline()
	if err != nil || baseline.CAA == nil || len(baseline.CAA) != 0 {
		t.Fatal("explicit no-policy baseline not reread")
	}
}

func monitorCertificate(t *testing.T, key *ecdsa.PrivateKey, hostname string, precertificate bool) *x509.Certificate {
	t.Helper()
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: []string{hostname}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if precertificate {
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}, Critical: true, Value: []byte{5, 0}}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The production endpoint remains fixed; only the test client's transport
// connects its HTTPS requests to a local, trusted fixture server.
func monitorHTTP(t *testing.T, m *certificateMonitor, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client := server.Client()
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	client.CheckRedirect = m.http.CheckRedirect
	m.http = client
}

func TestMonitorCTPrecertificateFinalAndWildcard(t *testing.T) {
	m := testMonitor(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pre := monitorCertificate(t, key, "*.example", true)
	final := monitorCertificate(t, key, "*.example", false)
	var finalAvailable atomic.Bool
	monitorHTTP(t, m, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domain") != m.hostname || r.URL.Query().Get("match_wildcards") != "true" || r.URL.Query().Get("expand") != "cert_der" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected CT request or credentials")
		}
		if r.URL.Query().Get("after") != "" {
			fmt.Fprint(w, "[]")
			return
		}
		cert := pre
		if finalAvailable.Load() {
			cert = final
		}
		json.NewEncoder(w).Encode([]ctIssuance{{ID: "opaque/id", TBSSHA256: strings.Repeat("a", 64), CertDER: cert.Raw}})
	})
	evidence, _ := m.loadEvidence()
	if err := m.pollCT(t.Context(), &evidence); err != nil {
		t.Fatal(err)
	}
	firstSeen := evidence.Certificates[publicSHA256(pre.Raw)].FirstSeen
	if err := m.pollCT(t.Context(), &evidence); err != nil || len(evidence.Certificates) != 1 || !evidence.Certificates[publicSHA256(pre.Raw)].FirstSeen.Equal(firstSeen) {
		t.Fatal("repeated precertificate was not deduplicated")
	}
	finalAvailable.Store(true)
	if err := m.pollCT(t.Context(), &evidence); err != nil {
		t.Fatal(err)
	}
	if len(evidence.Certificates) != 2 || !evidence.Certificates[publicSHA256(pre.Raw)].Precertificate || evidence.Certificates[publicSHA256(final.Raw)].Precertificate || evidence.Cursor != "" || evidence.CTLastComplete.IsZero() {
		t.Fatalf("lost pre/final evidence: %+v", evidence)
	}
	other := monitorCertificate(t, nil, "*.other.example", false)
	if observation, err := m.decodeCT(ctIssuance{ID: "other", TBSSHA256: strings.Repeat("b", 64), CertDER: other.Raw}, time.Now()); err != nil || observation.CoversHostname {
		t.Fatal("incorrect hostname coverage for unrelated valid wildcard DER")
	}
}

func TestMonitorCTPaginationRestartAndErrors(t *testing.T) {
	m := testMonitor(t)
	certificate := monitorCertificate(t, nil, m.hostname, false)
	var outage atomic.Bool
	var calls atomic.Int32
	monitorHTTP(t, m, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("after") == "" {
			json.NewEncoder(w).Encode([]ctIssuance{{ID: "opaque-first", TBSSHA256: strings.Repeat("c", 64), CertDER: certificate.Raw}})
			return
		}
		if outage.Load() {
			w.Header().Set("Retry-After", "7200")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, "[]")
	})
	outage.Store(true)
	evidence, _ := m.loadEvidence()
	if err := m.pollCT(t.Context(), &evidence); err == nil {
		t.Fatal("outage reported healthy")
	}
	restarted, err := m.loadEvidence()
	checkpointPreserved := restarted.Cursor == "opaque-first" && len(restarted.Certificates) == 1
	outageRecorded := restarted.CTError != "" && restarted.CTLastComplete.IsZero()
	if err != nil || !checkpointPreserved || !outageRecorded || restarted.CTNextCheck.Before(time.Now().Add(time.Hour)) {
		t.Fatalf("lost durable evidence/cursor: %+v, %v", restarted, err)
	}
	before := calls.Load()
	if err := m.pollCT(t.Context(), &restarted); err != nil || before != calls.Load() {
		t.Fatal("ignored server retry window")
	}
	outage.Store(false)
	restarted.CTNextCheck = time.Time{}
	if err := m.pollCT(t.Context(), &restarted); err != nil || restarted.Cursor != "" || restarted.CTError != "" {
		t.Fatalf("resume failed: %v %+v", err, restarted)
	}
}

func TestCTRetryAfterBounds(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		header string
		want   time.Time
	}{
		{"short seconds", "7200", now.Add(2 * time.Hour)},
		{"long seconds", "86401", now.Add(24 * time.Hour)},
		{"overflowing seconds", "18446744073709551616", now.Add(24 * time.Hour)},
		{"short HTTP date", now.Add(time.Hour).Format(http.TimeFormat), now.Add(time.Hour)},
		{"long HTTP date", now.Add(48 * time.Hour).Format(http.TimeFormat), now.Add(24 * time.Hour)},
		{"invalid", "unknown", time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ctRetryAfter(tc.header, now); !got.Equal(tc.want) {
				t.Fatalf("retry after %q = %s, want %s", tc.header, got, tc.want)
			}
		})
	}
}

func TestMonitorCTCorrectsExcessivePersistedRetry(t *testing.T) {
	m := testMonitor(t)
	checked := time.Now().UTC().Add(-48 * time.Hour)
	evidence, err := m.loadEvidence()
	if err != nil {
		t.Fatal(err)
	}
	certificate := monitorCertificate(t, nil, m.hostname, false)
	marker, err := m.decodeCT(ctIssuance{ID: "saved-page", TBSSHA256: strings.Repeat("c", 64), CertDER: certificate.Raw}, checked)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Cursor = marker.SourceID
	evidence.Certificates[marker.SHA256] = marker
	evidence.CTChecked = checked
	evidence.CTNextCheck = checked.Add(365 * 24 * time.Hour)
	if err := m.saveEvidence(evidence); err != nil {
		t.Fatal(err)
	}
	restarted, err := m.loadEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if want := checked.Add(24 * time.Hour); !restarted.CTNextCheck.Equal(want) {
		t.Fatalf("persisted retry after = %s, want %s", restarted.CTNextCheck, want)
	}
	if restarted.Cursor != marker.SourceID || !slices.Equal(restarted.Certificates[marker.SHA256].Certificate, marker.Certificate) {
		t.Fatal("lost durable evidence or cursor")
	}
}

func TestMonitorCTMalformedPagePreservesCheckpoint(t *testing.T) {
	for _, response := range []string{"null", "{}", "[] []", "[", `[{"id":"next","tbs_sha256":"invalid","cert_der":"AA=="}]`, strings.Repeat(" ", certificateMonitorBytes+1)} {
		t.Run(fmt.Sprintf("bytes-%d", len(response)), func(t *testing.T) {
			m := testMonitor(t)
			monitorHTTP(t, m, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, response) })
			evidence, _ := m.loadEvidence()
			evidence.Cursor = "last-saved"
			if err := m.saveEvidence(evidence); err != nil {
				t.Fatal(err)
			}
			if err := m.pollCT(t.Context(), &evidence); err == nil {
				t.Fatal("invalid page succeeded")
			}
			restored, err := m.loadEvidence()
			if err != nil || restored.Cursor != "last-saved" || len(restored.Certificates) != 0 || restored.CTError == "" {
				t.Fatalf("invalid page advanced checkpoint: %+v %v", restored, err)
			}
		})
	}
}

func TestMonitorCTFailedSaveDoesNotAdvance(t *testing.T) {
	m := testMonitor(t)
	certificate := monitorCertificate(t, nil, m.hostname, false)
	monitorHTTP(t, m, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]ctIssuance{{ID: "new", TBSSHA256: strings.Repeat("d", 64), CertDER: certificate.Raw}})
	})
	evidence, _ := m.loadEvidence()
	if err := os.Mkdir(filepath.Join(m.dir, "evidence.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.pollCT(t.Context(), &evidence); err == nil || evidence.Cursor != "" || len(evidence.Certificates) != 0 {
		t.Fatal("storage failure advanced in-memory checkpoint")
	}
}

func TestMonitorLocalHistoryAndExplicitKeyApproval(t *testing.T) {
	m := testMonitor(t)
	old := monitorCertificate(t, nil, m.hostname, false)
	current := monitorCertificate(t, nil, m.hostname, false)
	remote := monitorCertificate(t, nil, "*.example", false)
	m.events <- old.Raw
	m.events <- current.Raw
	m.rememberEvents()
	known, err := m.knownKeys(nil)
	if err != nil || !known[publicSHA256(old.RawSubjectPublicKeyInfo)] || !known[publicSHA256(current.RawSubjectPublicKeyInfo)] || known[publicSHA256(remote.RawSubjectPublicKeyInfo)] {
		t.Fatalf("wrong local provenance: %+v %v", known, err)
	}
	approved := publicSHA256(remote.RawSubjectPublicKeyInfo)
	known, err = m.knownKeys(&monitorBaseline{ApprovedSPKISHA256: []string{approved}})
	if err != nil || !known[approved] {
		t.Fatal("explicit extra key approval ignored")
	}
	files, _ := os.ReadDir(filepath.Join(m.dir, "local"))
	for _, file := range files {
		data, _ := os.ReadFile(filepath.Join(m.dir, "local", file.Name()))
		if bytes.Contains(data, []byte("PRIVATE KEY")) {
			t.Fatal("private material entered monitor evidence")
		}
		if _, err := x509.ParseCertificate(data); err != nil {
			t.Fatal("history is not public DER")
		}
	}
}

func TestMonitorConfigValidation(t *testing.T) {
	for _, config := range []MonitorConfig{{}, {StateDir: " "}, {StateDir: "x", DNSResolver: "resolver.example:53"}, {StateDir: "x", DNSResolver: "1.1.1.1:0"}} {
		if config.Validate() == nil {
			t.Fatalf("invalid config accepted: %+v", config)
		}
	}
	for _, resolver := range []string{"", "1.1.1.1:53", "[2606:4700:4700::1111]:53"} {
		if err := (MonitorConfig{StateDir: "x", DNSResolver: resolver}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMonitorOutagesPreserveUnknownEvidence(t *testing.T) {
	m := testMonitor(t)
	m.config.DNSResolver = monitorDNS(t, func(reply *dns.Msg) { reply.Rcode = dns.RcodeServerFailure })
	monitorHTTP(t, m, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	cert := monitorCertificate(t, nil, m.hostname, false)
	m.events <- cert.Raw
	m.poll(t.Context())
	evidence, err := m.loadEvidence()
	if err != nil || len(evidence.CAA) != 1 || evidence.CAA[0].Error == "" || evidence.CAA[0].Records != nil || evidence.CTError == "" {
		t.Fatalf("outage not preserved as unknown: %+v %v", evidence, err)
	}
	// An evidence lock held by another process cannot block the TLS owner.
	lock, err := utils.TryLockFile(filepath.Join(m.dir, "evidence.json.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	m.poll(t.Context())
	if _, err := os.Stat(filepath.Join(m.dir, "local", publicSHA256(cert.Raw)+".der")); errors.Is(err, os.ErrNotExist) {
		t.Fatal("worker did not retain local history")
	}
}

func TestMonitorRejectsInvalidInstalledCertificateEvents(t *testing.T) {
	m := testMonitor(t)
	wrong := monitorCertificate(t, nil, "other.example", false)
	m.events <- []byte("not DER")
	m.events <- wrong.Raw
	m.events <- make([]byte, (256<<10)+1)
	m.rememberEvents()
	known, err := m.knownKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(known) != 0 {
		t.Fatal("invalid installation event approved a public key")
	}
	cert := monitorCertificate(t, nil, m.hostname, false)
	m.events <- cert.Raw
	m.rememberEvents()
	known, err = m.knownKeys(nil)
	if err != nil || !known[publicSHA256(cert.RawSubjectPublicKeyInfo)] {
		t.Fatalf("valid installation event missing: %v", err)
	}
}
