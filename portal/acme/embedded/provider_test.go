package embedded

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
)

const testZone = "portal.example.com"

func newTestProvider(t *testing.T, mutate func(*Config)) *Provider {
	t.Helper()
	cfg := Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0"}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("new embedded provider: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Stop(); err != nil {
			t.Fatalf("stop embedded provider: %v", err)
		}
	})
	return p
}

func exchange(t *testing.T, p *Provider, network string, qtype uint16, name string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	if network == "udp" {
		m.SetEdns0(1232, false)
	}
	client := &dns.Client{Net: network}
	resp, _, err := client.Exchange(m, p.Addr())
	if err != nil {
		t.Fatalf("exchange %s %s %s: %v", network, dns.TypeToString[qtype], name, err)
	}
	return resp
}

func requireRcode(t *testing.T, resp *dns.Msg, rcode int) {
	t.Helper()
	if resp.Rcode != rcode {
		t.Fatalf("unexpected rcode %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[rcode])
	}
}

func TestASynthesisFollowsCurrentPublicIP(t *testing.T) {
	p := newTestProvider(t, nil)
	ctx := context.Background()

	if err := p.EnsureARecords(ctx, testZone, "203.0.113.10"); err != nil {
		t.Fatalf("ensure a records: %v", err)
	}
	for _, name := range []string{testZone, "tunnel." + testZone, "deep.a.b." + testZone} {
		resp := exchange(t, p, "tcp", dns.TypeA, name)
		requireRcode(t, resp, dns.RcodeSuccess)
		if !resp.Authoritative {
			t.Fatalf("%s: response is not authoritative", name)
		}
		if resp.RecursionAvailable {
			t.Fatalf("%s: recursion must not be advertised", name)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("%s: got %d answers, want 1", name, len(resp.Answer))
		}
		a, ok := resp.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("%s: got %T answer, want A", name, resp.Answer[0])
		}
		if !a.A.Equal(net.ParseIP("203.0.113.10")) {
			t.Fatalf("%s: got %s, want 203.0.113.10", name, a.A)
		}
		if a.Hdr.Ttl != recordTTL {
			t.Fatalf("%s: got ttl %d, want %d", name, a.Hdr.Ttl, recordTTL)
		}
	}

	// Explicit per-hostname A records must never override synthesis, so a
	// public IP change propagates to every hostname immediately.
	if err := p.EnsureARecord(ctx, "tunnel."+testZone, "198.51.100.7"); err != nil {
		t.Fatalf("ensure a record: %v", err)
	}
	if err := p.EnsureARecords(ctx, testZone, "198.51.100.99"); err != nil {
		t.Fatalf("ensure a records: %v", err)
	}
	resp := exchange(t, p, "tcp", dns.TypeA, "tunnel."+testZone)
	a := resp.Answer[0].(*dns.A)
	if !a.A.Equal(net.ParseIP("198.51.100.99")) {
		t.Fatalf("stale explicit answer %s after ip change, want 198.51.100.99", a.A)
	}
	if err := p.DeleteARecord(ctx, "tunnel."+testZone); err != nil {
		t.Fatalf("delete a record: %v", err)
	}
	resp = exchange(t, p, "tcp", dns.TypeA, "tunnel."+testZone)
	if len(resp.Answer) != 1 {
		t.Fatalf("delete removed synthesized answer")
	}
}

func TestAWithoutPublicIPIsNodata(t *testing.T) {
	p := newTestProvider(t, nil)
	resp := exchange(t, p, "tcp", dns.TypeA, testZone)
	requireRcode(t, resp, dns.RcodeSuccess)
	if len(resp.Answer) != 0 {
		t.Fatalf("got %d answers without a public ip, want 0", len(resp.Answer))
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("got %d authority records, want SOA", len(resp.Ns))
	}
	if _, ok := resp.Ns[0].(*dns.SOA); !ok {
		t.Fatalf("got %T authority record, want SOA", resp.Ns[0])
	}
}

func TestTXTRecordLifecycle(t *testing.T) {
	p := newTestProvider(t, nil)
	ctx := context.Background()
	name := "tunnel." + testZone

	if err := p.EnsureTXTRecord(ctx, name, "ENS1 0x238a8f792dfa6033814b18618ad4100654aeef01 0xabc"); err != nil {
		t.Fatalf("ensure txt: %v", err)
	}
	if err := p.EnsureTXTRecord(ctx, name, "dns-01-value"); err != nil {
		t.Fatalf("ensure txt: %v", err)
	}
	if err := p.EnsureTXTRecord(ctx, name, "dns-01-value"); err != nil {
		t.Fatalf("ensure duplicate txt: %v", err)
	}

	resp := exchange(t, p, "tcp", dns.TypeTXT, name)
	requireRcode(t, resp, dns.RcodeSuccess)
	if len(resp.Answer) != 2 {
		t.Fatalf("got %d txt answers, want 2", len(resp.Answer))
	}
	seen := map[string]bool{}
	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			t.Fatalf("got %T answer, want TXT", rr)
		}
		seen[strings.Join(txt.Txt, "")] = true
	}
	if !seen["ENS1 0x238a8f792dfa6033814b18618ad4100654aeef01 0xabc"] || !seen["dns-01-value"] {
		t.Fatalf("missing txt values: %v", seen)
	}

	// Prefix deletion removes only matching values.
	if err := p.DeleteTXTRecords(ctx, name, "ENS1 "); err != nil {
		t.Fatalf("delete txt records: %v", err)
	}
	resp = exchange(t, p, "tcp", dns.TypeTXT, name)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d txt answers after prefix delete, want 1", len(resp.Answer))
	}
	if got := strings.Join(resp.Answer[0].(*dns.TXT).Txt, ""); got != "dns-01-value" {
		t.Fatalf("kept wrong txt value %q", got)
	}
}

func TestDNS01ChallengePresentAndCleanup(t *testing.T) {
	p := newTestProvider(t, nil)
	keyAuth := "token.example-key-authorization"

	if err := p.Present(testZone, "token", keyAuth); err != nil {
		t.Fatalf("present: %v", err)
	}
	fqdn, value := dns01.GetRecord(testZone, keyAuth)
	resp := exchange(t, p, "tcp", dns.TypeTXT, fqdn)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d txt answers, want 1", len(resp.Answer))
	}
	if got := strings.Join(resp.Answer[0].(*dns.TXT).Txt, ""); got != value {
		t.Fatalf("got txt %q, want %q", got, value)
	}

	if err := p.CleanUp(testZone, "token", keyAuth); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	resp = exchange(t, p, "tcp", dns.TypeTXT, fqdn)
	requireRcode(t, resp, dns.RcodeSuccess)
	if len(resp.Answer) != 0 {
		t.Fatalf("txt survived cleanup")
	}
}

func TestHTTPSRecordRoundTrip(t *testing.T) {
	p := newTestProvider(t, nil)
	ctx := context.Background()
	name := "tunnel." + testZone
	ech := []byte{0x00, 0x08, 0xfe, 0x0d, 0x00, 0x20, 0x00, 0x01, 0x41, 0x42}
	svcParams := `ech="` + base64.StdEncoding.EncodeToString(ech) + `" port=8443`

	if err := p.EnsureHTTPSRecord(ctx, name, dnsrecord.HTTPSRecord{Priority: 1, Target: ".", SvcParams: svcParams}); err != nil {
		t.Fatalf("ensure https record: %v", err)
	}

	resp := exchange(t, p, "tcp", dns.TypeHTTPS, name)
	requireRcode(t, resp, dns.RcodeSuccess)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	rr, ok := resp.Answer[0].(*dns.HTTPS)
	if !ok {
		t.Fatalf("got %T answer, want HTTPS", resp.Answer[0])
	}
	if rr.Priority != 1 || rr.Target != "." {
		t.Fatalf("got priority %d target %q", rr.Priority, rr.Target)
	}
	var echSeen []byte
	var portSeen uint16
	for _, kv := range rr.Value {
		switch v := kv.(type) {
		case *dns.SVCBECHConfig:
			echSeen = v.ECH
		case *dns.SVCBPort:
			portSeen = v.Port
		}
	}
	if string(echSeen) != string(ech) {
		t.Fatalf("ech mismatch: got %v, want %v", echSeen, ech)
	}
	if portSeen != 8443 {
		t.Fatalf("port mismatch: got %d, want 8443", portSeen)
	}

	// Hostnames without an HTTPS record resolve via synthesis and answer
	// NODATA for HTTPS instead of NXDOMAIN.
	resp = exchange(t, p, "tcp", dns.TypeHTTPS, "other."+testZone)
	requireRcode(t, resp, dns.RcodeSuccess)
	if len(resp.Answer) != 0 {
		t.Fatalf("got %d https answers for absent record", len(resp.Answer))
	}

	if err := p.DeleteHTTPSRecord(ctx, name); err != nil {
		t.Fatalf("delete https record: %v", err)
	}
	resp = exchange(t, p, "tcp", dns.TypeHTTPS, name)
	if len(resp.Answer) != 0 {
		t.Fatalf("https record survived delete")
	}
}

func TestApexMetadata(t *testing.T) {
	p := newTestProvider(t, nil)
	ctx := context.Background()
	if err := p.EnsureARecords(ctx, testZone, "203.0.113.10"); err != nil {
		t.Fatalf("ensure a records: %v", err)
	}

	nsResp := exchange(t, p, "tcp", dns.TypeNS, testZone)
	requireRcode(t, nsResp, dns.RcodeSuccess)
	if len(nsResp.Answer) != 1 {
		t.Fatalf("got %d ns answers, want 1", len(nsResp.Answer))
	}
	ns, ok := nsResp.Answer[0].(*dns.NS)
	if !ok || ns.Ns != "ns."+testZone+"." {
		t.Fatalf("got %v, want ns.%s.", nsResp.Answer[0], testZone)
	}
	if len(nsResp.Extra) != 1 {
		t.Fatalf("got %d additional records, want in-bailiwick glue A", len(nsResp.Extra))
	}
	if glue, ok := nsResp.Extra[0].(*dns.A); !ok || !glue.A.Equal(net.ParseIP("203.0.113.10")) {
		t.Fatalf("got %v glue, want A 203.0.113.10", nsResp.Extra[0])
	}

	soaResp := exchange(t, p, "tcp", dns.TypeSOA, testZone)
	soa, ok := soaResp.Answer[0].(*dns.SOA)
	if !ok {
		t.Fatalf("got %T answer, want SOA", soaResp.Answer[0])
	}
	if soa.Ns != "ns."+testZone+"." || soa.Mbox != "hostmaster."+testZone+"." {
		t.Fatalf("got soa ns %q mbox %q", soa.Ns, soa.Mbox)
	}
	if soa.Minttl != recordTTL {
		t.Fatalf("got soa minttl %d, want %d", soa.Minttl, recordTTL)
	}

	// Mutations advance the SOA serial.
	before := soa.Serial
	if err := p.EnsureTXTRecord(ctx, testZone, "value"); err != nil {
		t.Fatalf("ensure txt: %v", err)
	}
	after := exchange(t, p, "tcp", dns.TypeSOA, testZone).Answer[0].(*dns.SOA).Serial
	if after <= before {
		t.Fatalf("soa serial did not advance: %d -> %d", before, after)
	}
}

func TestQueryBoundaries(t *testing.T) {
	p := newTestProvider(t, nil)
	ctx := context.Background()
	if err := p.EnsureARecords(ctx, testZone, "203.0.113.10"); err != nil {
		t.Fatalf("ensure a records: %v", err)
	}

	if resp := exchange(t, p, "tcp", dns.TypeA, "example.com."); resp.Rcode != dns.RcodeRefused {
		t.Fatalf("outside-zone query rcode %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if resp := exchange(t, p, "tcp", dns.TypeAAAA, testZone); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("aaaa must be NODATA, got rcode %s with %d answers", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	if resp := exchange(t, p, "tcp", dns.TypeNS, "child."+testZone); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("non-apex ns must be NODATA")
	}

	anyResp := new(dns.Msg)
	anyResp.SetQuestion(dns.Fqdn(testZone), dns.TypeANY)
	client := &dns.Client{Net: "tcp"}
	resp, _, err := client.Exchange(anyResp, p.Addr())
	if err != nil {
		t.Fatalf("exchange ANY: %v", err)
	}
	if resp.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("ANY rcode %s, want NOTIMP", dns.RcodeToString[resp.Rcode])
	}
}

func TestUDPExchangeWithEDNS(t *testing.T) {
	p := newTestProvider(t, nil)
	ctx := context.Background()
	if err := p.EnsureARecords(ctx, testZone, "203.0.113.10"); err != nil {
		t.Fatalf("ensure a records: %v", err)
	}
	resp := exchange(t, p, "udp", dns.TypeA, "tunnel."+testZone)
	requireRcode(t, resp, dns.RcodeSuccess)
	if len(resp.Answer) != 1 {
		t.Fatalf("udp got %d answers, want 1", len(resp.Answer))
	}
	if resp.IsEdns0() == nil {
		t.Fatalf("edns query did not get an edns response")
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New(Config{BaseDomain: ""}); err == nil {
		t.Fatalf("empty base domain accepted")
	}
	if _, err := New(Config{BaseDomain: "192.0.2.10", ListenAddr: "127.0.0.1:0"}); err == nil {
		t.Fatalf("ip base domain accepted")
	}
	p := newTestProvider(t, nil)
	ctx := context.Background()
	if err := p.EnsureTXTRecord(ctx, "other.example.com", "value"); err == nil {
		t.Fatalf("outside-zone txt accepted")
	}
	if err := p.EnsureARecords(ctx, "other.example.com", "203.0.113.10"); err == nil {
		t.Fatalf("outside-zone base domain accepted")
	}
	if err := p.EnsureARecords(ctx, testZone, "not-an-ip"); err == nil {
		t.Fatalf("invalid ipv4 accepted")
	}
	if _, _, _, err := p.EnsureDNSSEC(ctx, testZone); err == nil {
		t.Fatalf("dnssec must report unsupported")
	}
}

func TestStopIsIdempotent(t *testing.T) {
	p := newTestProvider(t, nil)
	if err := p.Stop(); err != nil {
		t.Fatalf("first stop: %v", err)
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("second stop: %v", err)
	}
}
