package embedded

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const testZone = "portal.example.com"

func newTestProvider(t *testing.T, mutate func(*Config)) *Provider {
	t.Helper()
	cfg := Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: filepath.Join(t.TempDir(), types.DNSSECKeyFileName)}
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

func checkSynthesizedARecord(t *testing.T, p *Provider, name string) {
	t.Helper()
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

func checkSynthesizedARollover(t *testing.T, p *Provider) {
	t.Helper()
	if err := p.EnsureAddressRecord(t.Context(), "tunnel."+testZone, "198.51.100.7"); err != nil {
		t.Fatalf("ensure a record: %v", err)
	}
	if err := p.EnsureAddressRecords(t.Context(), testZone, "198.51.100.99"); err != nil {
		t.Fatalf("ensure a records: %v", err)
	}
	updated := exchange(t, p, "tcp", dns.TypeA, "tunnel."+testZone)
	updatedA := updated.Answer[0].(*dns.A)
	if !updatedA.A.Equal(net.ParseIP("198.51.100.99")) {
		t.Fatalf("stale explicit answer %s after ip change, want 198.51.100.99", updatedA.A)
	}
	if err := p.DeleteAddressRecords(t.Context(), "tunnel."+testZone); err != nil {
		t.Fatalf("delete a record: %v", err)
	}
	afterDelete := exchange(t, p, "tcp", dns.TypeA, "tunnel."+testZone)
	if len(afterDelete.Answer) != 1 {
		t.Fatalf("delete removed synthesized answer")
	}
}

func TestASynthesisFollowsCurrentPublicIP(t *testing.T) {
	p := newTestProvider(t, nil)
	if err := p.EnsureAddressRecords(t.Context(), testZone, "203.0.113.10"); err != nil {
		t.Fatalf("ensure a records: %v", err)
	}
	for _, name := range []string{testZone, "tunnel." + testZone, "deep.a.b." + testZone} {
		checkSynthesizedARecord(t, p, name)
	}
	checkSynthesizedARollover(t, p)
}

func checkPreservedFamilyRecord(t *testing.T, p *Provider, tc struct {
	typ uint16
	ip  string
}, name, publicIP string) {
	t.Helper()
	response := exchange(t, p, "tcp", tc.typ, name)
	requireRcode(t, response, dns.RcodeSuccess)
	if tc.ip == "" {
		if len(response.Answer) != 0 {
			t.Fatalf("%s %s before publication returned %v", name, dns.TypeToString[tc.typ], response.Answer)
		}
		return
	}
	if len(response.Answer) != 1 {
		t.Fatalf("%s %s after updating %s: %v", name, dns.TypeToString[tc.typ], publicIP, response.Answer)
	}
	var got net.IP
	switch record := response.Answer[0].(type) {
	case *dns.A:
		got = record.A
	case *dns.AAAA:
		got = record.AAAA
	}
	if response.Answer[0].Header().Rrtype != tc.typ || !got.Equal(net.ParseIP(tc.ip)) {
		t.Fatalf("%s %s after updating %s = %v, want %s", name, dns.TypeToString[tc.typ], publicIP, response.Answer, tc.ip)
	}
}

func checkPreservedFamilyBatch(t *testing.T, p *Provider, publicIP, ipv4, ipv6 string) {
	t.Helper()
	for _, tc := range []struct {
		typ uint16
		ip  string
	}{{dns.TypeA, ipv4}, {dns.TypeAAAA, ipv6}} {
		for _, name := range []string{testZone, "tunnel." + testZone, "deep.child." + testZone} {
			checkPreservedFamilyRecord(t, p, tc, name, publicIP)
		}
	}
}

func checkPreservedFamilyFinal(t *testing.T, p *Provider, ipv6 string) {
	t.Helper()
	if err := p.EnsureAddressRecord(t.Context(), "tunnel."+testZone, "2001:db8::99"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteAddressRecords(t.Context(), "tunnel."+testZone); err != nil {
		t.Fatal(err)
	}
	response := exchange(t, p, "tcp", dns.TypeAAAA, "tunnel."+testZone)
	if len(response.Answer) != 1 {
		t.Fatalf("explicit mutation removed synthesized AAAA: %v", response.Answer)
	}
	if record, ok := response.Answer[0].(*dns.AAAA); !ok || !record.AAAA.Equal(net.ParseIP(ipv6)) {
		t.Fatalf("explicit mutation changed synthesized AAAA: %v", response.Answer)
	}
}

func TestAddressSynthesisPreservesOtherFamily(t *testing.T) {
	p := newTestProvider(t, nil)
	var ipv4, ipv6 string
	for _, publicIP := range []string{"2001:db8::10", "203.0.113.10", "2001:db8::20", "203.0.113.20"} {
		if err := p.EnsureAddressRecords(t.Context(), testZone, publicIP); err != nil {
			t.Fatal(err)
		}
		if net.ParseIP(publicIP).To4() != nil {
			ipv4 = publicIP
		} else {
			ipv6 = publicIP
		}
		checkPreservedFamilyBatch(t, p, publicIP, ipv4, ipv6)
	}
	checkPreservedFamilyFinal(t, p, ipv6)
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

func TestAWithoutPublicIPRefusesMissingNames(t *testing.T) {
	p := newTestProvider(t, nil)

	for _, name := range []string{"tunnel." + testZone, "deep.a.b." + testZone} {
		resp := exchange(t, p, "tcp", dns.TypeA, name)
		requireRcode(t, resp, dns.RcodeRefused)
		if len(resp.Answer) != 0 {
			t.Fatalf("%s: got %d answers without a public ip, want 0", name, len(resp.Answer))
		}
		if len(resp.Ns) != 0 {
			t.Fatalf("%s: got %d authority records, want no SOA on REFUSED", name, len(resp.Ns))
		}
	}

	if err := p.EnsureAddressRecords(t.Context(), testZone, "203.0.113.10"); err != nil {
		t.Fatalf("ensure a records: %v", err)
	}
	resp := exchange(t, p, "tcp", dns.TypeA, "tunnel."+testZone)
	requireRcode(t, resp, dns.RcodeSuccess)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers after the address synced, want 1", len(resp.Answer))
	}
}

func seedTXTRecordSet(t *testing.T, p *Provider, name string) {
	t.Helper()
	if err := p.EnsureTXTRecord(t.Context(), name, "ENS1 0x238a8f792dfa6033814b18618ad4100654aeef01 0xabc"); err != nil {
		t.Fatalf("ensure txt: %v", err)
	}
	if err := p.EnsureTXTRecord(t.Context(), name, "dns-01-value"); err != nil {
		t.Fatalf("ensure txt: %v", err)
	}
	if err := p.EnsureTXTRecord(t.Context(), name, "dns-01-value"); err != nil {
		t.Fatalf("ensure duplicate txt: %v", err)
	}
}

func checkBothTXTRecords(t *testing.T, p *Provider, name string) {
	t.Helper()
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
}

func checkRemainingTXTRecord(t *testing.T, p *Provider, name string) {
	t.Helper()
	if err := p.DeleteTXTRecords(t.Context(), name, "ENS1 "); err != nil {
		t.Fatalf("delete txt records: %v", err)
	}
	resp := exchange(t, p, "tcp", dns.TypeTXT, name)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d txt answers after prefix delete, want 1", len(resp.Answer))
	}
	if got := strings.Join(resp.Answer[0].(*dns.TXT).Txt, ""); got != "dns-01-value" {
		t.Fatalf("kept wrong txt value %q", got)
	}
}

func TestTXTRecordLifecycle(t *testing.T) {
	p := newTestProvider(t, nil)
	name := "tunnel." + testZone
	seedTXTRecordSet(t, p, name)
	checkBothTXTRecords(t, p, name)
	checkRemainingTXTRecord(t, p, name)
}

func TestDNS01ChallengePresentAndCleanup(t *testing.T) {
	p := newTestProvider(t, nil)
	keyAuth := "token.example-key-authorization"

	if err := p.Present(testZone, "token", keyAuth); err != nil {
		t.Fatalf("present: %v", err)
	}
	info := dns01.GetChallengeInfo(testZone, keyAuth)
	resp := exchange(t, p, "tcp", dns.TypeTXT, info.EffectiveFQDN)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d txt answers, want 1", len(resp.Answer))
	}
	if got := strings.Join(resp.Answer[0].(*dns.TXT).Txt, ""); got != info.Value {
		t.Fatalf("got txt %q, want %q", got, info.Value)
	}

	if err := p.CleanUp(testZone, "token", keyAuth); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	resp = exchange(t, p, "tcp", dns.TypeTXT, info.EffectiveFQDN)
	requireRcode(t, resp, dns.RcodeRefused)
	if len(resp.Answer) != 0 {
		t.Fatalf("txt survived cleanup")
	}
}

func checkApexNSGlue(t *testing.T, p *Provider) {
	t.Helper()
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
}

func queryApexSOASerial(t *testing.T, p *Provider) uint32 {
	t.Helper()
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
	return soa.Serial
}

func checkAdvancedSOASerial(t *testing.T, p *Provider, before uint32) {
	t.Helper()
	if err := p.EnsureTXTRecord(t.Context(), testZone, "value"); err != nil {
		t.Fatalf("ensure txt: %v", err)
	}
	after := exchange(t, p, "tcp", dns.TypeSOA, testZone).Answer[0].(*dns.SOA).Serial
	if after <= before {
		t.Fatalf("soa serial did not advance: %d -> %d", before, after)
	}
}

func TestApexMetadata(t *testing.T) {
	p := newTestProvider(t, nil)
	if err := p.EnsureAddressRecords(t.Context(), testZone, "203.0.113.10"); err != nil {
		t.Fatalf("ensure a records: %v", err)
	}
	checkApexNSGlue(t, p)
	before := queryApexSOASerial(t, p)
	checkAdvancedSOASerial(t, p, before)
}

func TestQueryBoundaries(t *testing.T) {
	p := newTestProvider(t, nil)
	if err := p.EnsureAddressRecords(t.Context(), testZone, "203.0.113.10"); err != nil {
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

func checkBadVersionOPTOnly(t *testing.T, p *Provider, network string) {
	t.Helper()
	for _, do := range []bool{false, true} {
		query := new(dns.Msg)
		query.SetQuestion(dns.Fqdn(testZone), dns.TypeNS)
		query.SetEdns0(1232, do)
		query.IsEdns0().SetVersion(1)
		response, _, err := (&dns.Client{Net: network}).Exchange(query, p.Addr())
		if err != nil {
			t.Fatal(err)
		}
		requireRcode(t, response, dns.RcodeBadVers)
		if len(response.Answer) != 0 || len(response.Ns) != 0 || len(response.Extra) != 1 || response.Truncated {
			t.Fatalf("%s DO=%t: BADVERS must contain only OPT: %v", network, do, response)
		}
		opt := response.IsEdns0()
		if opt == nil || opt.Version() != 0 || opt.ExtendedRcode() != dns.RcodeBadVers || opt.Do() != do {
			t.Fatalf("%s DO=%t: invalid BADVERS OPT: %v", network, do, opt)
		}
	}
}

func TestUnsupportedEDNSVersionContainsOnlyOPT(t *testing.T) {
	p := newTestProvider(t, nil)
	if err := p.EnsureAddressRecords(t.Context(), testZone, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"tcp", "udp"} {
		checkBadVersionOPTOnly(t, p, network)
	}
}

func TestUDPExchangeWithEDNS(t *testing.T) {
	p := newTestProvider(t, nil)
	if err := p.EnsureAddressRecords(t.Context(), testZone, "203.0.113.10"); err != nil {
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

func TestMutationsOutsideZoneRejected(t *testing.T) {
	p := newTestProvider(t, nil)
	if err := p.EnsureTXTRecord(t.Context(), "other.example.com", "value"); err == nil {
		t.Fatalf("outside-zone txt accepted")
	}
	if err := p.EnsureAddressRecords(t.Context(), "other.example.com", "203.0.113.10"); err == nil {
		t.Fatalf("outside-zone base domain accepted")
	}
}
