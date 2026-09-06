package embedded

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func dnssecExchange(t *testing.T, p *Provider, network, name string, typ uint16, size uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), typ)
	q.SetEdns0(size, true)
	response, _, err := (&dns.Client{Net: network}).Exchange(q, p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if response.IsEdns0() == nil || !response.IsEdns0().Do() {
		t.Fatal("DNSSEC request lost EDNS DO")
	}
	return response
}

func verifySection(t *testing.T, key *dns.DNSKEY, records []dns.RR) {
	t.Helper()
	sets := make(map[string][]dns.RR)
	signatures := make(map[string]*dns.RRSIG)
	for _, rr := range records {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT {
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok {
			signatures[h.Name+"/"+dns.TypeToString[sig.TypeCovered]] = sig
		} else {
			sets[h.Name+"/"+dns.TypeToString[h.Rrtype]] = append(sets[h.Name+"/"+dns.TypeToString[h.Rrtype]], rr)
		}
	}
	for id, set := range sets {
		sig := signatures[id]
		if sig == nil {
			t.Fatalf("unsigned RRset %s", id)
		}
		if !sig.ValidityPeriod(time.Now()) {
			t.Fatalf("signature outside validity period: %s", id)
		}
		if err := sig.Verify(key, set); err != nil {
			t.Fatalf("verify %s: %v", id, err)
		}
	}
}

func denialRecords(m *dns.Msg) []*dns.NSEC {
	var records []*dns.NSEC
	for _, rr := range m.Ns {
		if nsec, ok := rr.(*dns.NSEC); ok {
			records = append(records, nsec)
		}
	}
	return records
}

func compareTestDNSNames(a, b string) int {
	al, bl := strings.Split(strings.TrimSuffix(strings.ToLower(a), "."), "."), strings.Split(strings.TrimSuffix(strings.ToLower(b), "."), ".")
	for i, j := len(al)-1, len(bl)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if al[i] < bl[j] { return -1 }
		if al[i] > bl[j] { return 1 }
	}
	if len(al) < len(bl) { return -1 }
	if len(al) > len(bl) { return 1 }
	return 0
}

func requireDenial(t *testing.T, m *dns.Msg, name string) {
	t.Helper()
	name = dns.Fqdn(name)
	for _, nsec := range denialRecords(m) {
		start, end := compareTestDNSNames(nsec.Hdr.Name, name), compareTestDNSNames(name, nsec.NextDomain)
		wraps := compareTestDNSNames(nsec.Hdr.Name, nsec.NextDomain) >= 0
		if start < 0 && end < 0 || wraps && (start < 0 || end < 0) {
			return
		}
	}
	t.Fatalf("no NSEC covers %s: %v", name, m.Ns)
}

func TestDNSSECSigningAndWildcardDenial(t *testing.T) {
	p := newTestProvider(t, nil)
	ctx := context.Background()
	if err := p.EnsureARecords(ctx, testZone, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureTXTRecord(ctx, "leaf.branch."+testZone, "ENS1 example"); err != nil {
		t.Fatal(err)
	}
	keys := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key, ok := keys.Answer[0].(*dns.DNSKEY)
	if !ok || key.Flags != 257 || key.Algorithm != dns.ECDSAP256SHA256 {
		t.Fatalf("unexpected DNSKEY: %v", keys.Answer)
	}
	verifySection(t, key, keys.Answer)
	for _, network := range []string{"tcp", "udp"} {
		for _, name := range []string{testZone, "leaf.branch." + testZone, "deep.child.branch." + testZone, strings.ToUpper("unknown." + testZone)} {
			response := dnssecExchange(t, p, network, name, dns.TypeA, 1232)
			requireRcode(t, response, dns.RcodeSuccess)
			if len(response.Answer) != 2 {
				t.Fatalf("expected A and RRSIG: %v", response.Answer)
			}
			verifySection(t, key, response.Answer)
			verifySection(t, key, response.Ns)
			if strings.HasPrefix(name, "deep.") {
				requireDenial(t, response, "child.branch."+testZone)
			}
		}
	}
	for _, name := range []string{"leaf.branch." + testZone, "child.branch." + testZone} {
		response := dnssecExchange(t, p, "tcp", name, dns.TypeAAAA, 1232)
		requireRcode(t, response, dns.RcodeSuccess)
		if len(response.Answer) != 0 {
			t.Fatal("AAAA must be NODATA")
		}
		verifySection(t, key, response.Ns)
		owner := dns.Fqdn(name)
		if strings.HasPrefix(name, "child.") {
			owner = "*.branch." + dns.Fqdn(testZone)
			requireDenial(t, response, name)
		}
		found := false
		for _, nsec := range denialRecords(response) {
			if nsec.Hdr.Name == owner {
				found = true
				if slices.Contains(nsec.TypeBitMap, dns.TypeAAAA) {
					t.Fatal("NODATA bitmap includes AAAA")
				}
			}
		}
		if !found {
			t.Fatalf("missing NODATA proof for %s", owner)
		}
	}
	unsigned := exchange(t, p, "tcp", dns.TypeA, "unknown."+testZone)
	if len(unsigned.Answer) != 1 || len(unsigned.Ns) != 0 {
		t.Fatalf("DO absent leaked DNSSEC records: %v", unsigned)
	}
	// Direct DNSSEC queries are answered even without DO.
	if response := exchange(t, p, "tcp", dns.TypeDNSKEY, testZone); len(response.Answer) != 1 {
		t.Fatalf("DNSKEY query without DO: %v", response)
	}
	if response := exchange(t, p, "tcp", dns.TypeRRSIG, testZone); len(response.Answer) == 0 {
		t.Fatal("RRSIG query without DO is empty")
	}
}

func TestDNSSECNameErrorAndEmptyNonterminal(t *testing.T) {
	p := newTestProvider(t, nil)
	if err := p.EnsureTXTRecord(context.Background(), "leaf.branch."+testZone, "value"); err != nil {
		t.Fatal(err)
	}
	// No public address means no synthesized wildcard exists yet.
	for _, name := range []string{"absent." + testZone, "deep.absent.branch." + testZone} {
		response := dnssecExchange(t, p, "tcp", name, dns.TypeA, 1232)
		requireRcode(t, response, dns.RcodeNameError)
		verifySection(t, p.key, response.Ns)
		if strings.Contains(name, ".branch.") {
			requireDenial(t, response, "absent.branch."+testZone)
			requireDenial(t, response, "*.branch."+testZone)
		} else {
			requireDenial(t, response, name)
			requireDenial(t, response, "*."+testZone)
		}
	}
	response := dnssecExchange(t, p, "tcp", "branch."+testZone, dns.TypeTXT, 1232)
	requireRcode(t, response, dns.RcodeSuccess)
	verifySection(t, p.key, response.Ns)
	if len(response.Answer) != 0 {
		t.Fatal("empty nonterminal returned data")
	}
}

func TestDNSSECKeyPersistenceAndFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnssec-csk.json")
	cfg := Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path}
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, ds, message, err := first.EnsureDNSSEC(context.Background(), testZone)
	if err != nil || ds != first.key.ToDS(dns.SHA256).String() || !strings.Contains(message, "parent") {
		t.Fatalf("invalid DS export: %q %q %v", ds, message, err)
	}
	if err := first.Stop(); err != nil {
		t.Fatal(err)
	}
	second, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, nextDS, _, err := second.EnsureDNSSEC(context.Background(), testZone)
	if err != nil || nextDS != ds {
		t.Fatalf("DS changed across restart: %q => %q (%v)", ds, nextDS, err)
	}
	response := dnssecExchange(t, second, "tcp", testZone, dns.TypeDNSKEY, 1232)
	verifySection(t, first.key, response.Answer)
	if err := second.Stop(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.BaseDomain = "different.example.com"
	if wrong, err := New(cfg); err == nil {
		_ = wrong.Stop()
		t.Fatal("accepted another zone's key")
	}
	cfg.BaseDomain = testZone
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := New(cfg); err == nil {
			t.Fatal("accepted world-readable private key")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte("incomplete key"), 0600); err != nil {
		t.Fatal(err)
	}
	if broken, err := New(cfg); err == nil {
		_ = broken.Stop()
		t.Fatal("replaced a corrupt persisted key")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != "incomplete key" {
		t.Fatal("failed key load modified persisted state")
	}
	if len(data) == 0 {
		t.Fatal("empty persisted private key")
	}
}

func TestDNSSECRefreshAndMutation(t *testing.T) {
	p := newTestProvider(t, nil)
	now := time.Now()
	original, err := p.signedZone(now)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := p.signedZone(now.Add(time.Minute))
	if err != nil || cached != original {
		t.Fatal("unchanged signatures were not reused")
	}
	refreshed, err := p.signedZone(now.Add(signatureRefresh + time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	oldSig := original.records[p.zone][dns.TypeDNSKEY].signature
	newSet := refreshed.records[p.zone][dns.TypeDNSKEY]
	if newSet.signature.Expiration <= oldSig.Expiration || !newSet.signature.ValidityPeriod(now.Add(signatureRefresh+time.Minute)) {
		t.Fatal("signature expiration was not refreshed")
	}
	if err := newSet.signature.Verify(p.key, newSet.records); err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureTXTRecord(context.Background(), "new."+testZone, "value"); err != nil {
		t.Fatal(err)
	}
	response := dnssecExchange(t, p, "tcp", "new."+testZone, dns.TypeTXT, 1232)
	if len(response.Answer) != 2 {
		t.Fatalf("new RRset not signed: %v", response)
	}
	verifySection(t, p.key, response.Answer)
	if err := p.DeleteTXTRecords(context.Background(), "new."+testZone, "value"); err != nil {
		t.Fatal(err)
	}
	response = dnssecExchange(t, p, "tcp", "new."+testZone, dns.TypeTXT, 1232)
	requireRcode(t, response, dns.RcodeNameError)
	verifySection(t, p.key, response.Ns)
}

func TestDNSSECUDPTruncationAndTCPRetry(t *testing.T) {
	p := newTestProvider(t, nil)
	for i := range 8 {
		if err := p.EnsureTXTRecord(context.Background(), testZone, strings.Repeat(string(rune('a'+i)), 200)); err != nil {
			t.Fatal(err)
		}
	}
	udp := dnssecExchange(t, p, "udp", testZone, dns.TypeTXT, 512)
	if !udp.Truncated {
		t.Fatal("oversize UDP answer was not truncated")
	}
	tcp := dnssecExchange(t, p, "tcp", testZone, dns.TypeTXT, 512)
	if tcp.Truncated || len(tcp.Answer) != 9 {
		t.Fatalf("TCP did not return complete signed RRset: %v", tcp)
	}
	verifySection(t, p.key, tcp.Answer)
}
