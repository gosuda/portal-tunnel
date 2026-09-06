package embedded

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"

	"github.com/gosuda/portal-tunnel/v2/types"
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

func requireNSEC(t *testing.T, m *dns.Msg, owner, next string) {
	t.Helper()
	for _, nsec := range denialRecords(m) {
		if nsec.Hdr.Name == dns.Fqdn(owner) && nsec.NextDomain == dns.Fqdn(next) {
			return
		}
	}
	t.Fatalf("missing NSEC %s -> %s: %v", owner, next, m.Ns)
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
				// The next-closer child.branch lies between these known owners.
				requireNSEC(t, response, "*.branch."+testZone, "leaf.branch."+testZone)
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
			requireNSEC(t, response, "*.branch."+testZone, "leaf.branch."+testZone)
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
			// One interval denies both absent.branch and *.branch.
			requireNSEC(t, response, "branch."+testZone, "leaf.branch."+testZone)
		} else {
			// One interval denies both absent and the apex wildcard.
			requireNSEC(t, response, testZone, "branch."+testZone)
		}
	}
	response := dnssecExchange(t, p, "tcp", "branch."+testZone, dns.TypeTXT, 1232)
	requireRcode(t, response, dns.RcodeSuccess)
	verifySection(t, p.key, response.Ns)
	if len(response.Answer) != 0 {
		t.Fatal("empty nonterminal returned data")
	}
}

func TestDNSSECCanonicalDenialIntervals(t *testing.T) {
	p := newTestProvider(t, nil)
	for _, owner := range []string{"a.", "z.a.", "aa.", "b."} {
		if err := p.EnsureTXTRecord(context.Background(), owner+testZone, "value"); err != nil {
			t.Fatal(err)
		}
	}
	keys := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := keys.Answer[0].(*dns.DNSKEY)
	// RFC 4034 section 6.1 gives this fixed order: apex, a, z.a, aa, b.
	// These expected intervals deliberately do not sort with the server's code.
	for _, network := range []string{"tcp", "udp"} {
		for _, tc := range []struct {
			name  string
			owner string
			next  string
		}{
			{name: `\096.`, owner: "", next: "a."},
			{name: "m.a.", owner: "a.", next: "z.a."},
			{name: "a0.", owner: "z.a.", next: "aa."},
			{name: `\0970.`, owner: "z.a.", next: "aa."},
			{name: "az.", owner: "aa.", next: "b."},
			{name: "B0.", owner: "b.", next: ""},
		} {
			t.Run(network+"/"+tc.name, func(t *testing.T) {
				response := dnssecExchange(t, p, network, tc.name+testZone, dns.TypeA, 1232)
				requireRcode(t, response, dns.RcodeNameError)
				verifySection(t, key, response.Ns)
				requireNSEC(t, response, tc.owner+testZone, tc.next+testZone)
			})
		}
	}
}

func TestDNSSECKeyPersistenceAndFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), types.DNSSECKeyFileName)
	cfg := Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path}
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	keys := dnssecExchange(t, first, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := keys.Answer[0].(*dns.DNSKEY)
	_, ds, message, err := first.EnsureDNSSEC(context.Background(), testZone)
	if err != nil || ds != key.ToDS(dns.SHA256).String() || !strings.Contains(message, "parent") {
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
	verifySection(t, key, response.Answer)
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
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, data) {
		t.Fatal("wrong-zone key load modified persisted state")
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
	const maxSize = 16 * 1024
	if len(data) == 0 || len(data) >= maxSize {
		t.Fatalf("unexpected persisted private key size: %d", len(data))
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "incomplete", data: []byte("incomplete key")},
		{name: "truncated JSON", data: data[:len(data)-1]},
		{name: "trailing JSON", data: []byte(string(data) + " {}")},
		{name: "trailing garbage", data: []byte(string(data) + " corrupt")},
		{name: "oversized whitespace", data: []byte(string(data) + strings.Repeat(" ", maxSize+1-len(data)))},
		{name: "corruption past read limit", data: []byte(string(data) + strings.Repeat(" ", maxSize-len(data)) + "corrupt")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			if broken, err := New(cfg); err == nil {
				_ = broken.Stop()
				t.Fatal("accepted or replaced a corrupt persisted key")
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, tc.data) {
				t.Fatal("failed key load modified persisted state")
			}
		})
	}
	// Whitespace at the accepted size boundary is valid JSON, not oversize.
	bounded := []byte(string(data) + strings.Repeat(" ", maxSize-len(data)))
	if err := os.WriteFile(path, bounded, 0600); err != nil {
		t.Fatal(err)
	}
	last, err := New(cfg)
	if err != nil {
		t.Fatalf("rejected valid key at size limit: %v", err)
	}
	defer func() { _ = last.Stop() }()
	_, lastDS, _, err := last.EnsureDNSSEC(context.Background(), testZone)
	if err != nil || lastDS != ds {
		t.Fatalf("valid padded key changed DS: %q (%v)", lastDS, err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, bounded) {
		t.Fatal("valid key load modified persisted state")
	}
}

func TestDNSSECConcurrentKeyCreation(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: filepath.Join(dir, types.DNSSECKeyFileName)}
	type result struct {
		provider *Provider
		err      error
	}
	const starts = 8
	ready := make(chan struct{}, starts)
	start := make(chan struct{})
	results := make(chan result, starts)
	for range starts {
		go func() {
			ready <- struct{}{}
			<-start
			p, err := New(cfg)
			results <- result{p, err}
		}()
	}
	for range starts {
		<-ready
	}
	close(start)
	var providers []*Provider
	for range starts {
		got := <-results
		if got.err != nil {
			t.Errorf("concurrent start failed: %v", got.err)
			continue
		}
		providers = append(providers, got.provider)
		t.Cleanup(func() {
			if err := got.provider.Stop(); err != nil {
				t.Error(err)
			}
		})
	}
	if t.Failed() {
		return
	}
	var ds string
	var key *dns.DNSKEY
	for _, p := range providers {
		_, gotDS, _, err := p.EnsureDNSSEC(context.Background(), testZone)
		if err != nil {
			t.Fatal(err)
		}
		response := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
		gotKey := response.Answer[0].(*dns.DNSKEY)
		if key == nil {
			key, ds = gotKey, gotDS
		}
		if gotDS != ds || gotDS != gotKey.ToDS(dns.SHA256).String() || gotKey.PublicKey != key.PublicKey {
			t.Fatal("simultaneous starts did not preserve one key and DS")
		}
		verifySection(t, key, response.Answer)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != types.DNSSECKeyFileName {
		t.Fatalf("key publication left temporary files: %v", entries)
	}
	info, err := os.Stat(cfg.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("published private key has permissive mode: %v", info.Mode())
	}
}

// Only LocalAddr and WriteMsg are used by ServeDNS. Embedding the interface
// makes any unexpected writer operation fail rather than silently succeed.
// Packing here and unpacking in the test assert DNS wire data, not cache state.
type dnssecResponseWriter struct {
	dns.ResponseWriter
	wire []byte
}

func (*dnssecResponseWriter) LocalAddr() net.Addr { return &net.TCPAddr{} }

func (w *dnssecResponseWriter) WriteMsg(m *dns.Msg) error {
	var err error
	w.wire, err = m.Pack()
	return err
}

func TestDNSSECRefreshAndMutation(t *testing.T) {
	// Real listener goroutines stay outside the fake-time bubble so they do
	// not prevent its clock from advancing while the handler is idle.
	p := newTestProvider(t, nil)
	keys := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := keys.Answer[0].(*dns.DNSKEY)
	synctest.Test(t, func(t *testing.T) {
		query := new(dns.Msg)
		query.SetQuestion(dns.Fqdn(testZone), dns.TypeDNSKEY)
		query.SetEdns0(1232, true)
		querySignature := func() *dns.RRSIG {
			writer := new(dnssecResponseWriter)
			p.ServeDNS(writer, query)
			response := new(dns.Msg)
			if err := response.Unpack(writer.wire); err != nil {
				t.Fatal(err)
			}
			requireRcode(t, response, dns.RcodeSuccess)
			verifySection(t, key, response.Answer)
			for _, rr := range response.Answer {
				if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeDNSKEY {
					return sig
				}
			}
			t.Fatal("missing DNSKEY signature")
			return nil
		}
		original := querySignature()
		<-time.After(12 * time.Hour)
		refreshed := querySignature()
		if refreshed.Expiration <= original.Expiration {
			t.Fatal("idle zone did not renew signatures at the 12-hour boundary")
		}
		<-time.After(13 * time.Hour)
		if original.ValidityPeriod(time.Now()) {
			t.Fatal("test did not advance beyond the original signature lifetime")
		}
		if renewed := querySignature(); renewed.Expiration <= refreshed.Expiration {
			t.Fatal("idle zone did not renew signatures beyond the original lifetime")
		}
	})

	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			name := "new." + testZone
			before := dnssecExchange(t, p, network, testZone, dns.TypeSOA, 1232)
			verifySection(t, key, before.Answer)
			beforeSerial := before.Answer[0].(*dns.SOA).Serial
			absent := dnssecExchange(t, p, network, name, dns.TypeTXT, 1232)
			requireRcode(t, absent, dns.RcodeNameError)
			verifySection(t, key, absent.Ns)
			requireNSEC(t, absent, testZone, testZone)

			if err := p.EnsureTXTRecord(context.Background(), name, "value"); err != nil {
				t.Fatal(err)
			}
			response := dnssecExchange(t, p, network, name, dns.TypeTXT, 1232)
			requireRcode(t, response, dns.RcodeSuccess)
			if len(response.Answer) != 2 {
				t.Fatalf("new RRset not signed: %v", response)
			}
			if txt, ok := response.Answer[0].(*dns.TXT); !ok || strings.Join(txt.Txt, "") != "value" {
				t.Fatalf("new TXT value missing: %v", response.Answer)
			}
			verifySection(t, key, response.Answer)
			created := dnssecExchange(t, p, network, testZone, dns.TypeSOA, 1232)
			verifySection(t, key, created.Answer)
			createdSerial := created.Answer[0].(*dns.SOA).Serial
			if createdSerial <= beforeSerial {
				t.Fatal("TXT creation did not advance the served SOA serial")
			}
			nodata := dnssecExchange(t, p, network, name, dns.TypeAAAA, 1232)
			requireRcode(t, nodata, dns.RcodeSuccess)
			verifySection(t, key, nodata.Ns)
			requireNSEC(t, nodata, name, testZone)
			for _, nsec := range denialRecords(nodata) {
				if nsec.Hdr.Name == dns.Fqdn(name) && (!slices.Contains(nsec.TypeBitMap, dns.TypeTXT) || slices.Contains(nsec.TypeBitMap, dns.TypeAAAA)) {
					t.Fatalf("incorrect new owner type bitmap: %v", nsec)
				}
			}

			if err := p.DeleteTXTRecords(context.Background(), name, "value"); err != nil {
				t.Fatal(err)
			}
			response = dnssecExchange(t, p, network, name, dns.TypeTXT, 1232)
			requireRcode(t, response, dns.RcodeNameError)
			if len(response.Answer) != 0 {
				t.Fatalf("deleted TXT is still served: %v", response.Answer)
			}
			verifySection(t, key, response.Ns)
			requireNSEC(t, response, testZone, testZone)
			deletedSerial := response.Ns[0].(*dns.SOA).Serial
			if deletedSerial <= createdSerial {
				t.Fatal("TXT deletion did not advance the served SOA serial")
			}
		})
	}
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
