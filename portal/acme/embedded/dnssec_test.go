package embedded

import (
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

type dnssecResponseWriter struct {
	dns.ResponseWriter
	wire []byte
}

func (*dnssecResponseWriter) LocalAddr() net.Addr { return &net.TCPAddr{} }

func (*dnssecResponseWriter) RemoteAddr() net.Addr { return &net.TCPAddr{} }

func (w *dnssecResponseWriter) WriteMsg(m *dns.Msg) error {
	var err error
	w.wire, err = m.Pack()
	return err
}

func queryDNSKEYSignature(t *testing.T, p *Provider, key *dns.DNSKEY) *dns.RRSIG {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(testZone), dns.TypeDNSKEY)
	query.SetEdns0(1232, true)
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

func checkIdleSignatureRefresh(t *testing.T, p *Provider, key *dns.DNSKEY) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		original := queryDNSKEYSignature(t, p, key)
		<-time.After(12 * time.Hour)
		refreshed := queryDNSKEYSignature(t, p, key)
		if refreshed.Expiration <= original.Expiration {
			t.Fatal("idle zone did not renew signatures at the 12-hour boundary")
		}
		<-time.After(13 * time.Hour)
		if original.ValidityPeriod(time.Now()) {
			t.Fatal("test did not advance beyond the original signature lifetime")
		}
		if renewed := queryDNSKEYSignature(t, p, key); renewed.Expiration <= refreshed.Expiration {
			t.Fatal("idle zone did not renew signatures beyond the original lifetime")
		}
	})
}

func createMutatedTXTRecord(t *testing.T, p *Provider, key *dns.DNSKEY, network string) uint32 {
	t.Helper()
	name := "new." + testZone
	before := dnssecExchange(t, p, network, testZone, dns.TypeSOA, 1232)
	verifySection(t, key, before.Answer)
	beforeSerial := before.Answer[0].(*dns.SOA).Serial
	absent := dnssecExchange(t, p, network, name, dns.TypeTXT, 1232)
	requireRcode(t, absent, dns.RcodeSuccess)
	if len(absent.Answer) != 0 {
		t.Fatalf("absent TXT returned data: %v", absent.Answer)
	}
	verifySection(t, key, absent.Ns)
	requireNSEC(t, absent, "*."+testZone, "ns."+testZone)
	if err := p.EnsureTXTRecord(t.Context(), name, "value"); err != nil {
		t.Fatal(err)
	}
	created := dnssecExchange(t, p, network, name, dns.TypeTXT, 1232)
	requireRcode(t, created, dns.RcodeSuccess)
	if len(created.Answer) != 2 {
		t.Fatalf("new RRset not signed: %v", created)
	}
	if txt, ok := created.Answer[0].(*dns.TXT); !ok || strings.Join(txt.Txt, "") != "value" {
		t.Fatalf("new TXT value missing: %v", created.Answer)
	}
	verifySection(t, key, created.Answer)
	served := dnssecExchange(t, p, network, testZone, dns.TypeSOA, 1232)
	verifySection(t, key, served.Answer)
	createdSerial := served.Answer[0].(*dns.SOA).Serial
	if createdSerial <= beforeSerial {
		t.Fatal("TXT creation did not advance the served SOA serial")
	}
	nodata := dnssecExchange(t, p, network, name, dns.TypeAAAA, 1232)
	requireRcode(t, nodata, dns.RcodeSuccess)
	verifySection(t, key, nodata.Ns)
	requireNSEC(t, nodata, name, "*."+name)
	for _, nsec := range denialRecords(nodata) {
		if nsec.Hdr.Name == dns.Fqdn(name) && (!slices.Contains(nsec.TypeBitMap, dns.TypeTXT) || slices.Contains(nsec.TypeBitMap, dns.TypeAAAA)) {
			t.Fatalf("incorrect new owner type bitmap: %v", nsec)
		}
	}
	return createdSerial
}

func deleteMutatedTXTRecord(t *testing.T, p *Provider, key *dns.DNSKEY, network string, createdSerial uint32) {
	t.Helper()
	name := "new." + testZone
	if err := p.DeleteTXTRecords(t.Context(), name, "value"); err != nil {
		t.Fatal(err)
	}
	response := dnssecExchange(t, p, network, name, dns.TypeTXT, 1232)
	requireRcode(t, response, dns.RcodeSuccess)
	if len(response.Answer) != 0 {
		t.Fatalf("deleted TXT is still served: %v", response.Answer)
	}
	verifySection(t, key, response.Ns)
	requireNSEC(t, response, "*."+testZone, "ns."+testZone)
	deletedSerial := response.Ns[0].(*dns.SOA).Serial
	if deletedSerial <= createdSerial {
		t.Fatal("TXT deletion did not advance the served SOA serial")
	}
}

func runMutationNetworkCase(t *testing.T, p *Provider, key *dns.DNSKEY, network string) {
	t.Helper()
	t.Run(network, func(t *testing.T) {
		createdSerial := createMutatedTXTRecord(t, p, key, network)
		deleteMutatedTXTRecord(t, p, key, network, createdSerial)
	})
}

func TestDNSSECRefreshAndMutation(t *testing.T) {
	p := newTestProvider(t, nil)
	if err := p.EnsureAddressRecords(t.Context(), testZone, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	keys := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := keys.Answer[0].(*dns.DNSKEY)
	checkIdleSignatureRefresh(t, p, key)
	for _, network := range []string{"tcp", "udp"} {
		runMutationNetworkCase(t, p, key, network)
	}
}

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

func verifySectionCollectDNSSEC(records []dns.RR) (map[string][]dns.RR, map[string]*dns.RRSIG) {
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
	return sets, signatures
}

func verifySectionSingleDNSSEC(t *testing.T, key *dns.DNSKEY, id string, set []dns.RR, sig *dns.RRSIG) {
	t.Helper()
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

func verifySection(t *testing.T, key *dns.DNSKEY, records []dns.RR) {
	t.Helper()
	sets, signatures := verifySectionCollectDNSSEC(records)
	for id, set := range sets {
		verifySectionSingleDNSSEC(t, key, id, set, signatures[id])
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

func seedSignedWildcardZone(t *testing.T, p *Provider) *dns.DNSKEY {
	t.Helper()
	ctx := t.Context()
	if err := p.EnsureAddressRecords(ctx, testZone, "203.0.113.10"); err != nil {
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
	return key
}

func checkSignedWildcardAnswer(t *testing.T, p *Provider, key *dns.DNSKEY, network, name string) {
	t.Helper()
	response := dnssecExchange(t, p, network, name, dns.TypeA, 1232)
	requireRcode(t, response, dns.RcodeSuccess)
	if len(response.Answer) != 2 {
		t.Fatalf("expected A and RRSIG: %v", response.Answer)
	}
	verifySection(t, key, response.Answer)
	verifySection(t, key, response.Ns)
	if strings.HasPrefix(name, "deep.") {
		requireNSEC(t, response, "*.branch."+testZone, "leaf.branch."+testZone)
	}
}

func checkSignedWildcardAnswers(t *testing.T, p *Provider, key *dns.DNSKEY) {
	t.Helper()
	for _, network := range []string{"tcp", "udp"} {
		for _, name := range []string{testZone, "leaf.branch." + testZone, "deep.child.branch." + testZone, strings.ToUpper("unknown." + testZone)} {
			checkSignedWildcardAnswer(t, p, key, network, name)
		}
	}
}

func checkWildcardNodataProof(t *testing.T, p *Provider, key *dns.DNSKEY, name string) {
	t.Helper()
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

func checkWildcardNodataProofs(t *testing.T, p *Provider, key *dns.DNSKEY) {
	t.Helper()
	for _, name := range []string{"leaf.branch." + testZone, "child.branch." + testZone} {
		checkWildcardNodataProof(t, p, key, name)
	}
}

func checkUnsignedQueryResponse(t *testing.T, p *Provider) {
	t.Helper()
	unsigned := exchange(t, p, "tcp", dns.TypeA, "unknown."+testZone)
	if len(unsigned.Answer) != 1 || len(unsigned.Ns) != 0 {
		t.Fatalf("DO absent leaked DNSSEC records: %v", unsigned)
	}
	if dnskeyWithoutDO := exchange(t, p, "tcp", dns.TypeDNSKEY, testZone); len(dnskeyWithoutDO.Answer) != 1 {
		t.Fatalf("DNSKEY query without DO: %v", dnskeyWithoutDO)
	}
	if rrsigWithoutDO := exchange(t, p, "tcp", dns.TypeRRSIG, testZone); len(rrsigWithoutDO.Answer) == 0 {
		t.Fatal("RRSIG query without DO is empty")
	}
}

func TestDNSSECSigningAndWildcardDenial(t *testing.T) {
	p := newTestProvider(t, nil)
	key := seedSignedWildcardZone(t, p)
	checkSignedWildcardAnswers(t, p, key)
	checkWildcardNodataProofs(t, p, key)
	checkUnsignedQueryResponse(t, p)
}

func seedAddressFamilyZone(t *testing.T, p *Provider, addresses []string) {
	t.Helper()
	ctx := t.Context()
	for _, address := range addresses {
		if err := p.EnsureAddressRecords(ctx, testZone, address); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.EnsureTXTRecord(ctx, "leaf.branch."+testZone, "ENS1 example"); err != nil {
		t.Fatal(err)
	}
}

func checkAddressFamilyNetwork(t *testing.T, p *Provider, key *dns.DNSKEY, network string, addrCount int) {
	t.Helper()
	for _, hostname := range []string{testZone, "leaf.branch." + testZone, "deep.child.branch." + testZone} {
		for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
			requireDNSSECAddressAnswer(t, p, key, network, hostname, typ, typ == dns.TypeAAAA || addrCount > 1)
		}
	}
	requireDNSSECAddressGlue(t, p, key, network, addrCount > 1)
	missing := dnssecExchange(t, p, network, "absent.*."+testZone, dns.TypeAAAA, 1232)
	requireRcode(t, missing, dns.RcodeNameError)
	verifySection(t, key, missing.Ns)
}

func runAddressFamilyCase(t *testing.T, addresses []string) {
	t.Helper()
	p := newTestProvider(t, nil)
	seedAddressFamilyZone(t, p, addresses)
	keys := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := keys.Answer[0].(*dns.DNSKEY)
	for _, network := range []string{"tcp", "udp"} {
		checkAddressFamilyNetwork(t, p, key, network, len(addresses))
	}
}

func TestDNSSECAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []string
		dualStack bool
	}{
		{name: "ipv6-only", addresses: []string{"2001:db8::10"}},
		{name: "dual-stack", addresses: []string{"2001:db8::10", "203.0.113.10"}, dualStack: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runAddressFamilyCase(t, tc.addresses)
		})
	}
}

func requireDNSSECAddressAnswer(t *testing.T, p *Provider, key *dns.DNSKEY, network, hostname string, typ uint16, present bool) {
	t.Helper()
	response := dnssecExchange(t, p, network, hostname, typ, 1232)
	requireRcode(t, response, dns.RcodeSuccess)
	verifySection(t, key, response.Answer)
	verifySection(t, key, response.Ns)
	if present {
		if len(response.Answer) != 2 || response.Answer[0].Header().Rrtype != typ {
			t.Fatalf("expected %s and RRSIG: %v", dns.TypeToString[typ], response.Answer)
		}
		return
	}
	if len(response.Answer) != 0 {
		t.Fatalf("IPv6-only zone returned A records: %v", response.Answer)
	}
	owner := dns.Fqdn(hostname)
	if strings.HasPrefix(hostname, "deep.") {
		owner = "*.branch." + dns.Fqdn(testZone)
	}
	for _, nsec := range denialRecords(response) {
		if nsec.Hdr.Name != owner {
			continue
		}
		if slices.Contains(nsec.TypeBitMap, dns.TypeA) || !slices.Contains(nsec.TypeBitMap, dns.TypeAAAA) {
			t.Fatalf("incorrect IPv6-only type bitmap: %v", nsec)
		}
		return
	}
	t.Fatalf("missing A NODATA proof for %s", hostname)
}

func requireDNSSECAddressGlue(t *testing.T, p *Provider, key *dns.DNSKEY, network string, dualStack bool) {
	t.Helper()
	glue := dnssecExchange(t, p, network, testZone, dns.TypeNS, 1232)
	requireRcode(t, glue, dns.RcodeSuccess)
	verifySection(t, key, glue.Answer)
	verifySection(t, key, glue.Extra)
	var gotA, gotAAAA bool
	for _, rr := range glue.Extra {
		switch record := rr.(type) {
		case *dns.A:
			gotA = record.Hdr.Name == dns.Fqdn("ns."+testZone) && record.A.Equal(net.ParseIP("203.0.113.10"))
		case *dns.AAAA:
			gotAAAA = record.Hdr.Name == dns.Fqdn("ns."+testZone) && record.AAAA.Equal(net.ParseIP("2001:db8::10"))
		}
	}
	if gotA != dualStack || !gotAAAA {
		t.Fatalf("incorrect address glue: %v", glue.Extra)
	}
}

func checkRefusedUnknownName(t *testing.T, p *Provider) {
	t.Helper()
	for _, name := range []string{"absent." + testZone, "deep.absent.branch." + testZone} {
		response := dnssecExchange(t, p, "tcp", name, dns.TypeA, 1232)
		requireRcode(t, response, dns.RcodeRefused)
		if len(response.Ns) != 0 {
			t.Fatalf("%s: REFUSED carried %d authority records, want none", name, len(response.Ns))
		}
	}
}

func checkEmptyNonterminalNodata(t *testing.T, p *Provider) {
	t.Helper()
	response := dnssecExchange(t, p, "tcp", "branch."+testZone, dns.TypeTXT, 1232)
	requireRcode(t, response, dns.RcodeSuccess)
	verifySection(t, p.key, response.Ns)
	if len(response.Answer) != 0 {
		t.Fatal("empty nonterminal returned data")
	}
}

func checkProvenNameErrorDenial(t *testing.T, p *Provider) {
	t.Helper()
	if err := p.EnsureAddressRecords(t.Context(), testZone, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"absent." + testZone, "deep.absent.branch." + testZone} {
		proven := dnssecExchange(t, p, "tcp", name, dns.TypeA, 1232)
		requireRcode(t, proven, dns.RcodeSuccess)
		verifySection(t, p.key, proven.Answer)
	}
	wildcard := dnssecExchange(t, p, "tcp", "absent.*."+testZone, dns.TypeA, 1232)
	requireRcode(t, wildcard, dns.RcodeNameError)
	verifySection(t, p.key, wildcard.Ns)
}

func TestDNSSECNameErrorAndEmptyNonterminal(t *testing.T) {
	p := newTestProvider(t, nil)
	if err := p.EnsureTXTRecord(t.Context(), "leaf.branch."+testZone, "value"); err != nil {
		t.Fatal(err)
	}
	checkRefusedUnknownName(t, p)
	checkEmptyNonterminalNodata(t, p)
	checkProvenNameErrorDenial(t, p)
}

func seedCanonicalDenialNames(t *testing.T, p *Provider) {
	t.Helper()
	if err := p.EnsureAddressRecords(t.Context(), testZone, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"a.", "z.a.", "aa.", "b."} {
		if err := p.EnsureTXTRecord(t.Context(), owner+testZone, "value"); err != nil {
			t.Fatal(err)
		}
	}
}

func checkCanonicalDenialProofs(t *testing.T, p *Provider, key *dns.DNSKEY, network string) {
	t.Helper()
	for _, tc := range []struct {
		name   string
		proofs [][2]string
	}{
		{name: `\096.`, proofs: [][2]string{{"*.", "a."}}},
		{name: "m.a.", proofs: [][2]string{{"*.a.", "z.a."}}},
		{name: "a0.", proofs: [][2]string{{"*.z.a.", "aa."}, {"*.", "a."}}},
		{name: `\0970.`, proofs: [][2]string{{"*.z.a.", "aa."}, {"*.", "a."}}},
		{name: "az.", proofs: [][2]string{{"*.aa.", "b."}, {"*.", "a."}}},
		{name: "B0.", proofs: [][2]string{{"*.b.", "ns."}, {"*.", "a."}}},
	} {
		t.Run(network+"/"+tc.name, func(t *testing.T) {
			response := dnssecExchange(t, p, network, tc.name+testZone, dns.TypeTXT, 1232)
			requireRcode(t, response, dns.RcodeSuccess)
			if len(response.Answer) != 0 {
				t.Fatalf("missing name returned data: %v", response.Answer)
			}
			verifySection(t, key, response.Ns)
			for _, proof := range tc.proofs {
				requireNSEC(t, response, proof[0]+testZone, proof[1]+testZone)
			}
		})
	}
}

func TestDNSSECCanonicalDenialIntervals(t *testing.T) {
	p := newTestProvider(t, nil)
	seedCanonicalDenialNames(t, p)
	keys := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := keys.Answer[0].(*dns.DNSKEY)
	for _, network := range []string{"tcp", "udp"} {
		checkCanonicalDenialProofs(t, p, key, network)
	}
}

func createPersistedSigningKey(t *testing.T, cfg Config) (*Provider, string, *dns.DNSKEY) {
	t.Helper()
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	keys := dnssecExchange(t, first, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := keys.Answer[0].(*dns.DNSKEY)
	_, ds, message, err := first.EnsureDNSSEC(t.Context(), testZone)
	if err != nil || ds != key.ToDS(dns.SHA256).String() || !strings.Contains(message, "parent") {
		t.Fatalf("invalid DS export: %q %q %v", ds, message, err)
	}
	return first, ds, key
}

func checkNewKeyFileMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("new private key mode = %04o, want 0600", info.Mode().Perm())
	}
}

func checkKeptKeyFileMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("operator-managed private key mode changed: %04o", info.Mode().Perm())
	}
}

func checkReloadedSigningKey(t *testing.T, cfg Config, wantDS string, wantKey *dns.DNSKEY) {
	t.Helper()
	second, err := New(cfg)
	if err != nil {
		t.Fatalf("reload operator-managed key: %v", err)
	}
	_, nextDS, _, err := second.EnsureDNSSEC(t.Context(), testZone)
	if err != nil || nextDS != wantDS {
		t.Fatalf("DS changed across restart: %q => %q (%v)", wantDS, nextDS, err)
	}
	response := dnssecExchange(t, second, "tcp", testZone, dns.TypeDNSKEY, 1232)
	verifySection(t, wantKey, response.Answer)
	if err := second.Stop(); err != nil {
		t.Fatal(err)
	}
}

func checkWrongZoneKeyRefused(t *testing.T, cfg Config) {
	t.Helper()
	cfg.BaseDomain = "different.example.com"
	if wrong, err := New(cfg); err == nil {
		_ = wrong.Stop()
		t.Fatal("accepted another zone's key")
	}
}

func TestDNSSECKeyPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), types.DNSSECKeyFileName)
	cfg := Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path}
	first, ds, key := createPersistedSigningKey(t, cfg)
	if err := first.Stop(); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		checkNewKeyFileMode(t, path)
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	checkReloadedSigningKey(t, cfg, ds, key)
	if runtime.GOOS != "windows" {
		checkKeptKeyFileMode(t, path)
	}
	checkWrongZoneKeyRefused(t, cfg)
}

func TestDNSSECCorruptKeyRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), types.DNSSECKeyFileName)
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path}
	if p, err := New(cfg); err == nil {
		_ = p.Stop()
		t.Fatal("accepted a corrupt DNSSEC key")
	}
}

func TestDNSSECUDPTruncationAndTCPRetry(t *testing.T) {
	p := newTestProvider(t, nil)
	for i := range 8 {
		if err := p.EnsureTXTRecord(t.Context(), testZone, strings.Repeat(string(rune('a'+i)), 200)); err != nil {
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
