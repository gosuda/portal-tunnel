package embedded

import (
	"net"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
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
