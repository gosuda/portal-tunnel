package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestManualEmbeddedCertificateServesDNSAndKeepsENSPending(t *testing.T) {
	originalClient := utils.DefaultHTTPClient
	t.Cleanup(func() { utils.DefaultHTTPClient = originalClient })

	for _, familyIP := range []string{"203.0.113.10", "2001:db8::10"} {
		for _, ensEnabled := range []bool{false, true} {
			for _, discoveryOutage := range []bool{false, true} {
				transport := publicIPTransport{ip: familyIP}
				publicIP := familyIP
				if discoveryOutage {
					transport.err = errors.New("public IP discovery is unavailable")
					publicIP = ""
				}
				baseCfg := Config{
					BaseDomain:        "portal.example.com",
					ENSGaslessEnabled: ensEnabled,
					ENSGaslessAddress: "0x1234567890123456789012345678901234567890",
				}
				t.Run(fmt.Sprintf("ip=%s/ens=%t/discovery_outage=%t", familyIP, ensEnabled, discoveryOutage), func(t *testing.T) {
					runManualEmbeddedDNSCase(t, baseCfg, transport, familyIP, publicIP)
				})
			}
		}
	}
}

type manualEmbeddedDNSCase struct {
	manager  *Manager
	cfg      Config
	keyDir   string
	familyIP string
	publicIP string
}

func runManualEmbeddedDNSCase(t *testing.T, baseCfg Config, transport publicIPTransport, familyIP, publicIP string) {
	t.Helper()
	utils.DefaultHTTPClient = &http.Client{Transport: transport}
	keyDir := t.TempDir()
	if err := writeManualRelayCertificate(t, keyDir, baseCfg.BaseDomain); err != nil {
		t.Fatal(err)
	}
	baseCfg.KeyDir = keyDir
	manager, cfg := newEmbeddedDNSManager(t, baseCfg)
	testCase := manualEmbeddedDNSCase{manager: manager, cfg: cfg, keyDir: keyDir, familyIP: familyIP, publicIP: publicIP}
	checkManualEmbeddedDNSInitial(t, testCase)
	checkManualEmbeddedDNSReload(t, testCase)
}

func checkManualEmbeddedDNSInitial(t *testing.T, testCase manualEmbeddedDNSCase) {
	t.Helper()
	if err := testCase.manager.EnsureTLSMaterial(context.Background()); err != nil {
		t.Fatalf("EnsureTLSMaterial(): %v", err)
	}
	if testCase.manager.TLSMaterial() == nil {
		t.Fatal("EnsureTLSMaterial() loaded no certificate")
	}
	assertManualEmbeddedDNS(t, testCase.manager, testCase.cfg, testCase.publicIP)
}

func checkManualEmbeddedDNSReload(t *testing.T, testCase manualEmbeddedDNSCase) {
	t.Helper()
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPTransport{ip: testCase.familyIP}}
	if err := testCase.manager.EnsureTLSMaterial(context.Background()); err != nil {
		t.Fatalf("reload manual certificate after discovery recovers: %v", err)
	}
	assertManualEmbeddedDNS(t, testCase.manager, testCase.cfg, testCase.familyIP)
	if _, err := os.Stat(filepath.Join(testCase.keyDir, types.DNSSECKeyFileName)); err != nil {
		t.Fatalf("persistent DNSSEC key: %v", err)
	}
}

func assertManualEmbeddedDNS(t *testing.T, manager *Manager, cfg Config, publicIP string) {
	t.Helper()

	status := manager.ENSStatus()
	if status.Enabled != cfg.ENSGaslessEnabled || status.Verified {
		t.Fatalf("ENSStatus() = %+v, local signing must not verify ENS", status)
	}
	dnssecSynced := status.DNSSECState == "pending" && status.DSRecord != "" && status.LastError == ""
	if cfg.ENSGaslessEnabled && !dnssecSynced {
		t.Fatalf("ENSStatus() = %+v, want pending DS publication with successful synchronization", status)
	}

	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(cfg.EmbeddedDNSPort))
	for _, network := range []string{"udp", "tcp"} {
		client := &dns.Client{Net: network, Timeout: time.Second}
		for _, name := range []string{cfg.BaseDomain, "ns." + cfg.BaseDomain, "tenant." + cfg.BaseDomain} {
			assertEmbeddedDNSAddress(t, client, addr, name, publicIP)
		}
		answer := queryManualEmbeddedDNSNetworkTXT(t, client, addr, cfg.BaseDomain, network)
		assertManualEmbeddedDNSNetworkTXT(t, cfg, network, answer)
	}
}

func queryManualEmbeddedDNSNetworkTXT(t *testing.T, client *dns.Client, addr, baseDomain, network string) *dns.Msg {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(baseDomain), dns.TypeTXT)
	answer, _, err := client.Exchange(query, addr)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Rcode != dns.RcodeSuccess || !answer.Authoritative {
		t.Fatalf("%s TXT = %v, want authoritative answer", network, answer)
	}
	return answer
}

func assertManualEmbeddedDNSNetworkTXT(t *testing.T, cfg Config, network string, answer *dns.Msg) {
	t.Helper()
	if !cfg.ENSGaslessEnabled {
		if len(answer.Answer) != 0 {
			t.Fatalf("%s TXT = %v, ENS must remain opt-in", network, answer)
		}
		return
	}
	if len(answer.Answer) != 1 {
		t.Fatalf("%s TXT = %v, want ENS publication despite pending verification", network, answer)
	}
	txt, ok := answer.Answer[0].(*dns.TXT)
	if !ok || !strings.HasPrefix(strings.Join(txt.Txt, ""), "ENS1 ") {
		t.Fatalf("%s TXT = %v, want ENS1 record", network, answer.Answer)
	}
}

func assertEmbeddedDNSAddress(t *testing.T, client *dns.Client, addr, name, publicIP string) {
	t.Helper()

	query := new(dns.Msg)
	recordType := uint16(dns.TypeA)
	if strings.Contains(publicIP, ":") {
		recordType = dns.TypeAAAA
	}
	query.SetQuestion(dns.Fqdn(name), recordType)
	answer, _, err := client.Exchange(query, addr)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Authoritative {
		t.Fatalf("%s address %s = %v, want authoritative answer", client.Net, name, answer)
	}
	if publicIP == "" {
		if len(answer.Answer) != 0 || (answer.Rcode != dns.RcodeSuccess && answer.Rcode != dns.RcodeRefused) {
			t.Fatalf("%s address %s = %v, want no address during discovery outage", client.Net, name, answer)
		}
		return
	}
	if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
		t.Fatalf("%s address %s = %v, want initialized manual-certificate address", client.Net, name, answer)
	}
	var gotIP net.IP
	switch record := answer.Answer[0].(type) {
	case *dns.A:
		gotIP = record.A
	case *dns.AAAA:
		gotIP = record.AAAA
	}
	if !gotIP.Equal(net.ParseIP(publicIP)) {
		t.Fatalf("%s address %s = %v, want relay public IP %s", client.Net, name, answer.Answer, publicIP)
	}
}
