package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestNormalizePublicIPs(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		entries []string
		want    []string
	}{
		{entries: nil, want: nil},
		{entries: []string{" ", ""}, want: nil},
		{entries: []string{"203.0.113.10"}, want: []string{"203.0.113.10"}},
		{entries: []string{"2001:db8::10", " 203.0.113.10 "}, want: []string{"203.0.113.10", "2001:db8::10"}},
		{entries: []string{"::ffff:203.0.113.10"}, want: []string{"203.0.113.10"}},
		{entries: []string{"2001:DB8:0::10"}, want: []string{"2001:db8::10"}},
		{entries: []string{"10.0.0.1", "fd00::1"}, want: []string{"10.0.0.1", "fd00::1"}},
	} {
		got, err := NormalizePublicIPs(tc.entries)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("NormalizePublicIPs(%q) = %q, %v; want %q", tc.entries, got, err, tc.want)
		}
	}

	for _, tc := range []struct {
		entries []string
		want    error
	}{
		{entries: []string{"portal.example.com"}, want: errPublicIPNotAddress},
		{entries: []string{"203.0.113.0/24"}, want: errPublicIPNotAddress},
		{entries: []string{"203.0.113.10:443"}, want: errPublicIPNotAddress},
		{entries: []string{"[2001:db8::10]"}, want: errPublicIPNotAddress},
		{entries: []string{"fe80::1%eth0"}, want: errPublicIPNotAddress},
		{entries: []string{"0.0.0.0"}, want: errPublicIPUnreachable},
		{entries: []string{"::"}, want: errPublicIPUnreachable},
		{entries: []string{"127.0.0.1"}, want: errPublicIPUnreachable},
		{entries: []string{"::1"}, want: errPublicIPUnreachable},
		{entries: []string{"169.254.1.1"}, want: errPublicIPUnreachable},
		{entries: []string{"fe80::1"}, want: errPublicIPUnreachable},
		{entries: []string{"224.0.0.1"}, want: errPublicIPUnreachable},
		{entries: []string{"ff02::1"}, want: errPublicIPUnreachable},
		{entries: []string{"203.0.113.10", "198.51.100.10"}, want: errPublicIPSecondFamily},
		{entries: []string{"2001:db8::10", "2001:db8::11"}, want: errPublicIPSecondFamily},
		{entries: []string{"203.0.113.10", "::ffff:203.0.113.10"}, want: errPublicIPSecondFamily},
	} {
		got, err := NormalizePublicIPs(tc.entries)
		entry := fmt.Sprintf("%q", tc.entries[len(tc.entries)-1])
		if !errors.Is(err, tc.want) || got != nil || !strings.HasPrefix(err.Error(), "PUBLIC_IPS: "+entry) {
			t.Errorf("NormalizePublicIPs(%q) = %q, %v; want an error naming PUBLIC_IPS and %s: %v", tc.entries, got, err, entry, tc.want)
		}
	}
}

type forbiddenDiscoveryTransport struct {
	t *testing.T
}

func (transport forbiddenDiscoveryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.t.Errorf("public IP discovery requested %s although PUBLIC_IPS is set", request.URL)
	return nil, errors.New("public IP discovery must not run when PUBLIC_IPS is set")
}

func TestPublicIPsReplaceDiscovery(t *testing.T) {
	originalClient := utils.DefaultHTTPClient
	t.Cleanup(func() { utils.DefaultHTTPClient = originalClient })

	for _, publicIPs := range [][]string{{"203.0.113.10"}, {"2001:db8::10"}, {"2001:db8::10", "203.0.113.10"}} {
		t.Run(strings.Join(publicIPs, ","), func(t *testing.T) {
			utils.DefaultHTTPClient = &http.Client{Transport: forbiddenDiscoveryTransport{t: t}}
			keyDir := t.TempDir()
			if err := writeManualRelayCertificate(t, keyDir, "portal.example.com"); err != nil {
				t.Fatal(err)
			}
			manager, cfg := newEmbeddedDNSManager(t, Config{
				BaseDomain: "portal.example.com",
				KeyDir:     keyDir,
				PublicIPs:  publicIPs,
			})
			if err := manager.EnsureTLSMaterial(context.Background()); err != nil {
				t.Fatalf("EnsureTLSMaterial(): %v", err)
			}
			if err := manager.applyENSCommand(context.Background(), ensDNSCommand{hostname: "app." + cfg.BaseDomain}); err != nil {
				t.Fatalf("applyENSCommand(): %v", err)
			}

			want := make(map[uint16]string)
			for _, publicIP := range publicIPs {
				if strings.Contains(publicIP, ":") {
					want[dns.TypeAAAA] = publicIP
				} else {
					want[dns.TypeA] = publicIP
				}
			}
			addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(cfg.EmbeddedDNSPort))
			client := &dns.Client{Net: "udp", Timeout: time.Second}
			for _, name := range []string{cfg.BaseDomain, "tenant." + cfg.BaseDomain, "app." + cfg.BaseDomain} {
				for _, recordType := range []uint16{dns.TypeA, dns.TypeAAAA} {
					assertEmbeddedDNSFamily(t, client, addr, name, recordType, want[recordType])
				}
			}
		})
	}
}

func assertEmbeddedDNSFamily(t *testing.T, client *dns.Client, addr, name string, recordType uint16, publicIP string) {
	t.Helper()
	if publicIP != "" {
		assertEmbeddedDNSAddress(t, client, addr, name, publicIP)
		return
	}
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), recordType)
	answer, _, err := client.Exchange(query, addr)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 0 {
		t.Fatalf("%s %s = %v, want no record for a family PUBLIC_IPS leaves out", dns.TypeToString[recordType], name, answer)
	}
}
