package e2e_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A relay hostname can advertise both families while only one is reachable.
// Exercise the complete UDP path through that hostname with each family absent.
func TestUDPRelayAddressFallback(t *testing.T) {
	const hostname = "fallback.localhost"
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for local DNS: %v", err)
	}
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn:        packet,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			for _, question := range request.Question {
				if !strings.EqualFold(question.Name, dns.Fqdn(hostname)) {
					response.Rcode = dns.RcodeNameError
					continue
				}
				header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 1}
				switch question.Qtype {
				case dns.TypeA:
					response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.IPv4(127, 0, 0, 1)})
				case dns.TypeAAAA:
					response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: net.IPv6loopback})
				}
			}
			_ = w.WriteMsg(response)
		}),
	}
	stopped := make(chan struct{})
	var serveErr error
	go func() {
		serveErr = server.ActivateAndServe()
		close(stopped)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.ShutdownContext(ctx)
		_ = packet.Close()
		select {
		case <-stopped:
			if serveErr != nil {
				t.Errorf("serve local DNS: %v", serveErr)
			}
		case <-ctx.Done():
			t.Error("local DNS server did not stop")
		}
	})
	select {
	case <-started:
	case <-stopped:
		t.Fatalf("start local DNS: %v", serveErr)
	}

	originalResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", packet.LocalAddr().String())
		},
	}
	// Subtest cleanup closes the exposure and joins its proxy before restoring
	// this process-wide resolver or stopping the DNS server.
	t.Cleanup(func() { net.DefaultResolver = originalResolver })

	for _, tc := range []struct {
		name string
		host string
	}{
		{name: "IPv4 relay", host: "127.0.0.1"},
		{name: "IPv6 relay", host: "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testUDPPortRelay(t, tc.host, hostname, tc.host)
		})
	}
}
