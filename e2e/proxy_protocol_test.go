package e2e_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func proxyV2Header(source netip.AddrPort) []byte {
	ip := source.Addr().AsSlice()
	header := make([]byte, 16+2*len(ip)+4)
	copy(header, "\r\n\r\n\x00\r\nQUIT\n")
	header[12], header[13] = 0x21, 0x11
	if len(ip) == 16 {
		header[13] = 0x21
	}
	binary.BigEndian.PutUint16(header[14:], uint16(len(header)-16))
	copy(header[16:], ip)
	copy(header[16+len(ip):], ip)
	binary.BigEndian.PutUint16(header[16+2*len(ip):], source.Port())
	binary.BigEndian.PutUint16(header[18+2*len(ip):], 443)
	return header
}

// A real TCP proxy forwards bytes without terminating either API or tenant TLS.
// The header source is the accepted socket peer, never an HTTP header.
func startProxyV2Ingress(t *testing.T, parent context.Context, addr, backend string) {
	t.Helper()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(parent)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer client.Close()
				stopClient := context.AfterFunc(ctx, func() { _ = client.Close() })
				defer stopClient()
				upstream, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}).DialContext(ctx, "tcp", backend)
				if err != nil {
					return
				}
				defer upstream.Close()
				stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
				defer stopUpstream()
				peer, err := netip.ParseAddrPort(client.RemoteAddr().String())
				if err != nil {
					return
				}
				if _, err := upstream.Write(proxyV2Header(peer)); err != nil {
					return
				}
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, client)
					_ = upstream.Close()
					close(done)
				}()
				_, _ = io.Copy(client, upstream)
				_ = client.Close()
				_ = upstream.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		workers.Wait()
	})
}

func TestProxyV2PreAuthAdmission(t *testing.T) {
	for _, globalBurst := range []int{200, 18} {
		t.Run("global-burst="+strconv.Itoa(globalBurst), func(t *testing.T) {
			backend := net.JoinHostPort("127.0.0.1", strconv.Itoa(harnessPort(t, "127.0.0.1")))
			front := net.JoinHostPort("127.0.0.1", strconv.Itoa(harnessPort(t, "127.0.0.1")))
			server, err := portal.NewServer(portal.ServerConfig{
				PortalURL: "https://localhost", StateDir: t.TempDir(), SNIListenAddr: backend,
				ProxyProtocolTrustedIPs: []string{"127.0.0.1"},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			config := policy.DefaultPreAuthConfig()
			config.GlobalBurst = globalBurst
			// Slow refills keep assertions independent of execution speed. The
			// default 20-unit source burst and 1/5 endpoint costs are unchanged.
			limiter := policy.NewSourceLimiter(1, config.SourceBurst, 1, globalBurst)
			if err := server.Start(ctx, policy.Mux(server, nil, nil, limiter, nil, config)); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { stopRelay(t, server) })
			startProxyV2Ingress(t, ctx, front, backend)
			base, err := url.Parse("https://" + front)
			if err != nil {
				t.Fatal(err)
			}
			clients := make([]*http.Client, 3)
			identities := make([]types.Identity, len(clients))
			for i := range clients {
				identities[i], err = identity.Generate("proxy-" + strconv.Itoa(i))
				if err != nil {
					t.Fatal(err)
				}
				dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0." + strconv.Itoa(i+2))}}
				transport := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
				clients[i] = &http.Client{Transport: transport, Timeout: 5 * time.Second}
				t.Cleanup(transport.CloseIdleConnections)
			}
			register := func(client *http.Client, id types.Identity) error {
				// Spoofed HTTP headers must not override the PROXY source.
				headers := http.Header{"X-Forwarded-For": {"198.51.100.99"}, "X-Real-IP": {"198.51.100.99"}}
				var challenge types.RegisterChallengeResponse
				if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: id}, headers, &challenge); err != nil {
					return err
				}
				signature, err := identity.NewLocalAuthority(id).SignEthereumPersonalMessage(challenge.SIWEMessage)
				if err != nil {
					return err
				}
				var response types.RegisterResponse
				return utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: signature}, headers, &response)
			}
			// Concurrent startup, followed by re-registration of each source.
			for range 3 {
				results := make(chan error, len(clients))
				for i, client := range clients {
					go func() { results <- register(client, identities[i]) }()
				}
				for range clients {
					if err := <-results; err != nil {
						t.Fatal(err)
					}
				}
				if globalBurst == 18 {
					break
				}
			}
			seen := make(map[string]bool)
			leases := server.PolicyLeases()
			if len(leases) != len(clients) {
				t.Fatalf("leases after re-registration = %d, want %d", len(leases), len(clients))
			}
			for _, lease := range leases {
				seen[lease.ClientIP] = true
			}
			if len(seen) != 3 || !seen["127.0.0.2"] || !seen["127.0.0.3"] || !seen["127.0.0.4"] {
				t.Fatalf("registration sources = %v", seen)
			}
			request := func(client *http.Client, path string, want int) {
				t.Helper()
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+path, strings.NewReader("{}"))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != want {
					t.Fatalf("%s: status = %d, want %d", path, resp.StatusCode, want)
				}
				if want == http.StatusTooManyRequests {
					if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil || seconds <= 0 {
						t.Fatalf("invalid Retry-After: %q", resp.Header.Get("Retry-After"))
					}
				}
			}
			if globalBurst == 200 {
				// 3 * (challenge 1 + register 5) leaves 2 source units.
				request(clients[0], types.PathSDKRegister, http.StatusTooManyRequests)
				request(clients[0], types.PathSDKRegisterChallenge, http.StatusBadRequest)
				request(clients[0], types.PathSDKRegisterChallenge, http.StatusBadRequest)
				request(clients[0], types.PathSDKRegisterChallenge, http.StatusTooManyRequests)
				request(clients[1], types.PathSDKRegisterChallenge, http.StatusBadRequest)
			} else {
				// Every source still has 14 units; the shared global budget is empty.
				for _, client := range clients {
					request(client, types.PathSDKRegisterChallenge, http.StatusTooManyRequests)
				}
			}
		})
	}
}

func TestProxyV2TenantTLS(t *testing.T) {
	h := newHarnessWithName(t, "proxy-tenant", "127.0.0.1", "proxy-v2", sdk.WithMITMProtection(true))
	if got := h.get(h.waitForPublicURL()); got != marker {
		t.Fatalf("tenant response = %q, want %q", got, marker)
	}
}

func TestProxyV2IngressBoundary(t *testing.T) {
	ipv4 := proxyV2Header(netip.MustParseAddrPort("198.51.100.10:1234"))
	ipv6 := proxyV2Header(netip.MustParseAddrPort("[2001:db8::10]:1234"))
	withTLV := append(proxyV2Header(netip.MustParseAddrPort("198.51.100.10:1234")), 0xee, 0, 1, 42)
	binary.BigEndian.PutUint16(withTLV[14:], uint16(len(withTLV)-16))
	badTLV := append([]byte(nil), withTLV...)
	badTLV[len(badTLV)-2] = 2
	local := append([]byte(nil), ipv4...)
	local[12] = 0x20
	for _, mode := range []string{"enabled", "untrusted", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(harnessPort(t, "127.0.0.1")))
			cfg := portal.ServerConfig{PortalURL: "https://localhost", StateDir: t.TempDir(), SNIListenAddr: addr}
			if mode == "enabled" {
				cfg.ProxyProtocolTrustedIPs = []string{"127.0.0.1"}
			} else if mode == "untrusted" {
				cfg.ProxyProtocolTrustedIPs = []string{"127.0.0.2"}
			}
			server, err := portal.NewServer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.Start(t.Context(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, r.RemoteAddr)
			})); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { stopRelay(t, server) })
			type ingressCase struct {
				name       string
				header     []byte
				wantSource string
			}
			cases := []ingressCase{
				{"plain TLS", nil, "127.0.0.1"},
				{"TCP4", ipv4, "198.51.100.10"},
				{"TCP6", ipv6, "2001:db8::10"},
				{"unknown TLV ignored", withTLV, "198.51.100.10"},
				{"TLV length overflow", badTLV, ""},
				{"LOCAL ignores asserted source", local, "127.0.0.1"},
				{"v1", []byte("PROXY TCP4 198.51.100.10 127.0.0.1 1234 443\r\n"), ""},
				{"nested header", append(append([]byte(nil), ipv4...), ipv6...), ""},
				{"truncated", ipv4[:20], ""},
				{"unspecified source", proxyV2Header(netip.MustParseAddrPort("0.0.0.0:1234")), ""},
				{"multicast source", proxyV2Header(netip.MustParseAddrPort("224.0.0.1:1234")), ""},
			}
			for _, mutation := range []struct {
				name  string
				index int
				value byte
			}{
				{"bad signature", 0, 0}, {"wrong version", 12, 0x31}, {"unknown command", 12, 0x22},
				{"UDP", 13, 0x12}, {"UNSPEC", 13, 0}, {"short address", 15, 11},
				{"TLV exceeds payload", 15, 13},
			} {
				header := append([]byte(nil), ipv4...)
				header[mutation.index] = mutation.value
				cases = append(cases, ingressCase{mutation.name, header, ""})
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					want := tc.wantSource
					if mode == "untrusted" || (mode == "disabled" && tc.header != nil) || (mode == "enabled" && tc.header == nil) {
						want = ""
					}
					transport := &http.Transport{
						DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
						DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
							conn, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}).DialContext(ctx, network, target)
							if err != nil {
								return nil, err
							}
							if len(tc.header) > 0 {
								if _, err := conn.Write(tc.header); err != nil {
									_ = conn.Close()
									return nil, err
								}
							}
							return conn, nil
						},
					}
					defer transport.CloseIdleConnections()
					client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
					resp, err := client.Get("https://" + addr + "/source")
					if err != nil {
						if want != "" {
							t.Fatal(err)
						}
						return
					}
					defer resp.Body.Close()
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Fatal(err)
					}
					source, _, err := net.SplitHostPort(string(body))
					if want == "" || err != nil || source != want {
						t.Fatalf("source = %q (error %v), want %q; empty means TLS must fail", body, err, want)
					}
				})
			}
		})
	}
}
