package utils

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSanitizeReportedIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: "", want: ""},
		{name: "whitespace", raw: "   ", want: ""},
		{name: "ipv4", raw: " 203.0.113.10 ", want: "203.0.113.10"},
		{name: "ipv6", raw: " 2001:db8::1 ", want: "2001:db8::1"},
		{name: "canonical ipv6", raw: "2001:0DB8::0001", want: "2001:db8::1"},
		{name: "mapped ipv4", raw: "::ffff:203.0.113.10", want: "203.0.113.10"},
		{name: "scoped ipv6", raw: "fe80::1%eth0", want: ""},
		{name: "invalid", raw: "not-an-ip", want: ""},
		{name: "host port", raw: "203.0.113.10:443", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := SanitizeReportedIP(tc.raw); got != tc.want {
				t.Fatalf("SanitizeReportedIP(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestResolvePublicIPs(t *testing.T) {
	unavailable4 := errors.New("ipv4 unavailable")
	unavailable6 := errors.New("ipv6 unavailable")
	for _, tc := range []struct {
		name string
		ipv4 string
		ipv6 string
		want []string
	}{
		{name: "dual stack", ipv4: "203.0.113.10", ipv6: "2001:0DB8::0010", want: []string{"203.0.113.10", "2001:db8::10"}},
		{name: "ipv4 only", ipv4: "203.0.113.10", want: []string{"203.0.113.10"}},
		{name: "ipv6 only", ipv6: "2001:db8::10", want: []string{"2001:db8::10"}},
		{name: "neither family"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := DefaultHTTPClient
			DefaultHTTPClient = &http.Client{Transport: publicIPTransport(func(req *http.Request) (*http.Response, error) {
				body, unavailable := tc.ipv4, unavailable4
				if slices.Contains(publicIPv6Endpoints, req.URL.String()) {
					body, unavailable = tc.ipv6, unavailable6
				}
				if body == "" {
					return nil, unavailable
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			t.Cleanup(func() { DefaultHTTPClient = original })

			got, err := ResolvePublicIPs(context.Background())
			if !slices.Equal(got, tc.want) {
				t.Fatalf("ResolvePublicIPs() = %v, want %v", got, tc.want)
			}
			if len(tc.want) == 0 {
				if !errors.Is(err, unavailable4) || !errors.Is(err, unavailable6) {
					t.Fatalf("ResolvePublicIPs() error = %v, want both family failures", err)
				}
			} else if err != nil {
				t.Fatalf("ResolvePublicIPs() error = %v", err)
			}
		})
	}
}

func TestResolvePublicIPsFamiliesProgressIndependently(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ipv6Started := make(chan struct{})
	original := DefaultHTTPClient
	DefaultHTTPClient = &http.Client{Transport: publicIPTransport(func(req *http.Request) (*http.Response, error) {
		body := "203.0.113.10"
		if slices.Contains(publicIPv6Endpoints, req.URL.String()) {
			close(ipv6Started)
			body = "2001:db8::10"
		} else {
			select {
			case <-ipv6Started:
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	t.Cleanup(func() { DefaultHTTPClient = original })

	got, err := ResolvePublicIPs(ctx)
	if err != nil || !slices.Equal(got, []string{"203.0.113.10", "2001:db8::10"}) {
		t.Fatalf("ResolvePublicIPs() = %v, %v, want both families", got, err)
	}
}

func TestResolvePublicIPsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ipv4Responded := make(chan struct{})
	original := DefaultHTTPClient
	DefaultHTTPClient = &http.Client{Transport: publicIPTransport(func(req *http.Request) (*http.Response, error) {
		if slices.Contains(publicIPv6Endpoints, req.URL.String()) {
			<-ipv4Responded
			cancel()
			return nil, req.Context().Err()
		}
		close(ipv4Responded)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("203.0.113.10"))}, nil
	})}
	t.Cleanup(func() { DefaultHTTPClient = original })

	got, err := ResolvePublicIPs(ctx)
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolvePublicIPs() = %v, %v, want cancellation without partial results", got, err)
	}
}

func TestResolvePublicIPResponseValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		family int
		want   string
	}{
		{name: "ipv6", body: " 2001:0DB8::0001\n", family: 6, want: "2001:db8::1"},
		{name: "mapped ipv4", body: "::ffff:203.0.113.10", family: 4, want: "203.0.113.10"},
		{name: "ipv4 on ipv6 service", body: "203.0.113.10", family: 6},
		{name: "ipv6 on ipv4 service", body: "2001:db8::1", family: 4},
		{name: "malformed", body: "not-an-ip", family: 6},
		{name: "scoped", body: "fe80::1%eth0", family: 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := DefaultHTTPClient
			DefaultHTTPClient = &http.Client{Transport: publicIPTransport(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: contextIPBody{ctx: req.Context(), Reader: strings.NewReader(tc.body)}}, nil
			})}
			t.Cleanup(func() { DefaultHTTPClient = original })

			got, err := resolvePublicIP(context.Background(), time.Second, time.Second, tc.family, "https://ip.example")
			if got != tc.want || (tc.want == "") != (err != nil) {
				t.Fatalf("resolvePublicIP() = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestResolvePublicIPBestEffortIPv6Fallback(t *testing.T) {
	original := DefaultHTTPClient
	DefaultHTTPClient = &http.Client{Transport: publicIPTransport(func(req *http.Request) (*http.Response, error) {
		if !slices.Contains(publicIPv6Endpoints, req.URL.String()) {
			return nil, errors.New("service unavailable")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("2001:db8::1"))}, nil
	})}
	t.Cleanup(func() { DefaultHTTPClient = original })

	if got := ResolvePublicIP(context.Background()); got != "2001:db8::1" {
		t.Fatalf("ResolvePublicIP() = %q, want IPv6 fallback", got)
	}
}

type publicIPTransport func(*http.Request) (*http.Response, error)

func (f publicIPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type contextIPBody struct {
	ctx context.Context
	*strings.Reader
}

func (b contextIPBody) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	return b.Reader.Read(p)
}

func (contextIPBody) Close() error { return nil }
