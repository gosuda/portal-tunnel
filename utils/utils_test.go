package utils

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestNormalizeRelayURLs(t *testing.T) {
	t.Parallel()

	got, err := NormalizeRelayURLs(
		" localhost:4017 , https://relay.example.com/base/relay?x=1#frag ",
		"https://relay.example.com/base",
	)
	if err != nil {
		t.Fatalf("NormalizeRelayURLs() error = %v", err)
	}

	want := []string{
		"https://localhost:4017",
		"https://relay.example.com/base",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeRelayURLs() = %v, want %v", got, want)
	}
}

func TestNormalizeURLPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  string
	}{
		{input: "", want: "/"},
		{input: " ", want: "/"},
		{input: "api", want: "/api"},
		{input: "/api/", want: "/api"},
		{input: "/api/../v1//", want: "/v1"},
		{input: "/", want: "/"},
	}

	for _, tc := range cases {
		if got := NormalizeURLPath(tc.input); got != tc.want {
			t.Fatalf("NormalizeURLPath(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestFilterRelayURLs(t *testing.T) {
	t.Parallel()

	got := FilterRelayURLs(
		[]string{"https://relay-a.example", "https://relay-b.example"},
		[]string{"https://relay-b.example"},
	)

	want := []string{"https://relay-a.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterRelayURLs() = %v, want %v", got, want)
	}
}

func TestRemoveRelayURL(t *testing.T) {
	t.Parallel()

	got := RemoveRelayURL(
		[]string{"https://relay-a.example", "https://relay-b.example"},
		"https://relay-a.example",
	)

	want := []string{"https://relay-b.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RemoveRelayURL() = %v, want %v", got, want)
	}
}

func TestExcludeLocalRelayURLs(t *testing.T) {
	t.Parallel()

	got, err := ExcludeLocalRelayURLs(
		"https://localhost:4017",
		"https://127.0.0.1:4017",
		"https://relay.example.com/base",
		"https://demo.localhost",
	)
	if err != nil {
		t.Fatalf("ExcludeLocalRelayURLs() error = %v", err)
	}

	want := []string{"https://relay.example.com/base"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExcludeLocalRelayURLs() = %v, want %v", got, want)
	}
}

func TestParseCIDRs(t *testing.T) {
	t.Parallel()

	got, err := ParseCIDRs("10.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ParseCIDRs() len = %d, want %d", len(got), 2)
	}
}

func TestParseCIDRsRejectsInvalidValue(t *testing.T) {
	t.Parallel()

	if _, err := ParseCIDRs("not-a-cidr"); err == nil {
		t.Fatal("ParseCIDRs() error = nil, want invalid cidr error")
	}
}

func TestDomainCandidates(t *testing.T) {
	t.Parallel()

	got := DomainCandidates("portal.example.com")
	want := []string{"portal.example.com", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DomainCandidates() = %v, want %v", got, want)
	}
}

func TestNormalizeTargetAddr(t *testing.T) {
	t.Parallel()

	got, err := NormalizeTargetAddr("http://127.0.0.1")
	if err != nil {
		t.Fatalf("NormalizeTargetAddr() error = %v", err)
	}
	if got != "127.0.0.1:80" {
		t.Fatalf("NormalizeTargetAddr() = %q, want %q", got, "127.0.0.1:80")
	}
}

func TestValidateIPv4(t *testing.T) {
	t.Parallel()

	if err := ValidateIPv4("203.0.113.10"); err != nil {
		t.Fatalf("ValidateIPv4() error = %v", err)
	}
	if err := ValidateIPv4("not-an-ip"); err == nil {
		t.Fatal("ValidateIPv4() error = nil, want invalid ip error")
	}
}

func TestValidateIPv6(t *testing.T) {
	t.Parallel()

	if err := ValidateIPv6("2001:db8::10"); err != nil {
		t.Fatalf("ValidateIPv6() error = %v", err)
	}
	if err := ValidateIPv6("203.0.113.10"); err == nil {
		t.Fatal("ValidateIPv6() error = nil, want invalid ip error")
	}
}

func TestNormalizeDNSLabel(t *testing.T) {
	t.Parallel()

	got, err := NormalizeDNSLabel("Demo-App")
	if err != nil {
		t.Fatalf("NormalizeDNSLabel() error = %v", err)
	}
	if got != "demo-app" {
		t.Fatalf("NormalizeDNSLabel() = %q, want %q", got, "demo-app")
	}
}

func TestLeaseHostname(t *testing.T) {
	t.Parallel()

	got, err := LeaseHostname("Demo-App", "portal.example.com")
	if err != nil {
		t.Fatalf("LeaseHostname() error = %v", err)
	}
	if got != "demo-app.portal.example.com" {
		t.Fatalf("LeaseHostname() = %q, want %q", got, "demo-app.portal.example.com")
	}
}

func TestDecodeBase64URLString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		encoded string
		want    string
	}{
		{encoded: "bGVhc2UtMTIz", want: "lease-123"},
		{encoded: "bGVhc2UtMTIzZA==", want: "lease-123d"},
		{encoded: "bGVhc2UtMTIzZA", want: "lease-123d"},
	}

	for _, tc := range cases {
		encoded, want := tc.encoded, tc.want
		got, err := DecodeBase64URLString(encoded)
		if err != nil {
			t.Fatalf("DecodeBase64URLString(%q) error = %v", encoded, err)
		}
		if got != want {
			t.Fatalf("DecodeBase64URLString(%q) = %q, want %q", encoded, got, want)
		}
	}
}

func TestDecodeBase64URLStringRejectsInvalidValue(t *testing.T) {
	t.Parallel()

	if _, err := DecodeBase64URLString("%%%"); err == nil {
		t.Fatal("DecodeBase64URLString() error = nil, want invalid base64 error")
	}
}

func TestSleepOrDoneCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if SleepOrDone(ctx, time.Second) {
		t.Fatal("SleepOrDone() = true, want false for canceled context")
	}
}
