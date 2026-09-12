package sdk

import (
	"context"
	"strings"
	"testing"
)

func TestProxyWithConfigValidatesInputs(t *testing.T) {
	if err := Proxy(context.Background(), nil, "127.0.0.1:8080"); err == nil || !strings.Contains(err.Error(), "exposure is nil") {
		t.Fatalf("nil exposure: got %v", err)
	}
	//nolint:staticcheck // SA1012: intentionally tests nil-context rejection.
	if err := Proxy(nil, &Exposure{}, "127.0.0.1:8080"); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context: got %v", err)
	}
	if err := ProxyWithConfig(context.Background(), &Exposure{}, ProxyConfig{}); err == nil || !strings.Contains(err.Error(), "at least one proxy target is required") {
		t.Fatalf("empty targets: got %v", err)
	}
}

func TestProxyWithConfigRequiresRelays(t *testing.T) {
	err := ProxyWithConfig(context.Background(), &Exposure{}, ProxyConfig{TCPTarget: "127.0.0.1:8080"})
	if err == nil || !strings.Contains(err.Error(), "no relay URLs provided") {
		t.Fatalf("zero-relay exposure: got %v", err)
	}
}
