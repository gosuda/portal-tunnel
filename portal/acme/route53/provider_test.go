package route53

import (
	"context"
	"testing"
)

// Operators paste hosted zone IDs in the "/hostedzone/Z..." form shown by the
// AWS console; the configured override must keep accepting that form.
func TestFindHostedZoneIDExplicitOverride(t *testing.T) {
	t.Parallel()

	got, err := New(Config{HostedZoneID: "/hostedzone/Z123456789"}).findHostedZoneID(context.Background(), nil, "portal.example.com")
	if err != nil {
		t.Fatalf("findHostedZoneID() error = %v", err)
	}
	if got != "Z123456789" {
		t.Fatalf("findHostedZoneID() = %q, want %q", got, "Z123456789")
	}
}
