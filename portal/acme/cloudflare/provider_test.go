package cloudflare

import (
	"context"
	"testing"
)

func TestChallengeProviderRequiresToken(t *testing.T) {
	t.Parallel()

	provider := New("")
	challengeProvider, err := provider.ChallengeProvider(context.Background())
	if challengeProvider != nil {
		t.Fatalf("ChallengeProvider() provider = %T, want nil", challengeProvider)
	}
	if err == nil || err.Error() != "cloudflare token is required" {
		t.Fatalf("ChallengeProvider() error = %v, want local token error", err)
	}
}
