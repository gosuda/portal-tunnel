package njalla

import (
	"context"
	"encoding/json"
	"testing"
)

func TestChallengeProviderRequiresToken(t *testing.T) {
	t.Parallel()

	provider := New("")
	challengeProvider, err := provider.ChallengeProvider(context.Background())
	if challengeProvider != nil {
		t.Fatalf("ChallengeProvider() provider = %T, want nil", challengeProvider)
	}
	if err == nil || err.Error() != "njalla token is required" {
		t.Fatalf("ChallengeProvider() error = %v, want local token error", err)
	}
}

func TestRecordIDUnmarshal(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{`{"id":"123"}`, `{"id":123}`} {
		var record record
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
		}
		if record.ID.String() != "123" {
			t.Fatalf("record id = %q, want 123", record.ID.String())
		}
	}
}
