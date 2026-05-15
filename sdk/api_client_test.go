package sdk

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestNewRenewRequestIncludesMetadata(t *testing.T) {
	t.Parallel()

	metadata := types.LeaseMetadata{
		Description: "live app",
		Tags:        []string{"demo", "live"},
		Owner:       "ops",
		Thumbnail:   "https://example.com/thumb.png",
		Hide:        true,
	}

	req := newRenewRequest(2*time.Minute, "token", "203.0.113.10", metadata)
	if req.AccessToken != "token" {
		t.Fatalf("AccessToken = %q, want token", req.AccessToken)
	}
	if req.TTL != 120 {
		t.Fatalf("TTL = %d, want 120", req.TTL)
	}
	if req.ReportedIP != "203.0.113.10" {
		t.Fatalf("ReportedIP = %q, want 203.0.113.10", req.ReportedIP)
	}
	if got := req.Metadata; got.Description != metadata.Description || got.Owner != metadata.Owner || got.Thumbnail != metadata.Thumbnail || got.Hide != metadata.Hide || len(got.Tags) != 2 || got.Tags[0] != "demo" || got.Tags[1] != "live" {
		t.Fatalf("Metadata = %#v, want %#v", got, metadata)
	}

	metadata.Tags[0] = "mutated"
	if req.Metadata.Tags[0] != "demo" {
		t.Fatalf("Metadata tags alias input slice: got %q", req.Metadata.Tags[0])
	}
}
