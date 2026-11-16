package main

import (
	"slices"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestPublicIdentityLeasesUsesServiceIdentity(t *testing.T) {
	const owner = "0x1111111111111111111111111111111111111111"
	first := types.Lease{Name: "first", Address: owner, Hostname: "first.example.com"}
	second := types.Lease{Name: "second", Address: owner, Hostname: "second.example.com"}
	canonical := types.Lease{Address: owner, Namespace: types.LocalTLSNamespaceV1, CanonicalHostname: "default." + owner[2:] + ".example.com"}
	hidden := first
	hidden.Address = "0x2222222222222222222222222222222222222222"
	hidden.Metadata.Hide = true
	policies := make([]types.PolicyLease, 0)
	for _, lease := range []types.Lease{hidden, first, first, second, canonical} {
		policies = append(policies, types.PolicyLease{
			Lease:       lease,
			IdentityKey: types.NewServiceIdentityKey(lease.Name, lease.Address).String(),
		})
	}
	leases := publicIdentityLeases([]types.Lease{first, second, canonical}, policies)
	got := make([]string, 0, len(leases))
	for _, lease := range leases {
		got = append(got, lease.IdentityKey)
	}
	want := []string{
		types.NewServiceIdentityKey(first.Name, owner).String(),
		types.NewServiceIdentityKey(second.Name, owner).String(),
		types.NewServiceIdentityKey(canonical.Name, owner).String(),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("public identities = %v, want %v", got, want)
	}
}
