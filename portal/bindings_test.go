package portal

import (
	"errors"
	"testing"
	"time"

	ksigner "github.com/gosuda/keyless_tls/relay/signer"
)

func TestBindingRegistryIssueAndConsume(t *testing.T) {
	t.Parallel()

	registry := newBindingRegistry(5 * time.Minute)
	binding := registry.issue("lease-1")
	if len(binding) != 16 {
		t.Fatalf("issue() binding length = %d, want 16", len(binding))
	}
	if err := registry.validateAndConsume(binding[:], "lease-1"); err != nil {
		t.Fatalf("validateAndConsume() fresh binding error = %v, want nil", err)
	}
}

func TestBindingRegistryConsumedOnce(t *testing.T) {
	t.Parallel()

	registry := newBindingRegistry(5 * time.Minute)
	binding := registry.issue("lease-1")
	if err := registry.validateAndConsume(binding[:], "lease-1"); err != nil {
		t.Fatalf("validateAndConsume() first use error = %v, want nil", err)
	}
	if err := registry.validateAndConsume(binding[:], "lease-1"); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() reuse error = %v, want permission denied", err)
	}
}

func TestBindingRegistryRejectsCrossLease(t *testing.T) {
	t.Parallel()

	registry := newBindingRegistry(5 * time.Minute)
	binding := registry.issue("lease-1")
	if err := registry.validateAndConsume(binding[:], "lease-2"); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() cross-lease error = %v, want permission denied", err)
	}
	// A rejected presentation must not consume the binding.
	if err := registry.validateAndConsume(binding[:], "lease-1"); err != nil {
		t.Fatalf("validateAndConsume() after rejected cross-lease error = %v, want nil", err)
	}
}

func TestBindingRegistryRejectsExpiry(t *testing.T) {
	t.Parallel()

	// A negative TTL makes every minted binding already expired.
	registry := newBindingRegistry(-time.Minute)
	binding := registry.issue("lease-1")
	if err := registry.validateAndConsume(binding[:], "lease-1"); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() expired binding error = %v, want permission denied", err)
	}
}

func TestBindingRegistryRejectsMalformedAndUnknown(t *testing.T) {
	t.Parallel()

	registry := newBindingRegistry(5 * time.Minute)
	if err := registry.validateAndConsume([]byte("short"), "lease-1"); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() short binding error = %v, want permission denied", err)
	}
	unknown := registry.issue("lease-1")
	unknown[0] ^= 0xff
	if err := registry.validateAndConsume(unknown[:], "lease-1"); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() unknown binding error = %v, want permission denied", err)
	}
}

func TestBindingRegistrySweepExpired(t *testing.T) {
	t.Parallel()

	registry := newBindingRegistry(-time.Minute)
	registry.issue("lease-1")
	live := newBindingRegistry(5 * time.Minute)
	liveBinding := live.issue("lease-1")

	registry.sweepExpired(time.Now())
	if len(registry.entries) != 0 {
		t.Fatalf("sweepExpired() entries = %d, want 0 after expiry", len(registry.entries))
	}
	live.sweepExpired(time.Now())
	if _, ok := live.entries[liveBinding]; !ok {
		t.Fatal("sweepExpired() dropped live binding, want it kept")
	}
}
