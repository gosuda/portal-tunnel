package portal

import (
	"bytes"
	"errors"
	"testing"
	"time"

	ksigner "github.com/gosuda/keyless_tls/relay/signer"

	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
)

// testHelloMessage builds a structurally valid ClientHello handshake message
// with 1 type byte + 3-byte length + body, exactly the TranscriptSignRequest
// ClientHello span. Its 32-byte random ends in suffix, so two calls yield
// two distinct real hello spans.
func testHelloMessage(suffix byte) []byte {
	body := []byte{
		0x03, 0x03, // legacy_version: TLS 1.2
	}
	for i := 0; i < 31; i++ {
		body = append(body, 0x00)
	}
	body = append(body, suffix) // random: 32 bytes, distinct per suffix
	body = append(body,
		0x00,                   // legacy_session_id: length 0
		0x00, 0x02, 0x13, 0x01, // cipher_suites: TLS_AES_128_GCM_SHA256
		0x01, 0x00, // legacy_compression_methods: null
		0x00, 0x00, // extensions: length 0
	)

	msg := make([]byte, 4+len(body))
	msg[0] = tlsHandshakeTypeClientHello
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)
	return msg
}

// testFirstTLSRecord wraps a handshake message as the first TLS record a
// client writes: 5-byte record header plus the complete message.
func testFirstTLSRecord(t *testing.T, handshakeMessage []byte) []byte {
	t.Helper()

	record := make([]byte, tlsRecordHeaderLen+len(handshakeMessage))
	record[0] = tlsContentTypeHandshake
	record[3] = byte(len(handshakeMessage) >> 8)
	record[4] = byte(len(handshakeMessage))
	copy(record[tlsRecordHeaderLen:], handshakeMessage)
	return record
}

func TestBindingRegistryIssueAndConsume(t *testing.T) {
	t.Parallel()

	registry := keyless.NewBindingRegistry(5 * time.Minute)
	hello := testHelloMessage(0x01)
	binding := registry.Issue("lease-1", hello)
	if len(binding) != 16 {
		t.Fatalf("issue() binding length = %d, want 16", len(binding))
	}
	if err := registry.ValidateAndConsume(binding[:], "lease-1", hello); err != nil {
		t.Fatalf("validateAndConsume() fresh binding error = %v, want nil", err)
	}
}

func TestBindingRegistryConsumedOnce(t *testing.T) {
	t.Parallel()

	registry := keyless.NewBindingRegistry(5 * time.Minute)
	hello := testHelloMessage(0x02)
	binding := registry.Issue("lease-1", hello)
	if err := registry.ValidateAndConsume(binding[:], "lease-1", hello); err != nil {
		t.Fatalf("validateAndConsume() first use error = %v, want nil", err)
	}
	if err := registry.ValidateAndConsume(binding[:], "lease-1", hello); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() reuse error = %v, want permission denied", err)
	}
}

func TestBindingRegistryRejectsCrossLease(t *testing.T) {
	t.Parallel()

	registry := keyless.NewBindingRegistry(5 * time.Minute)
	hello := testHelloMessage(0x03)
	binding := registry.Issue("lease-1", hello)
	if err := registry.ValidateAndConsume(binding[:], "lease-2", hello); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() cross-lease error = %v, want permission denied", err)
	}
	// A rejected presentation must not consume the binding.
	if err := registry.ValidateAndConsume(binding[:], "lease-1", hello); err != nil {
		t.Fatalf("validateAndConsume() after rejected cross-lease error = %v, want nil", err)
	}
}

func TestBindingRegistryRejectsExpiry(t *testing.T) {
	t.Parallel()

	// A negative TTL makes every minted binding already expired.
	registry := keyless.NewBindingRegistry(-time.Minute)
	hello := testHelloMessage(0x04)
	binding := registry.Issue("lease-1", hello)
	if err := registry.ValidateAndConsume(binding[:], "lease-1", hello); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() expired binding error = %v, want permission denied", err)
	}
}

func TestBindingRegistryRejectsMalformedAndUnknown(t *testing.T) {
	t.Parallel()

	registry := keyless.NewBindingRegistry(5 * time.Minute)
	hello := testHelloMessage(0x05)
	if err := registry.ValidateAndConsume([]byte("short"), "lease-1", hello); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() short binding error = %v, want permission denied", err)
	}
	unknown := registry.Issue("lease-1", hello)
	unknown[0] ^= 0xff
	if err := registry.ValidateAndConsume(unknown[:], "lease-1", hello); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() unknown binding error = %v, want permission denied", err)
	}
}

// TestBindingRegistryRejectsForeignClientHelloTranscript pins the review
// blocker this file exists to close: before transcript binding, a signature
// over connection B's ClientHello validated against connection A's binding,
// so one routed connection unlocked transcript signing for every connection.
func TestBindingRegistryRejectsForeignClientHelloTranscript(t *testing.T) {
	t.Parallel()

	registry := keyless.NewBindingRegistry(5 * time.Minute)
	helloA := testHelloMessage(0xa1)
	helloB := testHelloMessage(0xb2)
	binding := registry.Issue("lease-1", helloA)

	if err := registry.ValidateAndConsume(binding[:], "lease-1", helloB); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() foreign hello error = %v, want permission denied", err)
	}
	if err := registry.ValidateAndConsume(binding[:], "lease-1", nil); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() nil hello error = %v, want permission denied", err)
	}
	// A rejected transcript must not consume the binding: connection A's
	// own transcript still validates exactly once.
	if err := registry.ValidateAndConsume(binding[:], "lease-1", helloA); err != nil {
		t.Fatalf("validateAndConsume() own hello error = %v, want nil", err)
	}
}

// TestBindingRegistryPendingHelloDeniesValidateUntilFixed covers the cache
// path lifecycle: a binding issued before any hello exists denies every
// validation, and only FixHello, which the relay must run before the SDK
// sees the ClientHello, arms it, at most once.
func TestBindingRegistryPendingHelloDeniesValidateUntilFixed(t *testing.T) {
	t.Parallel()

	registry := keyless.NewBindingRegistry(5 * time.Minute)
	hello := testHelloMessage(0xc3)
	binding := registry.Issue("lease-1", nil)
	if err := registry.ValidateAndConsume(binding[:], "lease-1", hello); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() pending binding error = %v, want permission denied", err)
	}
	if err := registry.FixHello(binding, hello); err != nil {
		t.Fatalf("fixHello() pending binding error = %v, want nil", err)
	}
	if err := registry.FixHello(binding, hello); err == nil {
		t.Fatal("fixHello() second call error = nil, want already-fixed error")
	}
	if err := registry.ValidateAndConsume(binding[:], "lease-1", hello); err != nil {
		t.Fatalf("validateAndConsume() fixed binding error = %v, want nil", err)
	}
}

// TestBindingRegistryDiscardRemovesPendingBinding covers the failed-claim
// path: a binding whose stream claim never delivered it is dropped outright
// instead of lingering until the TTL sweep.
func TestBindingRegistryDiscardRemovesPendingBinding(t *testing.T) {
	t.Parallel()

	registry := keyless.NewBindingRegistry(5 * time.Minute)
	hello := testHelloMessage(0xd4)
	binding := registry.Issue("lease-1", nil)
	registry.Discard(binding)

	if err := registry.ValidateAndConsume(binding[:], "lease-1", hello); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() discarded binding error = %v, want permission denied", err)
	}
	if err := registry.FixHello(binding, hello); err == nil {
		t.Fatal("fixHello() discarded binding error = nil, want unknown-binding error")
	}
}

func TestBindingRegistrySweepExpired(t *testing.T) {
	t.Parallel()

	hello := testHelloMessage(0xe5)
	registry := keyless.NewBindingRegistry(-time.Minute)
	expiredBinding := registry.Issue("lease-1", hello)
	live := keyless.NewBindingRegistry(5 * time.Minute)
	liveBinding := live.Issue("lease-1", hello)

	registry.SweepExpired(time.Now())
	if err := registry.ValidateAndConsume(expiredBinding[:], "lease-1", hello); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("validateAndConsume() swept binding error = %v, want permission denied", err)
	}
	live.SweepExpired(time.Now())
	if err := live.ValidateAndConsume(liveBinding[:], "lease-1", hello); err != nil {
		t.Fatalf("validateAndConsume() live binding error = %v, want nil", err)
	}
}

func TestHelloSpanFromFirstRecord(t *testing.T) {
	t.Parallel()

	hello := testHelloMessage(0xf6)
	record := testFirstTLSRecord(t, hello)

	span, err := helloSpanFromFirstRecord(record)
	if err != nil {
		t.Fatalf("helloSpanFromFirstRecord() error = %v, want nil", err)
	}
	if !bytes.Equal(span, hello) {
		t.Fatalf("helloSpanFromFirstRecord() span length = %d, want %d (the full handshake message)", len(span), len(hello))
	}

	// Data pipelined after the hello in the same record stays out of the span.
	withTrailer := append(append([]byte{}, record...), 0xde, 0xad)
	trailerSpan, err := helloSpanFromFirstRecord(withTrailer)
	if err != nil {
		t.Fatalf("helloSpanFromFirstRecord() with trailer error = %v, want nil", err)
	}
	if !bytes.Equal(trailerSpan, hello) {
		t.Fatal("helloSpanFromFirstRecord() with trailer did not stop at the declared message length")
	}

	for name, record := range map[string][]byte{
		"short":             record[:tlsRecordHeaderLen+2],
		"wrong content":     {0x17, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00},
		"wrong handshake":   {0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
		"truncated body":    {0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x20},
		"empty record body": {0x16, 0x03, 0x03, 0x00, 0x00},
	} {
		if _, err := helloSpanFromFirstRecord(record); err == nil {
			t.Fatalf("helloSpanFromFirstRecord() %s error = nil, want error", name)
		}
	}
}
