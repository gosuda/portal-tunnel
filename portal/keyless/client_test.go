package keyless

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// TestClientAccessTokenUpdateChangesSignerHeaders protects the exported-API contract that
// SetAccessToken() updates the headers sent with every subsequent keyless sign request,
// and that whitespace is trimmed from the token value.
func TestClientAccessTokenUpdateChangesSignerHeaders(t *testing.T) {
	t.Parallel()
	client := &Client{}
	client.SetAccessToken(" first ")
	if got := client.headers().Get(types.HeaderAccessToken); got != "first" {
		t.Fatalf("initial access token header = %q, want first", got)
	}
	client.SetAccessToken("second")
	if got := client.headers().Get(types.HeaderAccessToken); got != "second" {
		t.Fatalf("updated access token header = %q, want second", got)
	}
}

// TestVerifyRemoteSignerAcceptsMatchingKey protects the wire-protocol compatibility
// invariant that verifyRemoteSigner() accepts RSA and ECDSA signers whose public key
// matches the key used to produce the self-test signature.
func TestVerifyRemoteSignerAcceptsMatchingKey(t *testing.T) {
	t.Parallel()
	for name, signer := range selfTestSigners(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := verifyRemoteSigner(signer); err != nil {
				t.Fatalf("verifyRemoteSigner() error = %v", err)
			}
		})
	}
}

// TestVerifyRemoteSignerRejectsSwappedKeypair protects the security invariant from
// issue #377: when the pinned certificate advertises keypair A but the sign endpoint
// holds keypair B, verifyRemoteSigner() must reject the connection with errSignerKeyMismatch.
func TestVerifyRemoteSignerRejectsSwappedKeypair(t *testing.T) {
	t.Parallel()
	// Faithful to #377: RemoteSigner.Public() is parsed from the pinned
	// certificate (keypair A) while /v1/sign returns signatures from keypair B.
	cases := map[string]struct{ pinned, swapped crypto.Signer }{
		"rsa":   {pinned: mustRSAKey(t), swapped: mustRSAKey(t)},
		"ecdsa": {pinned: mustECDSAKey(t), swapped: mustECDSAKey(t)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			signer := swappedKeySigner{signWith: tc.swapped, present: tc.pinned.Public()}
			err := verifyRemoteSigner(signer)
			if err == nil {
				t.Fatal("verifyRemoteSigner() = nil, want keypair mismatch failure")
			}
			if !errors.Is(err, errSignerKeyMismatch) {
				t.Fatalf("error should match errSignerKeyMismatch, got: %v", err)
			}
		})
	}
}

// TestVerifyRemoteSignerRejectsTamperedSignature protects the data-integrity invariant
// that a tampered signature (mutated after signing) is rejected by verifyRemoteSigner()
// and classified as errSignerKeyMismatch, not as a sign-RPC failure.
func TestVerifyRemoteSignerRejectsTamperedSignature(t *testing.T) {
	t.Parallel()
	for name, signer := range selfTestSigners(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := verifyRemoteSigner(tamperingSigner{inner: signer})
			if err == nil {
				t.Fatal("verifyRemoteSigner() = nil, want tampered signature failure")
			}
			if !errors.Is(err, errSignerKeyMismatch) {
				t.Fatalf("error should match errSignerKeyMismatch, got: %v", err)
			}
		})
	}
}

// TestVerifyRemoteSignerPropagatesSignError protects the error-handling contract that when
// the keyless sign endpoint returns an error (network or server fault), that error propagates
// to the caller and is not incorrectly reclassified as errSignerKeyMismatch.
func TestVerifyRemoteSignerPropagatesSignError(t *testing.T) {
	t.Parallel()
	rsaKey := mustRSAKey(t)
	err := verifyRemoteSigner(failingSigner{public: rsaKey.Public()})
	if err == nil {
		t.Fatal("verifyRemoteSigner() = nil, want sign error propagation")
	}
	if !strings.Contains(err.Error(), "sign self-test challenge") {
		t.Fatalf("error should name the sign step, got: %v", err)
	}
	if errors.Is(err, errSignerKeyMismatch) {
		t.Fatal("sign-RPC failure must not be classified as a keypair mismatch")
	}
}

// TestVerifyRemoteSignerUnsupportedKey protects the wire-protocol compatibility contract that
// Ed25519 keys are rejected as unsupported by the keyless sign protocol (which only supports
// RSA and ECDSA), and the error message names the protocol limitation.
func TestVerifyRemoteSignerUnsupportedKey(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	err = verifyRemoteSigner(priv)
	if err == nil {
		t.Fatal("verifyRemoteSigner() = nil, want error for unsupported key type")
	}
	if !strings.Contains(err.Error(), "not supported by the keyless sign protocol") {
		t.Fatalf("error should name the protocol limitation, got: %v", err)
	}
	if errors.Is(err, errSignerKeyMismatch) {
		t.Fatal("unsupported key type must not be classified as a keypair mismatch")
	}
}

// TestClientClosePreservesFirstError protects the lifecycle guarantee that once Close()
// returns an error, subsequent Close() calls keep returning that same first error rather
// than masking it with a later close failure, and the underlying resource is closed exactly once.
func TestClientClosePreservesFirstError(t *testing.T) {
	t.Parallel()
	closer := &failingCloseResource{}
	client := &Client{signer: closer}

	first := client.Close()
	second := client.Close()
	if first == nil || second == nil {
		t.Fatalf("Close() must keep reporting the first close error; got first=%v second=%v", first, second)
	}
	if !errors.Is(second, first) {
		t.Fatalf("second Close() = %v, want first close error %v", second, first)
	}
	if closer.calls != 1 {
		t.Fatalf("underlying resource closed %d times, want exactly 1", closer.calls)
	}
}

func selfTestSigners(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	return map[string]crypto.Signer{
		"rsa":   mustRSAKey(t),
		"ecdsa": mustECDSAKey(t),
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return key
}

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	return key
}

// swappedKeySigner mimics a RemoteSigner whose pinned certificate advertises
// keypair A while the signing endpoint holds keypair B.
type swappedKeySigner struct {
	signWith crypto.Signer
	present  crypto.PublicKey
}

func (s swappedKeySigner) Public() crypto.PublicKey { return s.present }

func (s swappedKeySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signWith.Sign(rand, digest, opts)
}

type tamperingSigner struct {
	inner crypto.Signer
}

func (s tamperingSigner) Public() crypto.PublicKey { return s.inner.Public() }

func (s tamperingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := s.inner.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}
	signature[len(signature)-1] ^= 0x01
	return signature, nil
}

type failingSigner struct {
	public crypto.PublicKey
}

func (s failingSigner) Public() crypto.PublicKey { return s.public }

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("sign endpoint unavailable")
}

type failingCloseResource struct {
	calls int
}

func (c *failingCloseResource) Close() error {
	c.calls++
	return errors.New("signer close failed")
}
