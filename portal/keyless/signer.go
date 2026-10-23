package keyless

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	ksigner "github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
	"golang.org/x/crypto/cryptobyte"
)

// relayKeyID is the store key of the relay API listener certificate key.
// Tenant handshakes address it explicitly in every TranscriptSignRequest.
const relayKeyID = "relay-cert"

const (
	// handshakeTypeCertificate is the TLS handshake message type of Certificate.
	handshakeTypeCertificate = 11
	defaultAllowedSkew       = 30 * time.Second
	// maxSignRequestBody bounds /v1/sign JSON bodies. The transcript carries
	// full certificate chains, so the budget is generous but finite.
	maxSignRequestBody = 512 << 10
)

// unknownCertificateMessage is the /v1/sign answer when the relay holds no key
// for the certificate the tenant presents. The tenant's pinned chain is stale
// then, and the Client reads this text to pin the chain the relay serves now.
const unknownCertificateMessage = "relay does not hold the key of the presented certificate"

type Signer struct {
	service *ksigner.Service
}

// NewSigner builds the relay-side transcript signer bound to Portal's
// connection-binding policy. signingKey returns the private key of the
// certificate whose leaf (DER) a request presents, or nil when the relay holds
// none: a tenant pins the relay chain when it registers, so the key must be
// the one of that certificate and not necessarily of the one served now.
func NewSigner(bindings *BindingRegistry, signingKey func(leafDER []byte) crypto.Signer) (*Signer, error) {
	if bindings == nil {
		return nil, errors.New("portal binding registry is required")
	}
	if signingKey == nil {
		return nil, errors.New("signing key lookup is required")
	}

	return &Signer{
		service: &ksigner.Service{
			Store:       certificateKeys(signingKey),
			AllowedSkew: defaultAllowedSkew,
			TranscriptValidator: ksigner.TranscriptValidatorFunc(func(ctx context.Context, req *signrpc.TranscriptSignRequest) error {
				leaseID, _ := ctx.Value(signLeaseIDContextKey{}).(string)
				if leaseID == "" {
					return errors.New("signing request is not bound to a verified lease")
				}
				return bindings.ValidateAndConsume(req.Binding, leaseID, req.ClientHello)
			}),
		},
	}, nil
}

type (
	signLeaseIDContextKey   struct{}
	presentedLeafContextKey struct{}
)

// certificateKeys is the signer key store: it resolves the one key id every
// tenant asks for to the key of the certificate the request presents.
type certificateKeys func(leafDER []byte) crypto.Signer

func (keys certificateKeys) Signer(ctx context.Context, keyID string) (crypto.Signer, error) {
	if keyID != relayKeyID {
		return nil, fmt.Errorf("unknown key id: %s", keyID)
	}
	leaf, _ := ctx.Value(presentedLeafContextKey{}).([]byte)
	if signer := keys(leaf); signer != nil {
		return signer, nil
	}
	return nil, errors.New(unknownCertificateMessage)
}

// presentedLeaf returns the leaf certificate (DER) of a TLS 1.3 Certificate
// handshake message (RFC 8446 section 4.4.2). The signature covers that
// message, so its leaf is the certificate the visitor verifies it against.
func presentedLeaf(message []byte) ([]byte, error) {
	malformed := errors.New("malformed certificate message")
	var messageType uint8
	var body, requestContext, entries, leaf cryptobyte.String
	input := cryptobyte.String(message)
	if !input.ReadUint8(&messageType) || messageType != handshakeTypeCertificate || !input.ReadUint24LengthPrefixed(&body) || !input.Empty() {
		return nil, malformed
	}
	if !body.ReadUint8LengthPrefixed(&requestContext) || !body.ReadUint24LengthPrefixed(&entries) || !body.Empty() {
		return nil, malformed
	}
	if !entries.ReadUint24LengthPrefixed(&leaf) || len(leaf) == 0 {
		return nil, malformed
	}
	return leaf, nil
}

// ServeHTTP serves one transcript-signing request for an authenticated lease.
func (s *Signer) ServeHTTP(w http.ResponseWriter, r *http.Request, leaseID string) {
	r = r.WithContext(context.WithValue(r.Context(), signLeaseIDContextKey{}, leaseID))
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		writeJSONError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSignRequestBody)
	// The HTTP server owns body closure; connection deadlines belong to handlers.

	var req signrpc.TranscriptSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	leaf, err := presentedLeaf(req.Certificate)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := context.WithValue(r.Context(), presentedLeafContextKey{}, leaf)

	resp, err := s.service.SignTranscript(ctx, &req)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, ksigner.ErrInvalidArgument):
			status = http.StatusBadRequest
		case errors.Is(err, ksigner.ErrPermissionDenied):
			status = http.StatusForbidden
		}
		writeJSONError(w, status, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(signrpc.ErrorResponse{Error: message})
}
