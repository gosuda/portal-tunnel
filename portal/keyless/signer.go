package keyless

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	ksigner "github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

// RelayKeyID is the store key of the relay API listener certificate key.
// Tenant handshakes address it explicitly in every TranscriptSignRequest.
const RelayKeyID = "relay-cert"

const (
	defaultAllowedSkew = 30 * time.Second
	// maxSignRequestBody bounds /v1/sign JSON bodies. The transcript carries
	// full certificate chains, so the budget is generous but finite.
	maxSignRequestBody = 512 << 10
)

type Signer struct {
	service *ksigner.Service
}

// NewSigner builds the relay-side transcript signer bound to the relay API
// TLS key. Portal requires a validator because keyless_tls intentionally
// treats a nil validator as the generic mechanism and signs any structurally
// valid transcript; Portal's lease/binding policy must therefore be explicit.
func NewSigner(keyPEM []byte, validator ksigner.TranscriptValidator) (*Signer, error) {
	if validator == nil {
		return nil, errors.New("portal transcript validator is required")
	}

	signingKey, err := ksigner.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse keyless signing key: %w", err)
	}

	store := ksigner.NewStaticKeyStore()
	if err := store.Put(RelayKeyID, signingKey); err != nil {
		return nil, fmt.Errorf("register keyless signing key: %w", err)
	}

	return &Signer{
		service: &ksigner.Service{
			Store:               store,
			AllowedSkew:         defaultAllowedSkew,
			TranscriptValidator: validator,
		},
	}, nil
}

// Handler serves the transcript-bound sign endpoint. Requests and responses
// use the signrpc wire types; failures map to status codes without leaking
// validator internals.
func (s *Signer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		defer r.Body.Close()

		var req signrpc.TranscriptSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json body")
			return
		}

		resp, err := s.service.SignTranscript(r.Context(), &req)
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
	})
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(signrpc.ErrorResponse{Error: message})
}