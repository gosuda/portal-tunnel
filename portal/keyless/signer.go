package keyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	ksigner "github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

const (
	RelayKeyID         = "relay-cert"
	defaultAllowedSkew = 5 * time.Minute
)

type Signer struct {
	service *ksigner.Service
	keyID   string
}

func NewSigner(keyPEM []byte) (*Signer, error) {
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
			Store:       store,
			AllowedSkew: defaultAllowedSkew,
		},
		keyID: RelayKeyID,
	}, nil
}

func (s *Signer) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

func (s *Signer) Sign(ctx context.Context, req *signrpc.SignRequest) (*signrpc.SignResponse, error) {
	if s == nil || s.service == nil {
		return nil, errors.New("keyless signer is disabled")
	}
	return s.service.Sign(ctx, req)
}

func (s *Signer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(signrpc.SignPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
			writeJSONError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		defer r.Body.Close()

		var req signrpc.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json body")
			return
		}

		resp, err := s.Sign(r.Context(), &req)
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
	return mux
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(signrpc.ErrorResponse{Error: message})
}
