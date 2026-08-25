package keyless

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	ksigner "github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	// TenantKeyID is the only private key identifier exposed by the keyless signer.
	TenantKeyID        = "tenant-wildcard"
	defaultAllowedSkew = 5 * time.Minute
)

type Signer struct {
	service          *ksigner.Service
	keyID            string
	certificateChain []byte
}

func NewSigner(certPEM, keyPEM []byte) (*Signer, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse tenant keyless keypair: %w", err)
	}
	signingKey, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tenant keyless private key does not implement crypto.Signer")
	}

	store := ksigner.NewStaticKeyStore()
	if err := store.Put(TenantKeyID, signingKey); err != nil {
		return nil, fmt.Errorf("register keyless signing key: %w", err)
	}

	return &Signer{
		service: &ksigner.Service{
			Store:       store,
			AllowedSkew: defaultAllowedSkew,
		},
		keyID:            TenantKeyID,
		certificateChain: bytes.Clone(certPEM),
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

// ValidateMaterialSeparation ensures the tenant signer cannot authenticate the relay apex or unrelated names.
func ValidateMaterialSeparation(hostname string, apiCertPEM, tenantCertPEM []byte) error {
	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return errors.New("relay hostname is required")
	}
	apiCert, err := utils.ParseCertificatePEM(apiCertPEM)
	if err != nil {
		return fmt.Errorf("parse api certificate: %w", err)
	}
	tenantCert, err := utils.ParseCertificatePEM(tenantCertPEM)
	if err != nil {
		return fmt.Errorf("parse tenant certificate: %w", err)
	}
	if bytes.Equal(apiCert.RawSubjectPublicKeyInfo, tenantCert.RawSubjectPublicKeyInfo) {
		return errors.New("api and tenant certificates must use different public keys")
	}
	if tenantCert.IsCA {
		return errors.New("tenant certificate must not be a certificate authority")
	}
	if tenantCert.VerifyHostname(hostname) == nil {
		return fmt.Errorf("tenant certificate must not cover relay hostname %q", hostname)
	}
	wildcard := "*." + hostname
	if len(tenantCert.DNSNames) != 1 || !strings.EqualFold(strings.TrimSpace(tenantCert.DNSNames[0]), wildcard) || len(tenantCert.IPAddresses) != 0 {
		return fmt.Errorf("tenant certificate must cover only %q", wildcard)
	}
	return nil
}

func (s *Signer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(types.PathV1KeylessMaterials, func(w http.ResponseWriter, r *http.Request) {
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		utils.WriteAPIData(w, http.StatusOK, types.KeylessMaterials{
			KeyID:            s.keyID,
			CertificateChain: bytes.Clone(s.certificateChain),
		})
	})
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
