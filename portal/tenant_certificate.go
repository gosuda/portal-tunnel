package portal

import (
	"crypto/x509"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// tenantCertificateNames snapshots exact live ownership. A replacement lease
// must not complete an earlier owner's issuance request. Reassignable aliases
// are deliberately excluded from automatic certificate issuance.
func (r *leaseRegistry) tenantCertificateNames(record *leaseRecord) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	current, err := r.recordForVerifiedLeaseLocked(record.ServiceKey(), record.id, time.Now())
	if err != nil {
		return nil, err
	}
	if blocked, ok := r.blocked[current.ServiceKey()]; ok {
		return nil, blocked.refusal
	}
	if current.reverse == nil {
		return nil, errTransportMismatch
	}
	return []string{current.CanonicalHostname}, nil
}

// HandleTenantCertificate authenticates issuance with the existing lease token.
// The relay receives only a signed CSR and never handles the tenant private key.
func (s *Server) HandleTenantCertificate(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	if s.acmeManager == nil || !s.config().TenantCertificates {
		writeAPIErrorResponse(w, errFeatureUnavailable)
		return
	}
	record, err := s.registry.admitLeaseByToken(r.Header.Get(types.HeaderAccessToken), false)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	names, err := s.registry.tenantCertificateNames(record)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	request, ok := utils.DecodeJSONRequest[types.TenantCertificateRequest](w, r, 16<<10)
	if !ok {
		return
	}
	csr, err := acme.ParseTenantCSR(request.CSRPEM, names)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	cert, err := s.acmeManager.ObtainTenantCertificate(r.Context(), csr)
	if err != nil {
		if errors.Is(err, acme.ErrTenantOrderLimited) || errors.Is(err, acme.ErrTenantIssuerBusy) {
			w.Header().Set("Retry-After", "10")
			if errors.Is(err, acme.ErrTenantOrderLimited) {
				w.Header().Set("Retry-After", "3600")
			}
			utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, err.Error())
			return
		}
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, err.Error())
		return
	}
	names, err = s.registry.tenantCertificateNames(record)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	if !tenantCSRStillOwned(csr, names) {
		writeAPIErrorResponse(w, errUnauthorized)
		return
	}
	utils.WriteAPIData(w, http.StatusOK, types.TenantCertificateResponse{CertificatePEM: string(cert)})
}

func tenantCSRStillOwned(csr *x509.CertificateRequest, names []string) bool {
	for _, name := range csr.DNSNames {
		if !slices.Contains(names, name) {
			return false
		}
	}
	return true
}
