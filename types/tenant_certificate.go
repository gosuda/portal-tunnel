package types

// TenantCertificateRequest contains a CSR whose private key stays on the tunnel.
type TenantCertificateRequest struct {
	CSRPEM string `json:"csr_pem"`
}

type TenantCertificateResponse struct {
	CertificatePEM string `json:"certificate_pem"`
}
