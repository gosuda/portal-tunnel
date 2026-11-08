package types

// KeylessUnknownCertificateMessage is a compatibility signal from /v1/sign:
// the client refreshes its pinned chain when the remote signer reports it.
// The signer exposes the refusal text rather than a structured error code.
const KeylessUnknownCertificateMessage = "relay does not hold the key of the presented certificate"

const (
	APIErrorCodeFeatureUnavailable      = "feature_unavailable"
	APIErrorCodeHijackFailed            = "hijack_failed"
	APIErrorCodeHijackUnsupported       = "hijack_unsupported"
	APIErrorCodeHostnameConflict        = "hostname_conflict"
	APIErrorCodeHTTP11Only              = "http11_only"
	APIErrorCodeInvalidAddress          = "invalid_address"
	APIErrorCodeInvalidJSON             = "invalid_json"
	APIErrorCodeInvalidMode             = "invalid_mode"
	APIErrorCodeInvalidRequest          = "invalid_request"
	APIErrorCodeInternal                = "internal"
	APIErrorCodeLeaseDenied             = "lease_denied"
	APIErrorCodeLeaseNotFound           = "lease_not_found"
	APIErrorCodeLeaseRejected           = "lease_rejected"
	APIErrorCodeMethodNotAllowed        = "method_not_allowed"
	APIErrorCodeNotFound                = "not_found"
	APIErrorCodeRateLimited             = "rate_limited"
	APIErrorCodeReplicaConflict         = "replica_conflict"
	APIErrorCodeUnauthorized            = "unauthorized"
	APIErrorCodeUDPPortExhausted        = "udp_port_exhausted"
	APIErrorCodeUDPDisabled             = "udp_disabled"
	APIErrorCodeUDPCapacityExceeded     = "udp_capacity_exceeded"
	APIErrorCodeTCPPortExhausted        = "tcp_port_exhausted"
	APIErrorCodeTCPPortDisabled         = "tcp_port_disabled"
	APIErrorCodeTCPPortCapacityExceeded = "tcp_port_capacity_exceeded"
	APIErrorCodeTransportMismatch       = "transport_mismatch"

	MITMProbeReasonExporterMismatch = "tls_exporter_mismatch"
	MITMProbeReasonProbeTimeout     = "probe_timeout"
)
