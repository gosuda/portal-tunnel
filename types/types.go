package types

const (
	HeaderAccessToken       = "X-Portal-Access-Token"
	HeaderAccessCredential  = "X-Portal-Access-Credential"
	HeaderReverseCapability = "X-Portal-Reverse-Capability"

	// ReverseSubprotocol marks a WebSocket carrying reverse connections as yamux streams;
	// an initial capability rides beside it and every logical stream authenticates again.
	ReverseSubprotocol = "portal.reverse.v1"
)

const (
	DefaultHTTPRedirectAddr = ":80"
	HTTPRedirectFeatureName = "http-redirect"
	HTTPRedirectEnabledEnv  = "HTTP_REDIRECT_ENABLED"
)

// HTTPRedirectConfig controls the optional canonical-portal HTTP listener.
// The zero value disables redirects and HSTS; an empty Addr defaults to :80.
type HTTPRedirectConfig struct {
	Enabled bool
	Addr    string
	HSTS    bool
}
