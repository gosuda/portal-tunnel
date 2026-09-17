package types

// PreAuthConfig describes operational limits, not protocol constants.
type PreAuthConfig struct {
	SourcePerMinute int
	SourceBurst     int
	GlobalPerMinute int
	GlobalBurst     int
	ChallengeCost   int
	AnnounceCost    int
	RegisterCost    int
}

// Pre-auth admission labels and metric names are stable monitoring contracts.
const (
	PreAuthLayerSource        = "source"
	PreAuthLayerGlobal        = "global"
	PreAuthRejectedMetricName = "portal_preauth_rejected_total"
	PreAuthEndpointLabel      = "endpoint"
	PreAuthLayerLabel         = "layer"
)
