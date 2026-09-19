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

// Pre-auth admission layer values identify which shared budget rejected a request.
const (
	PreAuthLayerSource = "source"
	PreAuthLayerGlobal = "global"
)
