package mols

import "time"

// Default tuning constants for the GF(64) MOLS grid engine.
const (
	DefaultOrder         = 64
	DefaultMagicConstant = DefaultOrder*DefaultOrder + 1 // 4097

	DefaultBaseM1    uint8 = 3
	DefaultBaseM2    uint8 = 5
	DefaultVariantM1 uint8 = 7
	DefaultVariantM2 uint8 = 11

	DefaultCongestionRTTThreshold = 500 * time.Millisecond
	DefaultCVThreshold            = 0.5
	DefaultFallbackRTTThreshold   = 2 * time.Second
	DefaultMinActiveNodes         = 2
	DefaultMaxActiveRelays        = 3
	DefaultCandidateDepth         = 8
)

// Config holds tunable parameters for the MOLS engine.
// A zero value is not valid; use DefaultConfig.
type Config struct {
	Order                  int
	BaseM1, BaseM2         uint8
	VariantM1, VariantM2   uint8
	CongestionRTTThreshold time.Duration
	CVThreshold            float64
	FallbackRTTThreshold   time.Duration
	MinActiveNodes         int
	MaxActiveRelays        int
	CandidateDepth         int
}

// DefaultConfig returns a Config populated with package defaults.
func DefaultConfig() Config {
	return Config{
		Order:                  DefaultOrder,
		BaseM1:                 DefaultBaseM1,
		BaseM2:                 DefaultBaseM2,
		VariantM1:              DefaultVariantM1,
		VariantM2:              DefaultVariantM2,
		CongestionRTTThreshold: DefaultCongestionRTTThreshold,
		CVThreshold:            DefaultCVThreshold,
		FallbackRTTThreshold:   DefaultFallbackRTTThreshold,
		MinActiveNodes:         DefaultMinActiveNodes,
		MaxActiveRelays:        DefaultMaxActiveRelays,
		CandidateDepth:         DefaultCandidateDepth,
	}
}
