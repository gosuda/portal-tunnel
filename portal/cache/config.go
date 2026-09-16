package cache

import (
	"errors"
	"path/filepath"
	"strings"
	"time"
)

// Config is relay operator policy. Origins can only request a shorter TTL.
// Uploads and manifest checks have separately configured admission limits.
type Config struct {
	Enabled                                   bool
	Dir                                       string
	MaxBytes, MaxExposureBytes, MaxObjectSize int
	MaxTTL                                    time.Duration
	PopulationConcurrency, CheckConcurrency   int
}

func (cfg Config) Normalize(stateDir string) (Config, error) {
	if !cfg.Enabled {
		return cfg, nil
	}
	validSizes := cfg.MaxObjectSize > 0 && cfg.MaxObjectSize <= cfg.MaxExposureBytes && cfg.MaxExposureBytes <= cfg.MaxBytes
	validTTL := cfg.MaxTTL >= time.Second && cfg.MaxTTL <= 365*24*time.Hour
	validConcurrency := cfg.PopulationConcurrency >= 1 && cfg.PopulationConcurrency <= 32 && cfg.CheckConcurrency >= 1 && cfg.CheckConcurrency <= 32
	if !validSizes || !validTTL || !validConcurrency {
		return Config{}, errors.New("invalid relay cache limits: require 0 < object <= exposure <= total bytes, TTL 1s..8760h, and upload/check concurrency 1..32 each")
	}
	if strings.TrimSpace(cfg.Dir) == "" {
		cfg.Dir = filepath.Join(stateDir, "static-cache")
	}
	return cfg, nil
}
