package cache

import (
	"errors"
	"time"
)

// Config is operator policy. Tenant fairness and request admission are internal
// cache responsibilities; origins can only request a shorter offline TTL.
type Config struct {
	Enabled  bool
	MaxBytes int
	MaxTTL   time.Duration
}

func (cfg Config) Validate() error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.MaxBytes <= 0 {
		return errors.New("cache total bytes must be positive")
	}
	if cfg.MaxTTL < time.Second || cfg.MaxTTL > 365*24*time.Hour {
		return errors.New("cache offline TTL must be between 1s and 8760h")
	}
	return nil
}
