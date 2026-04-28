package pepper

import (
	"errors"
	"fmt"
	"time"
)

const (
	Version1 uint8  = 0x01
	SuiteV1  uint16 = 0x0001
)

const (
	DefaultCellSize       = 1200
	DefaultPaths          = 4
	DefaultHopsPerPath    = 3
	DefaultErasureK       = 48
	DefaultErasureN       = 64
	DefaultBatchWindow    = 25 * time.Millisecond
	DefaultJitter         = 8 * time.Millisecond
	DefaultEpochDuration  = 1 * time.Second
	DefaultReplayWindow   = 120 * time.Second
	DefaultReplayMaxItems = 4096
)

type Mode string

const (
	ModeInteractive Mode = "interactive"
	ModeBalanced    Mode = "balanced"
	ModePrivate     Mode = "private"
)

type SuiteSpec struct {
	ID          uint16
	Version     uint8
	CellSize    int
	HeaderSize  int
	PayloadSize int
	KeySize     int
	NonceSize   int
}

var suiteV1Spec = SuiteSpec{
	ID:          SuiteV1,
	Version:     Version1,
	CellSize:    DefaultCellSize,
	HeaderSize:  CellHeaderSize,
	PayloadSize: CellPayloadSize,
	KeySize:     32,
	NonceSize:   12,
}

func SupportedSuites() map[uint16]SuiteSpec {
	return map[uint16]SuiteSpec{
		SuiteV1: suiteV1Spec,
	}
}

type Config struct {
	Enabled       bool
	Require       bool
	Mode          Mode
	Version       uint8
	SuiteID       uint16
	CellSize      int
	Paths         int
	HopsPerPath   int
	ErasureK      int
	ErasureN      int
	BatchWindow   time.Duration
	Jitter        time.Duration
	ReplayWindow  time.Duration
	EpochDuration time.Duration
}

func DefaultConfig() Config {
	return Config{
		Mode:          ModeBalanced,
		Version:       Version1,
		SuiteID:       SuiteV1,
		CellSize:      DefaultCellSize,
		Paths:         DefaultPaths,
		HopsPerPath:   DefaultHopsPerPath,
		ErasureK:      DefaultErasureK,
		ErasureN:      DefaultErasureN,
		BatchWindow:   DefaultBatchWindow,
		Jitter:        DefaultJitter,
		ReplayWindow:  DefaultReplayWindow,
		EpochDuration: DefaultEpochDuration,
	}
}

func (c Config) Normalize() Config {
	out := c
	def := DefaultConfig()
	if out.Mode == "" {
		out.Mode = def.Mode
	}
	if out.Version == 0 {
		out.Version = def.Version
	}
	if out.SuiteID == 0 {
		out.SuiteID = def.SuiteID
	}
	return out
}

func (c Config) Validate() error {
	cfg := c.Normalize()
	suite, ok := SupportedSuites()[cfg.SuiteID]
	if !ok {
		return fmt.Errorf("unsupported pepper suite: 0x%04x", cfg.SuiteID)
	}
	if cfg.Version != suite.Version {
		return fmt.Errorf("pepper version %d does not match suite version %d", cfg.Version, suite.Version)
	}
	if cfg.CellSize != suite.CellSize {
		return fmt.Errorf("invalid pepper cell size: got %d want %d", cfg.CellSize, suite.CellSize)
	}
	if cfg.Paths <= 0 {
		return errors.New("pepper path count must be greater than zero")
	}
	if cfg.HopsPerPath <= 0 {
		return errors.New("pepper hop count must be greater than zero")
	}
	if cfg.ErasureK <= 0 || cfg.ErasureN <= 0 {
		return errors.New("pepper erasure parameters must be greater than zero")
	}
	if cfg.ErasureK > cfg.ErasureN {
		return errors.New("pepper erasure threshold cannot exceed shard total")
	}
	if cfg.BatchWindow <= 0 {
		return errors.New("pepper batch window must be greater than zero")
	}
	if cfg.Jitter < 0 {
		return errors.New("pepper jitter cannot be negative")
	}
	if cfg.ReplayWindow <= 0 {
		return errors.New("pepper replay window must be greater than zero")
	}
	if cfg.EpochDuration <= 0 {
		return errors.New("pepper epoch duration must be greater than zero")
	}
	if cfg.Require && !cfg.Enabled {
		return errors.New("pepper require cannot be set when pepper is disabled")
	}
	return nil
}

func (c Config) ValidateAvailablePaths(available int) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if available < 0 {
		return errors.New("available path count cannot be negative")
	}
	cfg := c.Normalize()
	if cfg.Require && available < cfg.Paths {
		return fmt.Errorf("pepper requires %d paths but only %d are available", cfg.Paths, available)
	}
	return nil
}
