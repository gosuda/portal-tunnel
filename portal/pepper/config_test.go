package pepper

import "testing"

func TestConfigRejectsInvalidCellSizes(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.CellSize = 1400
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid cell size to fail")
	}
}

func TestConfigRejectsKGreaterThanN(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ErasureK = 65
	cfg.ErasureN = 64
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected k > n to fail")
	}
}

func TestConfigRejectsZeroPaths(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Paths = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected zero paths to fail")
	}
}

func TestConfigRejectsRequiredModeWhenPathsInsufficient(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Require = true
	cfg.Paths = 4
	if err := cfg.ValidateAvailablePaths(3); err == nil {
		t.Fatal("expected insufficient available paths to fail")
	}
}
