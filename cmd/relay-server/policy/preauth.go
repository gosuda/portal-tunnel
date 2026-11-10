package policy

import "fmt"

// PreAuthConfig configures the relay's pre-auth request budgets and endpoint costs.
type PreAuthConfig struct {
	SourcePerMinute int
	SourceBurst     int
	GlobalPerMinute int
	GlobalBurst     int
	ChallengeCost   int
	AnnounceCost    int
	RegisterCost    int
}

func DefaultPreAuthConfig() PreAuthConfig {
	return PreAuthConfig{SourcePerMinute: 10, SourceBurst: 100, GlobalPerMinute: 600, GlobalBurst: 200, ChallengeCost: 1, AnnounceCost: 2, RegisterCost: 5}
}

func NormalizePreAuthConfig(c *PreAuthConfig) error {
	defaults := DefaultPreAuthConfig()
	for _, field := range []struct {
		value    *int
		fallback int
	}{
		{&c.SourcePerMinute, defaults.SourcePerMinute}, {&c.SourceBurst, defaults.SourceBurst},
		{&c.GlobalPerMinute, defaults.GlobalPerMinute}, {&c.GlobalBurst, defaults.GlobalBurst},
		{&c.ChallengeCost, defaults.ChallengeCost}, {&c.AnnounceCost, defaults.AnnounceCost}, {&c.RegisterCost, defaults.RegisterCost},
	} {
		if *field.value < 0 {
			return fmt.Errorf("pre-auth limits and weights must be positive")
		}
		if *field.value == 0 {
			*field.value = field.fallback
		}
	}
	if weight := max(c.ChallengeCost, c.AnnounceCost, c.RegisterCost); weight > c.SourceBurst || weight > c.GlobalBurst {
		return fmt.Errorf("pre-auth burst budgets must cover every endpoint weight")
	}
	return nil
}
