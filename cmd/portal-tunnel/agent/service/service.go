package service

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const defaultConfigFilename = "config.toml"

type Definition struct {
	Name        string
	DisplayName string
	Description string
	Executable  string
	Args        []string
	WorkingDir  string
}

func DefaultConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(windowsProgramDataDir(), "Portal Tunnel", "Agent", defaultConfigFilename)
	case "darwin":
		if os.Geteuid() == 0 {
			return filepath.Join(string(filepath.Separator), "Library", "Application Support", "Portal Tunnel", "Agent", defaultConfigFilename)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(".", "Library", "Application Support", "Portal Tunnel", "Agent", defaultConfigFilename)
		}
		return filepath.Join(home, "Library", "Application Support", "Portal Tunnel", "Agent", defaultConfigFilename)
	default:
		if os.Geteuid() == 0 {
			return filepath.Join(string(filepath.Separator), "etc", "portal-tunnel", "agent", defaultConfigFilename)
		}
		configHome := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
		if configHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return filepath.Join(".", ".config", "portal-tunnel", "agent", defaultConfigFilename)
			}
			configHome = filepath.Join(home, ".config")
		}
		return filepath.Join(configHome, "portal-tunnel", "agent", defaultConfigFilename)
	}
}

func DefaultDataDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(windowsProgramDataDir(), "Portal Tunnel", "Agent")
	case "darwin":
		if os.Geteuid() == 0 {
			return filepath.Join(string(filepath.Separator), "Library", "Application Support", "Portal Tunnel", "Agent")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(".", "Library", "Application Support", "Portal Tunnel", "Agent")
		}
		return filepath.Join(home, "Library", "Application Support", "Portal Tunnel", "Agent")
	default:
		if os.Geteuid() == 0 {
			return filepath.Join(string(filepath.Separator), "var", "lib", "portal-tunnel", "agent")
		}
		dataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
		if dataHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return filepath.Join(".", ".local", "share", "portal-tunnel", "agent")
			}
			dataHome = filepath.Join(home, ".local", "share")
		}
		return filepath.Join(dataHome, "portal-tunnel", "agent")
	}
}

func windowsProgramDataDir() string {
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData == "" {
		return `C:\ProgramData`
	}
	return programData
}
