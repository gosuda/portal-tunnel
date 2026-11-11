package acme

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/lego"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// NormalizeCADirURL validates an optional ACME CA directory URL and defaults
// an empty value to Let's Encrypt production. Only HTTPS directories are
// accepted; it returns the canonical form used to name the CA's files.
func NormalizeCADirURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return lego.LEDirectoryProduction, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errACMECADirectoryURLMustValid, err)
	}
	if parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errACMECADirectoryURLMustValid
	}
	if parsed.Scheme != "https" {
		return "", errACMECADirectoryURLMustUse
	}
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String(), nil
}

func registrationFilePath(keyDir, caDirURL string) string {
	if caDirURL == lego.LEDirectoryProduction {
		return filepath.Join(keyDir, registrationFileName)
	}
	return filepath.Join(keyDir, "acme-registration-"+caDirectoryDigest(caDirURL)+".json")
}

func certificateFilePaths(keyDir, caDirURL string) (certFile, keyFile string) {
	if caDirURL == lego.LEDirectoryProduction {
		return filepath.Join(keyDir, fullChainFileName), filepath.Join(keyDir, keyFileName)
	}
	digest := caDirectoryDigest(caDirURL)
	return filepath.Join(keyDir, "fullchain-"+digest+".pem"), filepath.Join(keyDir, "privatekey-"+digest+".pem")
}

func caDirectoryDigest(caDirURL string) string {
	sum := sha256.Sum256([]byte(caDirURL))
	return fmt.Sprintf("%x", sum[:8])
}

func (m *Manager) certificateFiles() (certFile, keyFile string) {
	if utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return certificateFilePaths(m.cfg.KeyDir, lego.LEDirectoryProduction)
	}
	return certificateFilePaths(m.cfg.KeyDir, m.cfg.CADirURL)
}
