package installer

import (
	_ "embed"
	"errors"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

//go:embed install.sh
var installShellScript string

//go:embed install.ps1
var installPowerShellScript string

func RelayScript(portalURL string, isWindows bool) (script, filename, contentType string, err error) {
	portalURL = strings.TrimSpace(portalURL)
	if portalURL == "" {
		return "", "", "", errors.New("portal url is required")
	}

	script, filename, contentType = scriptFor(isWindows)
	if isWindows {
		return relayPowerShellScript(portalURL, script), filename, contentType, nil
	}
	return relayShellScript(portalURL, script), filename, contentType, nil
}

func scriptFor(isWindows bool) (script, filename, contentType string) {
	if isWindows {
		return installPowerShellScript, "install.ps1", "text/plain; charset=utf-8"
	}
	return installShellScript, "install.sh", "text/x-shellscript"
}

func AssetFilename(slug string) (string, bool) {
	switch strings.TrimSpace(slug) {
	case "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64":
		return "portal-" + slug, true
	case "windows-amd64", "windows-arm64":
		return "portal-" + slug + ".exe", true
	default:
		return "", false
	}
}

func relayShellScript(portalURL, script string) string {
	overrides := strings.Join([]string{
		"BASE_URL=" + quoteShellValue(portalURL),
		"RELAY_URL=" + quoteShellValue(portalURL),
		"BIN_PATH_PREFIX=" + quoteShellValue(strings.Trim(types.PathInstallBinPrefix, "/")),
		"",
	}, "\n")
	return insertAfterShebang(script, overrides)
}

func relayPowerShellScript(portalURL, script string) string {
	overrides := strings.Join([]string{
		"$env:BASE_URL = " + quotePowerShellValue(portalURL),
		"$env:RELAY_URL = " + quotePowerShellValue(portalURL),
		"$env:BIN_PATH_PREFIX = " + quotePowerShellValue(strings.Trim(types.PathInstallBinPrefix, "/")),
		"",
	}, "\n")
	return overrides + script
}

func insertAfterShebang(script, prefix string) string {
	if strings.HasPrefix(script, "#!") {
		if newline := strings.IndexByte(script, '\n'); newline >= 0 {
			return script[:newline+1] + prefix + script[newline+1:]
		}
	}
	return prefix + script
}

func quoteShellValue(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\"'\"'`) + "'"
}

func quotePowerShellValue(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
