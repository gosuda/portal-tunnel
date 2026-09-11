// Command boundarycheck enforces the package ownership rule (#382):
//
//	portal -> internal, sdk -> internal
//	portal -X-> sdk, sdk -X-> portal, internal -X-> {portal, sdk}
//
// portal is the relay implementation, sdk is the public embeddable client,
// and internal holds the protocol machinery they share. They meet through
// internal/ and types/, never through each other's implementation packages.
// cmd/ and the module root are composition roots and are unconstrained.
//
// One audited exception: the x402 payment machinery lives under portal/ per
// the #382 layout while the sdk serves paywalled tunnel endpoints through
// it, so sdk may import portal/x402 and nothing else under portal/.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const modulePrefix = "github.com/gosuda/portal-tunnel/v2/"

// sdkAllowedPortalImport is the single exception to the sdk -X-> portal rule.
const sdkAllowedPortalImport = modulePrefix + "portal/x402"

func main() {
	out, err := exec.CommandContext(context.Background(), "go", "list", "-f", "{{.ImportPath}}\t{{join .Imports \" \"}}", "./...").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			fmt.Fprintf(os.Stderr, "boundarycheck: go list failed:\n%s", ee.Stderr)
		} else {
			fmt.Fprintf(os.Stderr, "boundarycheck: go list failed: %v\n", err)
		}
		os.Exit(1)
	}

	var violations []string
	for _, line := range strings.Split(string(bytes.TrimSpace(out)), "\n") {
		pkg, imports, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		for _, imp := range strings.Fields(imports) {
			if v := violation(pkg, imp); v != "" {
				violations = append(violations, v)
			}
		}
	}
	if len(violations) > 0 {
		fmt.Fprintf(os.Stderr, "boundarycheck: package ownership violations:\n")
		for _, v := range violations {
			fmt.Fprintf(os.Stderr, "  %s\n", v)
		}
		os.Exit(1)
	}
}

// area classifies a package path relative to the ownership rule.
func area(path string) string {
	switch {
	case path == modulePrefix+"portal" || strings.HasPrefix(path, modulePrefix+"portal/"):
		return "portal"
	case path == modulePrefix+"sdk" || strings.HasPrefix(path, modulePrefix+"sdk/"):
		return "sdk"
	case strings.HasPrefix(path, modulePrefix+"internal/"):
		return "internal"
	default:
		return ""
	}
}

func violation(pkg, imp string) string {
	from, to := area(pkg), area(imp)
	switch {
	case from == "" || to == "":
		return ""
	case from == "sdk" && to == "portal" && imp == sdkAllowedPortalImport:
		return ""
	case from == "sdk" && to == "portal":
		return fmt.Sprintf("sdk must not import portal (except %s): %s -> %s", sdkAllowedPortalImport, pkg, imp)
	case from == "portal" && to == "sdk":
		return fmt.Sprintf("portal must not import sdk: %s -> %s", pkg, imp)
	case from == "internal" && (to == "portal" || to == "sdk"):
		return fmt.Sprintf("internal must not import portal or sdk: %s -> %s", pkg, imp)
	default:
		return ""
	}
}
