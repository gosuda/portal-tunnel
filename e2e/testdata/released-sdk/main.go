// This program is copied into an independent module by released_sdk_test.go.
// Its SDK and validation code come from the pinned release, never the checkout.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	id, err := identity.Generate(os.Args[3])
	if err != nil {
		return err
	}
	exposure, err := sdk.Expose(ctx, id, []string{os.Args[1]})
	if err != nil {
		return err
	}
	defer exposure.Close()
	go func() { _ = sdk.Proxy(ctx, exposure, os.Args[2]) }()
	ready, err := exposure.WaitReady(ctx)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		Release   string
		PublicURL string
		AliasURL  string
	}{types.ReleaseVersion, ready[0].PublicURL, ready[0].AliasURL}); err != nil {
		return err
	}
	// The parent closes stdin after checking renewal and relay restart recovery.
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		return err
	}
	return exposure.Close()
}
