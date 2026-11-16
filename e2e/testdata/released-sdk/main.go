// This program is copied into an independent module by released_sdk_test.go.
// Its SDK and validation code come from the pinned release, never the checkout.
package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	id, err := identity.Generate(os.Args[2])
	if err != nil {
		return err
	}
	exposure, err := sdk.Expose(ctx, id, []string{os.Args[1]})
	if err != nil {
		return err
	}
	defer exposure.Close()
	// These releases' WaitReady does not return terminal errors. Read their
	// public status instead of turning an incompatibility into a timeout.
	for {
		for _, status := range exposure.Relays() {
			if status.State != sdk.RelayReady && status.State != sdk.RelayFailed {
				continue
			}
			var message string
			if status.Err != nil {
				message = status.Err.Error()
			}
			return json.NewEncoder(os.Stdout).Encode(struct {
				Release         string
				ProtocolVersion string
				Error           string
				Terminal        bool
			}{
				Release:         types.ReleaseVersion,
				ProtocolVersion: types.SDKVersion,
				Error:           message,
				Terminal:        status.State == sdk.RelayFailed && status.Failure == sdk.RelayFailureTerminal,
			})
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exposure.Updates():
		}
	}
}
