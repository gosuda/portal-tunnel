//go:build js && wasm

// Command wasm exposes the Portal HTTPS connector to the relay frontend.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"syscall/js"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

type browserConnector struct {
	mu       sync.Mutex
	cancel   context.CancelFunc
	exposure *sdk.Exposure
}

func main() {
	connector := &browserConnector{}
	start := js.FuncOf(connector.start)
	stop := js.FuncOf(connector.stop)
	js.Global().Set("portalTunnel", map[string]any{
		"start": start,
		"stop":  stop,
	})
	select {}
}

func (c *browserConnector) start(_ js.Value, args []js.Value) any {
	return promise(func() (any, error) {
		if len(args) != 1 || args[0].Type() != js.TypeObject {
			return nil, errors.New("browser tunnel options are required")
		}
		options := args[0]
		name := strings.TrimSpace(jsString(options.Get("name")))
		relayURL := strings.TrimSpace(jsString(options.Get("relayURL")))
		body := jsString(options.Get("body"))
		if relayURL == "" {
			return nil, errors.New("relay URL is required")
		}

		id, err := identity.Generate(name)
		if err != nil {
			return nil, fmt.Errorf("generate browser identity: %w", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		exposure, err := sdk.Expose(ctx, id, []string{relayURL})
		if err != nil {
			cancel()
			return nil, err
		}

		c.mu.Lock()
		previousCancel := c.cancel
		previousExposure := c.exposure
		c.cancel = cancel
		c.exposure = exposure
		c.mu.Unlock()
		if previousCancel != nil {
			previousCancel()
		}
		if previousExposure != nil {
			_ = previousExposure.Close()
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte(body))
		})
		go func() {
			_ = sdk.RunHTTP(ctx, exposure, handler, "")
		}()

		ready, err := exposure.WaitReady(ctx)
		if err != nil {
			c.clear(exposure)
			return nil, err
		}
		if len(ready) == 0 || ready[0].PublicURL == "" {
			c.clear(exposure)
			return nil, errors.New("relay did not return a public URL")
		}
		return map[string]any{"publicURL": ready[0].PublicURL}, nil
	})
}

func (c *browserConnector) stop(_ js.Value, _ []js.Value) any {
	return promise(func() (any, error) {
		c.mu.Lock()
		cancel := c.cancel
		exposure := c.exposure
		c.cancel = nil
		c.exposure = nil
		c.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if exposure != nil {
			return nil, exposure.Close()
		}
		return nil, nil
	})
}

func (c *browserConnector) clear(exposure *sdk.Exposure) {
	c.mu.Lock()
	var cancel context.CancelFunc
	if c.exposure == exposure {
		cancel = c.cancel
		c.cancel = nil
		c.exposure = nil
	}
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	_ = exposure.Close()
}

func promise(run func() (any, error)) js.Value {
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			value, err := run()
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			resolve.Invoke(js.ValueOf(value))
		}()
		return nil
	})
	p := js.Global().Get("Promise").New(executor)
	executor.Release()
	return p
}

func jsString(v js.Value) string {
	if v.Type() == js.TypeString {
		return v.String()
	}
	return ""
}
