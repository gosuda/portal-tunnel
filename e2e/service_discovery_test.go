package e2e_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestServiceDiscoveryListsPublicServicesOfOneAddress(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	port := harnessPort(t, "127.0.0.1")
	base := "https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	stateDir := t.TempDir()
	server, err := portal.NewServer(portal.ServerConfig{PortalURL: base, StateDir: stateDir, SNIListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), SNIPort: port})
	if err != nil {
		t.Fatal(err)
	}
	api := http.NewServeMux()
	api.HandleFunc(types.PathServices, server.HandleServices)
	if err := server.Start(ctx, relayHandler(server, api)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopRelay(t, server) })
	owner, err := identity.Generate("blog")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"blog", "api", "secret"} {
		service := owner
		service.Name = name
		exposure, err := sdk.Expose(ctx, service, []string{base}, sdk.WithMetadata(types.LeaseMetadata{Hide: name == "secret"}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = exposure.Close() })
		readyCtx, stop := context.WithTimeout(ctx, 15*time.Second)
		_, err = exposure.WaitReady(readyCtx)
		stop()
		if err != nil {
			t.Fatal(err)
		}
	}
	client := relayControlClient(t, stateDir)
	for _, query := range []string{"", "?address=invalid", "?address=" + url.QueryEscape(owner.Address) + "&name=" + url.QueryEscape("!!!")} {
		invalid, err := client.Get(base + types.PathServices + query)
		if err != nil {
			t.Fatal(err)
		}
		invalid.Body.Close()
		if invalid.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid lookup %q status=%d", query, invalid.StatusCode)
		}
	}
	response, err := client.Get(base + types.PathServices + "?address=" + url.QueryEscape(owner.Address))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result types.APIEnvelope[types.ServiceDiscoveryResponse]
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !result.OK || result.Data.Partial || len(result.Data.Services) != 2 {
		t.Fatalf("public lookup: status=%d result=%+v", response.StatusCode, result)
	}
	if result.Data.Services[0].Name != "api" || result.Data.Services[1].Name != "blog" {
		t.Fatalf("services=%+v", result.Data.Services)
	}
	for _, service := range result.Data.Services {
		if len(service.Locations) != 1 || !service.Locations[0].CurrentRelay || service.Locations[0].Verification != "relay-reported" {
			t.Fatalf("locations=%+v", service.Locations)
		}
	}
}
