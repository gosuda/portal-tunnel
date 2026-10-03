package tunnel

import (
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
)

func TestSpecValidateModes(t *testing.T) {
	tests := []struct {
		name  string
		spec  Spec
		valid bool
	}{
		{name: "raw target", spec: Spec{Transport: TransportSpec{Target: "localhost:3000"}}, valid: true},
		{name: "missing mode", spec: Spec{}},
		{name: "HTTP target", spec: Spec{Transport: TransportSpec{Target: "localhost:3000"}, HTTP: &HTTPConfig{}}, valid: true},
		{name: "HTTP route", spec: Spec{HTTP: &HTTPConfig{Routes: []HTTPRoute{{Prefix: "/", Upstream: "http://localhost:3000"}}}}, valid: true},
		{name: "static", spec: Spec{HTTP: &HTTPConfig{Serve: "./dist"}}, valid: true},
		{name: "HTTP with TCP", spec: Spec{Transport: TransportSpec{Target: "localhost:3000", TCP: true}, HTTP: &HTTPConfig{}}},
		{name: "HTTP with UDP", spec: Spec{Transport: TransportSpec{Target: "localhost:3000", UDP: &UDPConfig{}}, HTTP: &HTTPConfig{}}},
		{name: "target and route", spec: Spec{Transport: TransportSpec{Target: "localhost:3000"}, HTTP: &HTTPConfig{Routes: []HTTPRoute{{Prefix: "/", Upstream: "http://localhost:4000"}}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.spec.Validate(); (err == nil) != test.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, test.valid)
			}
		})
	}
}

func TestSpecValidateHTTPFeatures(t *testing.T) {
	base := func() Spec {
		return Spec{Transport: TransportSpec{Target: "localhost:3000"}, HTTP: &HTTPConfig{}}
	}
	tests := []struct {
		name  string
		edit  func(*Spec)
		valid bool
	}{
		{name: "siwe", edit: func(spec *Spec) { spec.HTTP.Auth = &gateway.ApplicationAuthConfig{Provider: "siwe"} }, valid: true},
		{name: "unknown auth", edit: func(spec *Spec) { spec.HTTP.Auth = &gateway.ApplicationAuthConfig{Provider: "unknown"} }},
		{name: "missing auth provider", edit: func(spec *Spec) { spec.HTTP.Auth = &gateway.ApplicationAuthConfig{IdentityHeaders: true} }},
		{name: "credential allowlist", edit: func(spec *Spec) {
			spec.HTTP.Auth = &gateway.ApplicationAuthConfig{Provider: "credential", AllowedWallets: []string{"wallet"}}
		}},
		{name: "paid route", edit: func(spec *Spec) {
			spec.Transport.Target = ""
			spec.HTTP.Payment.PayTo = "recipient"
			spec.HTTP.Routes = []HTTPRoute{{Prefix: "/paid", Upstream: "http://localhost:4000", Methods: []string{"GET"}, Amount: "1"}}
		}, valid: true},
		{name: "payment without recipient", edit: func(spec *Spec) {
			spec.Transport.Target = ""
			spec.HTTP.Routes = []HTTPRoute{{Prefix: "/paid", Upstream: "http://localhost:4000", Amount: "1"}}
		}},
		{name: "cache static", edit: func(spec *Spec) {
			spec.Transport.Target = ""
			spec.HTTP.Serve = "./dist"
			spec.HTTP.Cache = &CacheConfig{}
		}, valid: true},
		{name: "cache target", edit: func(spec *Spec) { spec.HTTP.Cache = &CacheConfig{} }},
		{name: "strip request headers", edit: func(spec *Spec) {
			spec.Transport.Target = ""
			spec.HTTP.Routes = []HTTPRoute{{Prefix: "/", Upstream: "http://localhost:4000"}}
			spec.HTTP.StripRequestHeaders = []string{"X-Tenant-User"}
		}, valid: true},
		{name: "strip request headers with auth target", edit: func(spec *Spec) {
			spec.HTTP.Auth = &gateway.ApplicationAuthConfig{Provider: "siwe"}
			spec.HTTP.StripRequestHeaders = []string{"X-Tenant-User"}
		}, valid: true},
		{name: "strip request headers on static", edit: func(spec *Spec) {
			spec.Transport.Target = ""
			spec.HTTP.Serve = "./dist"
			spec.HTTP.StripRequestHeaders = []string{"X-Tenant-User"}
		}},
		{name: "strip request headers on target only", edit: func(spec *Spec) {
			spec.HTTP.StripRequestHeaders = []string{"X-Tenant-User"}
		}, valid: true},
		{name: "strip Host", edit: func(spec *Spec) {
			spec.HTTP.StripRequestHeaders = []string{"Host"}
		}},
		{name: "strip X-Portal-User with auth identity headers", edit: func(spec *Spec) {
			spec.HTTP.Auth = &gateway.ApplicationAuthConfig{Provider: "siwe", IdentityHeaders: true}
			spec.HTTP.StripRequestHeaders = []string{"X-Portal-User"}
		}, valid: true},
		{name: "strip X-Portal-Auth without auth identity headers", edit: func(spec *Spec) {
			spec.HTTP.Auth = &gateway.ApplicationAuthConfig{Provider: "siwe"}
			spec.HTTP.StripRequestHeaders = []string{"X-Portal-Auth"}
		}, valid: true},
		{name: "invalid strip request header name", edit: func(spec *Spec) {
			spec.Transport.Target = ""
			spec.HTTP.Routes = []HTTPRoute{{Prefix: "/", Upstream: "http://localhost:4000"}}
			spec.HTTP.StripRequestHeaders = []string{"X Tenant"}
		}, valid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := base()
			test.edit(&spec)
			if err := spec.Validate(); (err == nil) != test.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, test.valid)
			}
		})
	}
}
