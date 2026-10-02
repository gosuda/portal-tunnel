package main

import (
	"reflect"
	"testing"
	"time"
)

func TestNormalizeExposeAuthArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{name: "bare", in: []string{"3000", "--auth"}, want: []string{"3000", "--auth=siwe"}},
		{name: "siwe", in: []string{"--auth", "siwe", "3000"}, want: []string{"--auth=siwe", "3000"}},
		{name: "token", in: []string{"3000", "--auth", "token"}, want: []string{"3000", "--auth=token"}},
		{name: "inline", in: []string{"3000", "--auth=token"}, want: []string{"3000", "--auth=token"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeExposeAuthArgs(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v; want %#v", got, tc.want)
			}
		})
	}
}

func TestParseCredentialLifetimeDays(t *testing.T) {
	got, err := parseCredentialLifetime("30d")
	if err != nil || got != 30*24*time.Hour {
		t.Fatalf("got %v, %v", got, err)
	}
}
