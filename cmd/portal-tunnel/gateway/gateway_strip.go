package gateway

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// NewStripRequestHeaders removes the listed client request headers, in any
// case or underscore spelling, before Portal processing. Host and other
// invalid names are rejected.
func NewStripRequestHeaders(next http.Handler, names []string) (http.Handler, error) {
	headers := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		canonical, err := canonicalStripName(name)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		headers = append(headers, canonical)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.DelHeaderSpellings(r.Header, headers...)
		next.ServeHTTP(w, r)
	}), nil
}

func canonicalStripName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", errStripRequestHeaderNameRequired
	}
	if !isValidHeaderName(trimmed) {
		return "", fmt.Errorf("invalid strip request header name %q", trimmed)
	}
	canonical := http.CanonicalHeaderKey(trimmed)
	switch canonical {
	case "Host":
		return "", errHostCannotStrippedGoStoresIt
	case "X-Forwarded-Proto":
		return "", errXForwardedProtoCannotStrippedRunhttp
	}
	return canonical, nil
}

func isValidHeaderName(name string) bool {
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		default:
			switch c {
			case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			default:
				return false
			}
		}
	}
	return true
}
