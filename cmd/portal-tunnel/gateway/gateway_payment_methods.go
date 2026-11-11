package gateway

import (
	"slices"
	"strings"
)

func NormalizePaymentMethods(methods []string) ([]string, error) {
	set := make(map[string]struct{}, len(methods))
	for _, raw := range methods {
		method := strings.ToUpper(strings.TrimSpace(raw))
		if method == "" {
			return nil, errX402PaymentMethodIsRequired
		}
		set[method] = struct{}{}
	}
	if len(set) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(set))
	for method := range set {
		out = append(out, method)
	}
	slices.Sort(out)
	return out, nil
}

func paymentMethodSet(methods []string) map[string]struct{} {
	set := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		set[method] = struct{}{}
	}
	return set
}
