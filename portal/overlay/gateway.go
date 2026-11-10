package overlay

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// IssueInput is the complete point-in-time state needed to issue an endpoint.
type IssueInput struct {
	LeaseIdentity types.Identity
	LeaseID       string
	ExpiresAt     time.Time
	FailedURL     string
	Self          types.RelayDescriptor
	Descriptors   []types.RelayDescriptor
}

// IssueEndpoint returns false when direct reverse transport should be used.
// Input carries the caller's current relay-state snapshot; FailedURL excludes
// a failed gateway when the SDK requests replacement.
func (r *Runtime) IssueEndpoint(input IssueInput) (types.ReverseEndpoint, bool, error) {
	if r == nil || !r.ready.Load() {
		return types.ReverseEndpoint{}, false, nil
	}
	now := time.Now().UTC()
	input.LeaseID = strings.TrimSpace(input.LeaseID)
	if input.LeaseID == "" || !input.ExpiresAt.After(now) {
		return types.ReverseEndpoint{}, false, errOverlayLeaseIsInvalid
	}
	ingress, ingressDestination, err := r.checkIssueEndpointIngress(input.Self)
	if err != nil {
		return types.ReverseEndpoint{}, false, err
	}

	candidates := r.gatewayCandidates(input.Descriptors, now, ingress.Address, ingressDestination)
	if len(candidates) == 0 {
		return types.ReverseEndpoint{}, false, nil
	}
	gateway, ok := r.selectGateway(input.LeaseID, input.FailedURL, candidates, now)
	if !ok {
		return types.ReverseEndpoint{}, false, nil
	}
	return r.assembleIssueEndpointResponse(input, ingress, gateway)
}

func (r *Runtime) gatewayCandidates(descriptors []types.RelayDescriptor, now time.Time, ingressAddress, ingressDestination string) []types.RelayDescriptor {
	var candidates []types.RelayDescriptor
	seenAddresses := make(map[string]struct{})
	seenDestinations := make(map[string]struct{})
	for _, candidate := range descriptors {
		verified, destination, ok := r.gatewayCandidatesVerify(candidate, now, ingressAddress, ingressDestination)
		if !ok {
			continue
		}
		addressKey := strings.ToLower(verified.Address)
		_, addrSeen := seenAddresses[addressKey]
		_, destSeen := seenDestinations[destination]
		if addrSeen || destSeen {
			continue
		}
		seenAddresses[addressKey] = struct{}{}
		seenDestinations[destination] = struct{}{}
		candidates = append(candidates, verified)
	}
	slices.SortFunc(candidates, gatewayCandidatesCompare)
	return candidates
}

func (r *Runtime) selectGateway(leaseID, failedURL string, candidates []types.RelayDescriptor, now time.Time) (types.RelayDescriptor, bool) {
	r.assignmentMu.Lock()
	defer r.assignmentMu.Unlock()
	failed := r.failures[leaseID]
	if failed == nil {
		failed = make(map[string]time.Time)
		r.failures[leaseID] = failed
	}
	selectGatewayPrune(failed, now)
	if origin := endpointOrigin(failedURL); origin != "" {
		failed[origin] = now.Add(gatewayRetryDelay)
	}
	candidates = slices.DeleteFunc(candidates, func(candidate types.RelayDescriptor) bool {
		_, rejected := failed[endpointOrigin(candidate.APIHTTPSAddr)]
		return rejected
	})
	if len(candidates) == 0 {
		delete(r.assignments, leaseID)
		return types.RelayDescriptor{}, false
	}
	return r.selectGatewayAssign(leaseID, failedURL, candidates)
}

func endpointOrigin(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host)
}

func (r *Runtime) checkIssueEndpointIngress(self types.RelayDescriptor) (types.RelayDescriptor, string, error) {
	ingress, err := discovery.VerifyRelayDescriptor(self)
	if err != nil {
		return types.RelayDescriptor{}, "", err
	}
	ingressDestination, err := normalizeIVNPDestination(ingress.IVNPDestination)
	if err != nil || ingressDestination != r.Destination() {
		return types.RelayDescriptor{}, "", errOverlayIngressDescriptorIsInvalid
	}
	return ingress, ingressDestination, nil
}

func (r *Runtime) assembleIssueEndpointResponse(input IssueInput, ingress types.RelayDescriptor, gateway types.RelayDescriptor) (types.ReverseEndpoint, bool, error) {
	capabilityExpiry := input.ExpiresAt.UTC()
	if ingress.ExpiresAt.Before(capabilityExpiry) {
		capabilityExpiry = ingress.ExpiresAt
	}
	if gateway.ExpiresAt.Before(capabilityExpiry) {
		capabilityExpiry = gateway.ExpiresAt
	}
	claims := capabilityClaims{
		Version:            1,
		LeaseIdentity:      input.LeaseIdentity,
		LeaseID:            input.LeaseID,
		ExpiresAt:          capabilityExpiry,
		Ingress:            ingress,
		GatewayAddress:     gateway.Address,
		GatewayDestination: gateway.IVNPDestination,
	}
	capability, err := signCapability(r.config.Authority, claims)
	if err != nil {
		return types.ReverseEndpoint{}, false, err
	}
	gatewayURL, err := url.Parse(gateway.APIHTTPSAddr)
	if err != nil {
		return types.ReverseEndpoint{}, false, err
	}
	return types.ReverseEndpoint{
		URL:        utils.ResolveAPIURL(gatewayURL, types.PathSDKConnect).String(),
		Capability: capability,
		ExpiresAt:  capabilityExpiry,
		Overlay:    true,
		Gateway:    &gateway,
	}, true, nil
}

func (r *Runtime) gatewayCandidatesVerify(candidate types.RelayDescriptor, now time.Time, ingressAddress, ingressDestination string) (types.RelayDescriptor, string, bool) {
	verified, err := discovery.VerifyRelayDescriptor(candidate)
	if err != nil || !verified.ExpiresAt.After(now.Add(minimumGatewayTTL)) || strings.EqualFold(verified.Address, ingressAddress) {
		return types.RelayDescriptor{}, "", false
	}
	destination, err := normalizeIVNPDestination(verified.IVNPDestination)
	if err != nil || destination != verified.IVNPDestination || destination == ingressDestination {
		return types.RelayDescriptor{}, "", false
	}
	return verified, destination, true
}

func gatewayCandidatesCompare(a, b types.RelayDescriptor) int {
	if a.ActiveConnections < b.ActiveConnections {
		return -1
	}
	if a.ActiveConnections > b.ActiveConnections {
		return 1
	}
	if a.TCPBPS < b.TCPBPS {
		return -1
	}
	if a.TCPBPS > b.TCPBPS {
		return 1
	}
	return strings.Compare(a.APIHTTPSAddr, b.APIHTTPSAddr)
}

func selectGatewayPrune(failed map[string]time.Time, now time.Time) {
	for origin, retryAt := range failed {
		if !retryAt.After(now) {
			delete(failed, origin)
		}
	}
}

func (r *Runtime) selectGatewayAssign(leaseID string, failedURL string, candidates []types.RelayDescriptor) (types.RelayDescriptor, bool) {
	current := r.assignments[leaseID]
	if failedURL == "" {
		for _, candidate := range candidates {
			if strings.EqualFold(candidate.Address, current) {
				return candidate, true
			}
		}
	}
	for _, candidate := range candidates {
		if strings.EqualFold(candidate.Address, current) {
			continue
		}
		r.assignments[leaseID] = candidate.Address
		return candidate, true
	}
	r.assignments[leaseID] = candidates[0].Address
	return candidates[0], true
}
