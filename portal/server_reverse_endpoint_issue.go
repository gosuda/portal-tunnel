package portal

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func (s *Server) overlayIssueDescriptors(now time.Time) (types.RelayDescriptor, []types.RelayDescriptor, error) {
	if s.overlay == nil || s.relaySet == nil {
		return types.RelayDescriptor{}, nil, nil
	}
	self, err := s.newSelfDescriptor(now)
	if err != nil {
		return types.RelayDescriptor{}, nil, fmt.Errorf("build self overlay descriptor: %w", err)
	}
	return self, s.relaySet.Descriptors(types.RelayDescriptor{}), nil
}

func (s *Server) issueReverseEndpoint(input reverseEndpointInput) (types.ReverseEndpoint, error) {
	var self types.RelayDescriptor
	var descriptors []types.RelayDescriptor
	if input.useOverlay {
		var err error
		self, descriptors, err = s.overlayIssueDescriptors(time.Now().UTC())
		if err != nil {
			log.Warn().Err(err).Str("lease", input.leaseIdentity.Key()).Msg("relay overlay descriptors unavailable; using direct reverse transport")
			input.useOverlay = false
		}
	}
	endpoint, err := s.registry.issueReverseEndpoint(input, self, descriptors)
	if err != nil {
		if errors.Is(err, errUnauthorized) || errors.Is(err, errLeaseNotFound) {
			return types.ReverseEndpoint{}, err
		}
		return types.ReverseEndpoint{}, &apiError{types.APIErrorCodeInternal, err.Error(), http.StatusInternalServerError}
	}
	return endpoint, nil
}
