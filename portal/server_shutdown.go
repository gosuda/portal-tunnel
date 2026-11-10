package portal

import (
	"context"
)

func (s *Server) haltRelayTransports(ctx context.Context) []*leaseRecord {
	if s.cancel != nil {
		s.cancel()
	}
	s.closeIngress()
	if s.overlay != nil {
		s.overlay.Close()
	}
	if s.quicBackhaul != nil {
		_ = s.quicBackhaul.Close()
	}
	if s.quicBackhaulDone != nil {
		<-s.quicBackhaulDone
	}
	records := s.registry.CloseAll()
	s.ingressWorkers.Wait()
	return records
}

func (s *Server) deleteHaltedLeaseDNS(ctx context.Context, records []*leaseRecord) {
	for _, record := range records {
		s.deleteLeaseDNS(ctx, record)
	}
}

func (s *Server) closeRelayServers(ctx context.Context) error {
	var firstErr error
	if s.apiHandoff != nil {
		_ = s.apiHandoff.Close()
	}
	if err := s.closeSNIServer(); err != nil && firstErr == nil {
		firstErr = err
	}
	if s.apiServer != nil {
		if err := s.apiServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := s.shutdownRedirectServer(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	if s.apiTLSClose != nil {
		_ = s.apiTLSClose.Close()
	}
	return firstErr
}
