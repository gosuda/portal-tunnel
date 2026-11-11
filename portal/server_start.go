package portal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

type serverStartBundle struct {
	sniListener      net.Listener
	apiServer        *http.Server
	apiCloser        io.Closer
	redirectListener net.Listener
	redirectServer   *http.Server
	quicBackhaul     *quic.Listener
	group            *errgroup.Group
	groupCtx         context.Context
}

func (s *Server) buildRedirectServerStart(serverCtx context.Context, cfg ServerConfig) (net.Listener, *http.Server, error) {
	if !cfg.HTTPRedirect.Enabled {
		return nil, nil, nil
	}
	var listenConfig net.ListenConfig
	redirectListener, err := listenConfig.Listen(serverCtx, "tcp", cfg.HTTPRedirect.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen http redirect: %w", err)
	}
	redirectServer := &http.Server{
		DisableGeneralOptionsHandler: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.HTTPRedirect.HSTS {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			}
			http.Redirect(w, r, cfg.PortalURL, http.StatusMovedPermanently)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return redirectListener, redirectServer, nil
}

func (s *Server) buildQUICBackhaulStart(apiTLS *tls.Config) (*quic.Listener, error) {
	udpEnabled, _ := s.registry.udpPolicy()
	if !udpEnabled {
		return nil, nil
	}
	quicBackhaul, err := s.newQUICBackhaulListener(apiTLS)
	if err != nil {
		return nil, fmt.Errorf("listen quic backhaul: %w", err)
	}
	return quicBackhaul, nil
}

func (s *Server) enterOverlayStart(serverCtx context.Context) error {
	if s.overlay == nil {
		return nil
	}
	if err := s.overlay.Start(serverCtx); err != nil {
		return fmt.Errorf("start relay overlay: %w", err)
	}
	return nil
}

func (s *Server) fillBundleFrontListeners(serverCtx context.Context, cfg ServerConfig, apiHandler http.Handler, apiTLS *tls.Config, bundle *serverStartBundle) error {
	var listenConfig net.ListenConfig
	sniListener, err := listenConfig.Listen(serverCtx, "tcp", cfg.SNIListenAddr)
	if err != nil {
		return fmt.Errorf("listen sni: %w", err)
	}
	bundle.sniListener = sniListener
	bundle.group, bundle.groupCtx = errgroup.WithContext(serverCtx)
	apiServer, apiCloser, err := s.newAPIServer(apiHandler, apiTLS)
	if err != nil {
		return err
	}
	bundle.apiServer = apiServer
	bundle.apiCloser = apiCloser
	return nil
}

func (s *Server) fillBundleBackListeners(serverCtx context.Context, cfg ServerConfig, apiTLS *tls.Config, bundle *serverStartBundle) error {
	redirectListener, redirectServer, err := s.buildRedirectServerStart(serverCtx, cfg)
	if err != nil {
		return err
	}
	bundle.redirectListener = redirectListener
	bundle.redirectServer = redirectServer
	quicBackhaul, err := s.buildQUICBackhaulStart(apiTLS)
	if err != nil {
		return err
	}
	bundle.quicBackhaul = quicBackhaul
	if err := s.enterOverlayStart(serverCtx); err != nil {
		return err
	}
	return nil
}

func (s *Server) collectStartBundle(serverCtx context.Context, cfg ServerConfig, apiHandler http.Handler, apiTLS *tls.Config) (serverStartBundle, error) {
	var bundle serverStartBundle
	if err := s.fillBundleFrontListeners(serverCtx, cfg, apiHandler, apiTLS, &bundle); err != nil {
		return bundle, err
	}
	if err := s.fillBundleBackListeners(serverCtx, cfg, apiTLS, &bundle); err != nil {
		return bundle, err
	}
	return bundle, nil
}

func (s *Server) abortStartBundle(ctx context.Context, bundle serverStartBundle) {
	if s.overlay != nil {
		s.overlay.Close()
	}
	_ = s.acmeManager.Stop(ctx)
	if bundle.apiServer != nil {
		_ = bundle.apiServer.Close()
	}
	if bundle.redirectServer != nil {
		_ = bundle.redirectServer.Close()
	}
	if bundle.redirectListener != nil {
		_ = bundle.redirectListener.Close()
	}
	if bundle.quicBackhaul != nil {
		_ = bundle.quicBackhaul.Close()
	}
	if bundle.apiCloser != nil {
		_ = bundle.apiCloser.Close()
	}
	if bundle.sniListener != nil {
		_ = bundle.sniListener.Close()
	}
}

func (s *Server) serveStartListeners(bundle serverStartBundle) {
	bundle.group.Go(func() error {
		err := s.apiServer.Serve(tls.NewListener(s.apiHandoff, s.apiServer.TLSConfig))
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	})
	if s.redirectServer != nil {
		bundle.group.Go(func() error {
			err := s.redirectServer.Serve(s.redirectListener)
			if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		})
	}
	bundle.group.Go(func() error { return s.runPublicIngress(bundle.groupCtx) })
	if s.quicBackhaul != nil {
		s.quicBackhaulDone = make(chan struct{})
		bundle.group.Go(func() error {
			defer close(s.quicBackhaulDone)
			return s.runQUICBackhaulListener(bundle.groupCtx)
		})
	}
}

func (s *Server) serveStartBackground(serverCtx context.Context, bundle serverStartBundle, cfg ServerConfig) {
	bundle.group.Go(func() error { return s.runRegistryJanitor(bundle.groupCtx, 5*time.Second) })
	if s.registry.cache != nil {
		bundle.group.Go(func() error { return s.registry.cache.Run(bundle.groupCtx) })
	}
	if cfg.DiscoveryEnabled {
		bundle.group.Go(func() error { return s.runRelayDiscoveryLoop(bundle.groupCtx) })
	}
	if s.overlay != nil {
		s.serveStartOverlay(bundle)
	}
	s.acmeManager.Start(serverCtx)
	bundle.group.Go(func() error {
		<-bundle.groupCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		return s.Shutdown(shutdownCtx)
	})
}

func (s *Server) serveStartOverlay(bundle serverStartBundle) {
	bundle.group.Go(func() error {
		if err := s.overlay.Run(bundle.groupCtx); err != nil && bundle.groupCtx.Err() == nil {
			log.Error().Err(err).Msg("relay overlay stopped; direct reverse transport remains available")
			s.overlay.Close()
		}
		return nil
	})
	for range reverseOfferAdmissionWorkers {
		bundle.group.Go(func() error {
			for {
				select {
				case <-bundle.groupCtx.Done():
					return nil
				case offer := <-s.overlay.ReverseOffers():
					s.admitReverseOffer(offer)
				}
			}
		})
	}
}

func (s *Server) emitStartLog(cfg ServerConfig) {
	logEvent := log.Info().
		Str("sni_addr", s.sniListener.Addr().String()).
		Str("root_host", s.identity.Name).
		Str("acme_dns_provider", cfg.ACME.DNSProvider).
		Int("min_port", cfg.MinPort).
		Int("max_port", cfg.MaxPort).
		Bool("discovery_enabled", cfg.DiscoveryEnabled).
		Bool("udp_enabled", s.quicBackhaul != nil).
		Bool("tcp_enabled", s.supportsTCP())
	if s.redirectListener != nil {
		logEvent = logEvent.Str("http_redirect_addr", s.redirectListener.Addr().String())
	}
	if s.quicBackhaul != nil {
		logEvent = logEvent.Str("internal_quic_backhaul_addr", s.quicBackhaul.Addr().String())
	}
	logEvent.Msg("relay server started")
}
