package portal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
)

const (
	defaultClaimTimeout          = 10 * time.Second
	defaultClientHelloWait       = 2 * time.Second
	defaultControlBodyLimit      = 4 << 20
	reverseOfferAdmissionWorkers = 16
	quicBackhaulPendingLimit     = 64
	quicBackhaulAuthTimeout      = 3 * time.Second
	quicBackhaulPerSourceLimit   = 4
	publicIngressLimit           = 1024
	publicInspectionLimit        = 128
)

// Serve runs the complete relay lifecycle around the composed handler: the
// relay's route table (see the relay package), admin API, and application
// routes all arrive as one handler.
func (s *Server) Serve(ctx context.Context, handler http.Handler) error {
	if err := s.start(ctx, handler); err != nil {
		return fmt.Errorf("start relay server: %w", err)
	}
	return s.Wait()
}

// Start starts the relay and returns after its listeners are ready. Serve is
// the normal lifecycle entry point; Start and Wait remain available to callers
// that need explicit lifecycle control.
func (s *Server) Start(ctx context.Context, handler http.Handler) error {
	return s.start(ctx, handler)
}

func (s *Server) installStartBundle(serverCtx context.Context, bundle serverStartBundle, cancel context.CancelFunc) {
	s.apiHandoff = &handoffListener{addr: bundle.sniListener.Addr(), conns: make(chan net.Conn), done: make(chan struct{})}
	s.sniListener = bundle.sniListener
	s.apiServer = bundle.apiServer
	s.apiTLSClose = bundle.apiCloser
	s.redirectListener = bundle.redirectListener
	s.redirectServer = bundle.redirectServer
	s.ingressCtx = serverCtx
	s.cancel = cancel
	s.group = bundle.group
	s.quicBackhaul = bundle.quicBackhaul
}

func (s *Server) start(ctx context.Context, apiHandler http.Handler) error {
	if s.group != nil {
		return errServerAlreadyStarted
	}
	cfg := s.config()
	cacheManager, cacheErr := cache.New(cfg.Cache, filepath.Join(cfg.StateDir, "static-cache"))
	if cacheErr != nil {
		log.Warn().Err(cacheErr).Msg("relay cache unavailable; using origin tunnels")
	}
	s.registry.cache = cacheManager
	apiTLS, err := s.prepareAPITLS(ctx)
	if err != nil {
		return err
	}
	serverCtx, cancel := context.WithCancel(ctx)
	started := false
	var bundle serverStartBundle
	defer func() {
		if started {
			return
		}
		cancel()
		s.abortStartBundle(ctx, bundle)
	}()
	collected, err := s.collectStartBundle(serverCtx, cfg, apiHandler, apiTLS)
	bundle = collected
	if err != nil {
		return err
	}
	s.installStartBundle(serverCtx, bundle, cancel)
	started = true
	s.serveStartListeners(bundle)
	s.serveStartBackground(serverCtx, bundle, cfg)
	s.emitStartLog(cfg)
	return nil
}

func (s *Server) runPublicIngress(ctx context.Context) error {
	for {
		conn, err := s.sniListener.Accept()
		switch {
		case err == nil:
			if !s.admitIngress(conn, true) {
				_ = conn.Close()
				continue
			}
			go s.servePublicIngressConn(ctx, conn)
		case errors.Is(err, net.ErrClosed):
			return nil
		default:
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("accept sni connection: %w", err)
		}
	}
}

func (s *Server) handleQUICBackhaulConn(ctx context.Context, conn *quic.Conn) {
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.CloseWithError(1, "backhaul authentication canceled")
		close(closed)
	})
	authenticated := false
	defer func() {
		if !authenticated && !stop() {
			<-closed
		}
	}()
	lease, ok := s.admitBackhaulLease(ctx, conn)
	if !ok {
		return
	}
	if !stop() {
		<-closed
		return
	}
	authenticated = true
	s.noteBackhaulConnected(conn, lease)
}
