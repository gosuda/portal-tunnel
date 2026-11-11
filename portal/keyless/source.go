package keyless

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	keylesstls "github.com/gosuda/keyless_tls/keyless"
	"github.com/gosuda/keyless_tls/keyless/t13server"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// relaySource acquires bootstrap material and binds its remote signer to the lease.
type relaySource struct {
	relayURL   string
	serverName string
	hostname   string
	headers    func() http.Header
}

func (c *relaySource) acquire(ctx context.Context) (*pinnedChain, error) {
	chain, err := relayChain(ctx, c.relayURL, c.serverName)
	if err != nil {
		return nil, err
	}
	return c.newPin(chain)
}

// fileSource owns reloadable operator-provided material. Errors never fall back.
type fileSource struct {
	certFile, keyFile, hostname, alternativeHostname string
}

func (s *fileSource) acquire() (*pinnedChain, error) {
	return loadLocalPin(s.certFile, s.keyFile, s.hostname, s.alternativeHostname)
}

func (c *relaySource) newPin(chainPEM []byte) (*pinnedChain, error) {
	if err := verifyCertificateHostname(chainPEM, c.hostname); err != nil {
		return nil, fmt.Errorf("keyless certificate does not cover %s: %w", c.hostname, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(chainPEM) {
		return nil, errKeylessPinnedRelayCertificateChainUnparsable
	}
	remoteSigner, err := keylesstls.NewRemoteSigner(keylesstls.RemoteSignerConfig{
		Endpoint:   c.relayURL,
		ServerName: c.serverName,
		KeyID:      types.KeylessRelayKeyID,
		RootCAPEM:  chainPEM,
		Headers:    c.headers,
	})
	if err != nil {
		return nil, fmt.Errorf("create keyless remote signer: %w", err)
	}
	server, err := t13server.NewServer(t13server.Config{
		CertPEM:          chainPEM,
		NextProtos:       []string{"http/1.1"},
		KeyID:            types.KeylessRelayKeyID,
		TranscriptSigner: remoteSigner,
	})
	if err != nil {
		_ = remoteSigner.Close()
		return nil, fmt.Errorf("create keyless tls server: %w", err)
	}
	leaf, _ := utils.ParseCertificatePEM(chainPEM)
	return &pinnedChain{chainPEM: chainPEM, server: server, pool: pool, signer: remoteSigner, leaf: leaf}, nil
}
