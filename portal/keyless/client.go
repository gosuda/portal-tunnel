package keyless

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	keylesstls "github.com/gosuda/keyless_tls/keyless"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func BuildClientTLSConfig(relayURL, hostname string, echKeys []tls.EncryptedClientHelloKey, headers func() http.Header) (*tls.Config, ioCloser, error) {
	normalizedRelayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return nil, nil, err
	}

	parsed, err := url.Parse(normalizedRelayURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse relay url: %w", err)
	}
	serverName := parsed.Hostname()
	if serverName == "" {
		return nil, nil, errors.New("relay hostname is required")
	}

	certPEM, rootCAPEM, err := ResolveMaterials(context.Background(), normalizedRelayURL, serverName)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare keyless materials: %w", err)
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return nil, nil, errors.New("keyless hostname is required")
	}
	if verifyErr := VerifyCertificateHostname(certPEM, hostname); verifyErr != nil {
		return nil, nil, fmt.Errorf("keyless certificate does not cover %s: %w", hostname, verifyErr)
	}

	remoteSigner, err := keylesstls.NewRemoteSigner(keylesstls.RemoteSignerConfig{
		Endpoint:   normalizedRelayURL,
		ServerName: serverName,
		KeyID:      RelayKeyID,
		RootCAPEM:  rootCAPEM,
		Headers:    headers,
	}, certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("create keyless remote signer: %w", err)
	}

	tlsConfig, err := keylesstls.NewServerTLSConfig(keylesstls.ServerTLSConfig{
		CertPEM:                  certPEM,
		Signer:                   newVerifyingSigner(remoteSigner),
		NextProtos:               []string{"http/1.1"},
		MinVersion:               MinTLSVersion(len(echKeys) > 0),
		EncryptedClientHelloKeys: echKeys,
	})
	if err != nil {
		_ = remoteSigner.Close()
		return nil, nil, fmt.Errorf("create keyless tls config: %w", err)
	}
	return tlsConfig, remoteSigner, nil
}

type ioCloser interface {
	Close() error
}

func ResolveMaterials(ctx context.Context, endpoint, serverName string) ([]byte, []byte, error) {
	chainPEM, err := utils.FetchEndpointCertificateChain(ctx, endpoint, serverName)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch signer certificate chain: %w", err)
	}
	if len(chainPEM) == 0 {
		return nil, nil, errors.New("keyless certificate chain is required")
	}
	return bytes.Clone(chainPEM), bytes.Clone(chainPEM), nil
}

func VerifyCertificateHostname(certPEM []byte, hostname string) error {
	leaf, err := utils.ParseCertificatePEM(certPEM)
	if err != nil {
		return err
	}
	return leaf.VerifyHostname(hostname)
}

// verifyingSigner checks every remote signature against the public key pinned
// from the relay's served certificate before handing it to crypto/tls. A
// terminating proxy that presents one keypair while the relay signer holds
// another otherwise surfaces only as an opaque TLS "bad signature" alert.
type verifyingSigner struct {
	inner      *keylesstls.RemoteSigner
	warnedOnce sync.Once
}

func newVerifyingSigner(inner *keylesstls.RemoteSigner) *verifyingSigner {
	return &verifyingSigner{inner: inner}
}

func (v *verifyingSigner) Public() crypto.PublicKey { return v.inner.Public() }

func (v *verifyingSigner) Close() error { return v.inner.Close() }

func (v *verifyingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := v.inner.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(v.inner.Public(), digest, opts, signature); err != nil {
		v.warnedOnce.Do(func() {
			log.Warn().
				Err(err).
				Msg("relay keyless signature does not match the pinned certificate; tenant TLS handshakes will keep failing until the relay's terminating proxy and signer share one keypair")
		})
		return nil, fmt.Errorf("relay signature does not match the pinned certificate (terminating proxy and relay signer keypairs differ): %w", err)
	}
	return signature, nil
}

func verifySignature(publicKey crypto.PublicKey, digest []byte, opts crypto.SignerOpts, signature []byte) error {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			return rsa.VerifyPSS(key, opts.HashFunc(), digest, signature, pss)
		}
		return rsa.VerifyPKCS1v15(key, opts.HashFunc(), digest, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, signature) {
			return errors.New("ecdsa signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported pinned key type %T", publicKey)
	}
}
