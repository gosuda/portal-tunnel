package keyless

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

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

	if err := verifyRemoteSigner(remoteSigner, remoteSigner.Public()); err != nil {
		_ = remoteSigner.Close()
		return nil, nil, fmt.Errorf("keyless signer self-test against %s failed: %w", serverName, err)
	}

	tlsConfig, err := keylesstls.NewServerTLSConfig(keylesstls.ServerTLSConfig{
		CertPEM:                  certPEM,
		Signer:                   remoteSigner,
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

// verifyRemoteSigner probes signer with a one-off random challenge and checks
// the returned signature against pinned, the public key of the certificate the
// relay served. The #377 failure mode — a terminating proxy presenting
// certificate A while the relay's keyless signer holds keypair B — otherwise
// surfaces only as an opaque TLS "bad signature" alert on every tenant
// handshake. One probe at configuration time turns it into an actionable
// startup error; healthy deployments pay a single extra /v1/sign round trip.
func verifyRemoteSigner(signer crypto.Signer, pinned crypto.PublicKey) error {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("generate self-test challenge: %w", err)
	}
	digest := sha256.Sum256(challenge)

	// RSA keys probe with RSA-PSS / SHA-256 — the CertificateVerify scheme
	// TLS 1.3 uses and the salt length the relay signer applies — and ECDSA
	// keys with ECDSA / SHA-256. Other key types are rejected by the /v1/sign
	// protocol itself.
	var opts crypto.SignerOpts
	switch pinned.(type) {
	case *rsa.PublicKey:
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	case *ecdsa.PublicKey:
		opts = crypto.SHA256
	default:
		return fmt.Errorf("unsupported pinned key type %T", pinned)
	}

	signature, err := signer.Sign(rand.Reader, digest[:], opts)
	if err != nil {
		return fmt.Errorf("sign self-test challenge: %w", err)
	}
	if err := verifySignature(pinned, digest[:], opts, signature); err != nil {
		return fmt.Errorf("self-test signature does not match the pinned certificate (terminating proxy and relay signer keypairs differ; tenant TLS cannot succeed until they share one keypair): %w", err)
	}
	return nil
}

// verifySignature checks a signature made for digest under opts against
// publicKey, preserving RSA-PSS salt options.
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
