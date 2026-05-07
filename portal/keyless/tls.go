package keyless

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"

	keylesstls "github.com/gosuda/keyless_tls/keyless"
)

type TLSMaterialConfig struct {
	Keyless                  *RemoteSignerConfig
	CertPEM                  []byte
	KeyPEM                   []byte
	EncryptedClientHelloKeys []tls.EncryptedClientHelloKey
}

type RemoteSignerConfig struct {
	Endpoint      string
	ServerName    string
	KeyID         string
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	RootCAPEM     []byte
}

func AttachToHTTPServer(server *http.Server, cfg TLSMaterialConfig) (io.Closer, error) {
	if server == nil {
		return nil, errors.New("http server is required")
	}
	if cfg.Keyless != nil {
		minVersion := tls.VersionTLS12
		if len(cfg.EncryptedClientHelloKeys) > 0 {
			minVersion = tls.VersionTLS13
		}
		remoteSigner, err := keylesstls.AttachToHTTPServer(server, keylesstls.HTTPServerAttachConfig{
			CertPEM: cfg.CertPEM,
			RemoteSigner: keylesstls.RemoteSignerConfig{
				Endpoint:      cfg.Keyless.Endpoint,
				ServerName:    cfg.Keyless.ServerName,
				KeyID:         cfg.Keyless.KeyID,
				ClientCertPEM: cfg.Keyless.ClientCertPEM,
				ClientKeyPEM:  cfg.Keyless.ClientKeyPEM,
				RootCAPEM:     cfg.Keyless.RootCAPEM,
			},
			NextProtos:               []string{"http/1.1"},
			MinTLSVersion:            uint16(minVersion),
			EncryptedClientHelloKeys: cfg.EncryptedClientHelloKeys,
		})
		if err != nil {
			return nil, err
		}
		return remoteSigner, nil
	}

	cert, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse api tls key pair: %w", err)
	}

	minVersion := tls.VersionTLS12
	if len(cfg.EncryptedClientHelloKeys) > 0 {
		minVersion = tls.VersionTLS13
	}
	server.TLSConfig = &tls.Config{
		MinVersion:               uint16(minVersion),
		NextProtos:               []string{"http/1.1"},
		Certificates:             []tls.Certificate{cert},
		EncryptedClientHelloKeys: cfg.EncryptedClientHelloKeys,
	}
	return nil, nil
}
