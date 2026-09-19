package portal

import (
	"context"
	"errors"
	"fmt"

	ksigner "github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

const (
	tlsRecordHeaderLen          = 5
	tlsContentTypeHandshake     = 22
	tlsHandshakeTypeClientHello = 1
)

// helloSpanFromFirstRecord extracts the exact ClientHello handshake-message bytes.
func helloSpanFromFirstRecord(record []byte) ([]byte, error) {
	if len(record) < tlsRecordHeaderLen+4 {
		return nil, errors.New("first TLS record is too short for a client hello")
	}
	if record[0] != tlsContentTypeHandshake {
		return nil, errors.New("first TLS record is not a handshake record")
	}
	body := record[tlsRecordHeaderLen:]
	if body[0] != tlsHandshakeTypeClientHello {
		return nil, errors.New("first handshake message is not a client hello")
	}
	msgLen := int(body[1]&0x7f)<<16 | int(body[2])<<8 | int(body[3])
	if msgLen <= 0 || 4+msgLen > len(body) {
		return nil, errors.New("client hello handshake message is incomplete")
	}
	return body[:4+msgLen], nil
}

type signLeaseIDContextKey struct{}

func withSignLeaseID(ctx context.Context, leaseID string) context.Context {
	return context.WithValue(ctx, signLeaseIDContextKey{}, leaseID)
}

func signLeaseIDFromContext(ctx context.Context) string {
	leaseID, _ := ctx.Value(signLeaseIDContextKey{}).(string)
	return leaseID
}

// transcriptValidator connects authenticated API context to keyless binding policy.
func (s *Server) transcriptValidator() ksigner.TranscriptValidatorFunc {
	return func(ctx context.Context, req *signrpc.TranscriptSignRequest) error {
		leaseID := signLeaseIDFromContext(ctx)
		if leaseID == "" {
			return fmt.Errorf("%w: signing request is not bound to a verified lease", ksigner.ErrPermissionDenied)
		}
		return s.registry.bindings.ValidateAndConsume(req.Binding, leaseID, req.ClientHello)
	}
}
