package transport

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"time"

	"gosuda.org/ivnp"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// IVNPPeerDestination reads public identity authenticated by IVNP Streaming.
// A socket address alone is not evidence of an authenticated destination.
func IVNPPeerDestination(conn net.Conn) (string, error) {
	peer, ok := conn.(interface{ RemoteDestination() []byte })
	if !ok {
		return "", errors.New("ivnp connection lacks authenticated destination metadata")
	}
	encoded := peer.RemoteDestination()
	if len(encoded) == 0 || len(encoded) > 4096 {
		return "", errors.New("invalid ivnp peer destination metadata")
	}
	raw, err := ivnp.DecodeI2PBase64(encoded)
	if err != nil {
		return "", err
	}
	return ivnp.B32(sha256.Sum256(raw)), nil
}

// DialIVNP reaches one destination and checks the authenticated peer against
// that target. Portal admission remains the caller's discovery responsibility.
func DialIVNP(ctx context.Context, endpoint ivnp.DestinationEndpoint, destination string, port string) (net.Conn, error) {
	if endpoint == nil {
		return nil, errors.New("ivnp destination endpoint is required")
	}
	destination, err := utils.NormalizeIVNPDestination(destination)
	if err != nil {
		return nil, err
	}
	conn, err := endpoint.DialI2P(ctx, net.JoinHostPort(destination, port))
	if err != nil {
		return nil, err
	}
	peer, err := IVNPPeerDestination(conn)
	if err != nil || peer != destination {
		_ = conn.SetDeadline(time.Now())
		_ = conn.Close()
		return nil, errors.New("ivnp authenticated peer does not match dial target")
	}
	return conn, nil
}
