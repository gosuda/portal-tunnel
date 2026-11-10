package sdk

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// VerifyTLSChannelBinding performs the client-side identity-bound TLS channel
// binding handshake (#653) on an established TLS connection to a canonical
// Portal hostname. It verifies that the tunnel endpoint terminated the exact
// same TLS session (Ec == Et) and signed (context || hostname || nonce || Et)
// with the secp256k1 identity embedded in hostname. On any mismatch, it closes
// conn immediately so no application bytes are ever sent over a MITMed stream.
// A reply without the answer tag, such as one from a tunnel that does not
// offer binding, also closes conn, with an error that says the tunnel did not
// answer rather than an exporter mismatch.
//
// hostname must be the lease's canonical hostname exactly as the relay
// publishes it: the tunnel signs that name, so another canonical form that
// embeds the same address fails with a signer mismatch. The exchange ends,
// closing conn, as soon as ctx is done. It sets a deadline on conn and clears
// it when it returns, so a deadline set earlier does not survive; set it again
// afterwards.
func VerifyTLSChannelBinding(ctx context.Context, conn net.Conn, hostname string) error {
	if conn == nil {
		return errTLSConnectionIsRequired
	}
	var clientExporter []byte
	var expectedAddr string
	var nonce [types.TLSChannelBindingNonceSize]byte
	c, e, n, err := prepareChannelBindingClient(conn, hostname)
	if err != nil {
		return err
	}
	clientExporter, expectedAddr, nonce = c, e, n
	_ = conn.SetDeadline(time.Now().Add(defaultChannelBindingTimeout))
	defer conn.SetDeadline(time.Time{})
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	flow := &exchangeVerifyTLSChannelBindingFlow{
		conn:           conn,
		hostname:       hostname,
		nonce:          nonce,
		clientExporter: clientExporter,
		expectedAddr:   expectedAddr,
		stop:           stop,
	}
	return flow.completeVerifyTLSChannelBinding(ctx)
}

func prepareChannelBindingClient(conn net.Conn, hostname string) ([]byte, string, [types.TLSChannelBindingNonceSize]byte, error) {
	var nonce [types.TLSChannelBindingNonceSize]byte
	var expectedAddr string
	e, err := utils.ExtractCanonicalHostnameAddress(hostname)
	if err != nil {
		_ = conn.Close()
		return nil, "", nonce, err
	}
	expectedAddr = e
	exportFn, ok := probeExporter(conn)
	if !ok {
		_ = conn.Close()
		return nil, "", nonce, errTLSConnectionDoesNotSupportKeying
	}
	var clientExporter []byte
	c, err := exportFn(types.TLSChannelBindingExporterLabel, nil, types.TLSChannelBindingExporterSize)
	if err != nil {
		_ = conn.Close()
		return nil, "", nonce, fmt.Errorf("export client tls keying material: %w", err)
	}
	clientExporter = c
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		_ = conn.Close()
		return nil, "", nonce, fmt.Errorf("generate channel binding nonce: %w", err)
	}
	return clientExporter, expectedAddr, nonce, nil
}

type exchangeVerifyTLSChannelBindingFlow struct {
	conn           net.Conn
	hostname       string
	nonce          [types.TLSChannelBindingNonceSize]byte
	clientExporter []byte
	expectedAddr   string
	stop           func() bool
}

func (f *exchangeVerifyTLSChannelBindingFlow) completeVerifyTLSChannelBinding(ctx context.Context) error {
	reqFrame := make([]byte, types.TLSChannelBindingRequestSize)
	copy(reqFrame, types.TLSChannelBindingRequestMagic)
	copy(reqFrame[len(types.TLSChannelBindingRequestMagic):], f.nonce[:])
	if _, err := f.conn.Write(reqFrame); err != nil {
		_ = f.conn.Close()
		return fmt.Errorf("write channel binding request: %w", cmp.Or(ctx.Err(), err))
	}
	var compactSig []byte
	s, err := f.readBindingFlowAnswer(ctx)
	if err != nil {
		return err
	}
	compactSig = s
	if err := verifyChannelBindingSigner(f.hostname, f.nonce[:], f.clientExporter, f.expectedAddr, compactSig); err != nil {
		_ = f.conn.Close()
		return err
	}
	if !f.stop() {
		_ = f.conn.Close()
		return ctx.Err()
	}
	return nil
}

func (f *exchangeVerifyTLSChannelBindingFlow) readBindingFlowAnswer(ctx context.Context) ([]byte, error) {
	tunnelExporter, compactSig, err := readChannelBindingAnswer(ctx, f.conn)
	if err != nil {
		_ = f.conn.Close()
		return nil, err
	}
	if subtle.ConstantTimeCompare(f.clientExporter, tunnelExporter) != 1 {
		_ = f.conn.Close()
		return nil, errTLSChannelBindingExporterMismatchRelay
	}
	return compactSig, nil
}

func readChannelBindingAnswer(ctx context.Context, conn net.Conn) ([]byte, []byte, error) {
	var answer [types.TLSChannelBindingAnswerSize]byte
	tag := answer[:len(types.TLSChannelBindingAnswerTag)]
	if _, err := io.ReadFull(conn, tag); err != nil {
		return nil, nil, fmt.Errorf("read channel binding answer: %w", cmp.Or(ctx.Err(), err))
	}
	if string(tag) != types.TLSChannelBindingAnswerTag {
		return nil, nil, errTunnelDidNotAnswerChannelBinding
	}
	signed := answer[len(tag):]
	if _, err := io.ReadFull(conn, signed); err != nil {
		return nil, nil, fmt.Errorf("read channel binding answer: %w", cmp.Or(ctx.Err(), err))
	}
	tunnelExporter := append([]byte(nil), signed[:types.TLSChannelBindingExporterSize]...)
	compactSig := append([]byte(nil), signed[types.TLSChannelBindingExporterSize:]...)
	return tunnelExporter, compactSig, nil
}

// DialCanonicalTLS dials addr, completes a TLS 1.3 handshake for the canonical
// Portal hostname, and enforces identity-bound TLS channel binding (#653)
// before returning the connection for application traffic.
func DialCanonicalTLS(ctx context.Context, addr, hostname string, baseTLSConfig *tls.Config) (net.Conn, error) {
	normalizedHost := utils.NormalizeHostWithoutPort(hostname)
	if _, err := utils.ExtractCanonicalHostnameAddress(normalizedHost); err != nil {
		return nil, err
	}
	tlsConf := buildDialCanonicalTLSConfig(normalizedHost, baseTLSConfig)
	tlsConn, err := dialCanonicalTLSTransport(ctx, addr, tlsConf)
	if err != nil {
		return nil, err
	}
	if err := VerifyTLSChannelBinding(ctx, tlsConn, normalizedHost); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func buildDialCanonicalTLSConfig(normalizedHost string, baseTLSConfig *tls.Config) *tls.Config {
	tlsConf := &tls.Config{}
	if baseTLSConfig != nil {
		tlsConf = baseTLSConfig.Clone()
	}
	if tlsConf.ServerName == "" {
		tlsConf.ServerName = normalizedHost
	}
	if tlsConf.MinVersion < tls.VersionTLS13 {
		tlsConf.MinVersion = tls.VersionTLS13
	}
	return tlsConf
}

func dialCanonicalTLSTransport(ctx context.Context, addr string, tlsConf *tls.Config) (*tls.Conn, error) {
	var rawConn net.Conn
	c, err := (&net.Dialer{Timeout: defaultDialTimeout}).DialContext(ctx, "tcp", utils.EnsurePort(addr))
	if err != nil {
		return nil, err
	}
	rawConn = c
	tlsConn := tls.Client(rawConn, tlsConf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}
