package sdk

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func tlsChannelBindingPayload(hostname string, nonce, exported []byte) []byte {
	normalizedHost := utils.NormalizeHostWithoutPort(hostname)
	buf := make([]byte, 0, len(types.TLSChannelBindingDomain)+1+len(normalizedHost)+1+len(nonce)+len(exported))
	buf = append(buf, types.TLSChannelBindingDomain...)
	buf = append(buf, 0)
	buf = append(buf, normalizedHost...)
	buf = append(buf, 0)
	buf = append(buf, nonce...)
	buf = append(buf, exported...)
	return buf
}
func verifyChannelBindingSigner(hostname string, nonce, clientExporter []byte, expectedAddr string, compactSig []byte) error {
	payload := tlsChannelBindingPayload(hostname, nonce, clientExporter)
	pubKey, err := identity.RecoverSHA256Secp256k1Compact(payload, compactSig)
	if err != nil {
		return fmt.Errorf("recover channel binding signer: %w", err)
	}
	recoveredAddr, err := identity.AddressFromCompressedPublicKeyHex(hex.EncodeToString(pubKey.SerializeCompressed()))
	if err != nil {
		return fmt.Errorf("resolve channel binding signer address: %w", err)
	}
	if !strings.EqualFold(recoveredAddr, expectedAddr) {
		return fmt.Errorf("tls channel binding signer %s does not match canonical hostname identity %s", recoveredAddr, expectedAddr)
	}
	return nil
}
func (m *mitmManager) serveChannelBindingHandshake(conn net.Conn, reader *bufio.Reader, exportFn func(string, []byte, int) ([]byte, error)) (net.Conn, error) {
	l := m.listener
	hostname := ""
	if lease, ok := l.leaseSnapshot(); ok {
		hostname = lease.hostname
	}
	if hostname == "" {
		_ = conn.Close()
		return nil, errListenerCanonicalHostnameUnavailableChannelBinding
	}
	var reqFrame [types.TLSChannelBindingRequestSize]byte
	if _, err := io.ReadFull(reader, reqFrame[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read channel binding request: %w", err)
	}
	nonce := bytes.Clone(reqFrame[len(types.TLSChannelBindingRequestMagic):])
	var exported []byte
	e, err := exportFn(types.TLSChannelBindingExporterLabel, nil, types.TLSChannelBindingExporterSize)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("export server channel binding keying material: %w", err)
	}
	exported = e
	var compactSig []byte
	s, err := signChannelBindingPayload(hostname, nonce, exported, l.identity)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	compactSig = s
	return m.writeChannelBindingAnswer(conn, reader, exported, compactSig)
}

func signChannelBindingPayload(hostname string, nonce, exported []byte, id types.Identity) ([]byte, error) {
	payload := tlsChannelBindingPayload(hostname, nonce, exported)
	authority := identity.NewLocalAuthority(id)
	var compactSig []byte
	sig, err := authority.SignSHA256Secp256k1(payload)
	if err != nil {
		return nil, fmt.Errorf("sign channel binding payload: %w", err)
	}
	c, err := sig.Compact()
	if err != nil {
		return nil, fmt.Errorf("encode channel binding signature: %w", err)
	}
	compactSig = c
	return compactSig, nil
}

func (m *mitmManager) writeChannelBindingAnswer(conn net.Conn, reader *bufio.Reader, exported, compactSig []byte) (net.Conn, error) {
	var answer [types.TLSChannelBindingAnswerSize]byte
	n := copy(answer[:], types.TLSChannelBindingAnswerTag)
	n += copy(answer[n:], exported)
	copy(answer[n:], compactSig)
	_ = conn.SetWriteDeadline(time.Now().Add(channelBindingRequestTimeout))
	if _, err := conn.Write(answer[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write channel binding answer: %w", err)
	}
	return wrapBufferedConn(conn, reader), nil
}

func (m *mitmManager) maybeHandleConn(conn net.Conn) (net.Conn, bool, error) {
	if conn == nil {
		return conn, false, nil
	}

	exportFn, ok := probeExporter(conn)
	if !ok {
		return conn, false, nil
	}

	m.mu.Lock()
	hasPending := len(m.pending) > 0
	m.mu.Unlock()

	canChannelBind := m.listener != nil && m.listener.cache == nil
	if !hasPending && !canChannelBind {
		return conn, false, nil
	}

	frameSize := len(mitmProbeNonce{})
	peekLen := len(types.TLSChannelBindingRequestMagic)
	if hasPending {
		peekLen = frameSize
	}
	reader := bufio.NewReaderSize(conn, frameSize)
	_ = conn.SetReadDeadline(time.Now().Add(mitmProbePeekTimeout))
	peeked, _ := reader.Peek(peekLen)
	defer conn.SetDeadline(time.Time{})

	if canChannelBind && bytes.HasPrefix(peeked, []byte(types.TLSChannelBindingRequestMagic)) {

		_ = conn.SetReadDeadline(time.Now().Add(channelBindingRequestTimeout))
		boundConn, err := m.serveChannelBindingHandshake(conn, reader, exportFn)
		if err != nil {
			return nil, true, err
		}
		return boundConn, false, nil
	}

	if len(peeked) != frameSize || !hasPending {
		return wrapBufferedConn(conn, reader), false, nil
	}
	return m.consumePendingProbe(conn, reader, exportFn, peeked)
}

func (m *mitmManager) consumePendingProbe(conn net.Conn, reader *bufio.Reader, exportFn func(string, []byte, int) ([]byte, error), peeked []byte) (net.Conn, bool, error) {
	frameSize := len(mitmProbeNonce{})
	var nonce mitmProbeNonce
	copy(nonce[:], peeked[:frameSize])
	m.mu.Lock()
	_, ok := m.pending[nonce]
	m.mu.Unlock()
	if !ok {
		return wrapBufferedConn(conn, reader), false, nil
	}

	defer conn.Close()

	frame := make([]byte, frameSize)
	if _, err := io.ReadFull(reader, frame); err != nil {
		return nil, true, fmt.Errorf("read mitm probe frame: %w", err)
	}

	actual, err := exportFn(mitmProbeExporterLabel, nil, 32)
	if err != nil {
		return nil, true, fmt.Errorf("export server probe keying material: %w", err)
	}

	m.completeProbe(nonce, actual)
	return nil, true, nil
}
