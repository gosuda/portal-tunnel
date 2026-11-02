package portal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"
)

var (
	errProxyProtocolPeer    = errors.New("PROXY protocol peer is not trusted")
	errProxyProtocolHeader  = errors.New("invalid PROXY v2 TCP header")
	errProxyProtocolAddress = errors.New("PROXY protocol requires a concrete unicast IP address")
)

// proxySourceConn changes only the source address. TLS bytes, deadlines,
// closure and the actual local endpoint remain owned by the original socket.
type proxySourceConn struct {
	net.Conn
	source *net.TCPAddr
}

func (c *proxySourceConn) RemoteAddr() net.Addr { return c.source }

// readProxyProtocolV2 runs inside the existing bounded ingress inspection
// worker. Never sniff or accept optional headers: configured ingress requires
// a trusted socket peer and a v2 header. LOCAL keeps the socket source;
// PROXY must carry a TCP4/TCP6 source.
func readProxyProtocolV2(conn net.Conn, trustedIPs []string) (net.Conn, error) {
	peer, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil || !slices.Contains(trustedIPs, peer.Addr().Unmap().String()) {
		return nil, errProxyProtocolPeer
	}
	if err := conn.SetReadDeadline(time.Now().Add(defaultClientHelloWait)); err != nil {
		return nil, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	var header [16]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, fmt.Errorf("read PROXY header: %w", err)
	}
	if string(header[:12]) != "\r\n\r\n\x00\r\nQUIT\n" || (header[12] != 0x20 && header[12] != 0x21) {
		return nil, errProxyProtocolHeader
	}
	// The v2 uint16 length bounds this allocation to 64 KiB per admitted
	// inspection. Extensions are opaque: only the address block has authority.
	payload := make([]byte, int(binary.BigEndian.Uint16(header[14:])))
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("read PROXY payload: %w", err)
	}
	if header[12] == 0x20 { // LOCAL health checks never assert a client address.
		return conn, nil
	}
	var ipSize int
	switch header[13] {
	case 0x11: // AF_INET, STREAM
		ipSize = 4
	case 0x21: // AF_INET6, STREAM
		ipSize = 16
	default:
		return nil, errProxyProtocolHeader
	}
	if len(payload) < 2*ipSize+4 {
		return nil, errProxyProtocolHeader
	}
	source, ok := netip.AddrFromSlice(payload[:ipSize])
	source = source.Unmap()
	if !ok || source.IsUnspecified() || source.IsMulticast() {
		return nil, errProxyProtocolAddress
	}
	port := binary.BigEndian.Uint16(payload[ipSize*2:])
	return &proxySourceConn{Conn: conn, source: net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, port))}, nil
}
