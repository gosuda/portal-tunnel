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
	var header [16]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, fmt.Errorf("read PROXY header: %w", err)
	}
	if string(header[:12]) != "\r\n\r\n\x00\r\nQUIT\n" || (header[12] != 0x20 && header[12] != 0x21) {
		return nil, errProxyProtocolHeader
	}
	remaining := int(binary.BigEndian.Uint16(header[14:]))
	if header[12] == 0x20 { // LOCAL health checks never assert a client address.
		if _, err := io.CopyN(io.Discard, conn, int64(remaining)); err != nil {
			return nil, fmt.Errorf("read PROXY LOCAL payload: %w", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, err
		}
		return conn, nil
	}
	var addressSize int
	switch header[13] {
	case 0x11: // AF_INET, STREAM
		addressSize = 12
	case 0x21: // AF_INET6, STREAM
		addressSize = 36
	default:
		return nil, errProxyProtocolHeader
	}
	if remaining < addressSize {
		return nil, errProxyProtocolHeader
	}
	var addresses [36]byte
	if _, err := io.ReadFull(conn, addresses[:addressSize]); err != nil {
		return nil, fmt.Errorf("read PROXY addresses: %w", err)
	}
	ipSize := (addressSize - 4) / 2
	source, ok := netip.AddrFromSlice(addresses[:ipSize])
	source = source.Unmap()
	if !ok || source.IsUnspecified() || source.IsMulticast() {
		return nil, errProxyProtocolAddress
	}
	port := binary.BigEndian.Uint16(addresses[ipSize*2:])
	// Extensions carry no authority here. Consume only well-framed TLVs,
	// bounded by the uint16 payload length and the inspection deadline.
	for remaining -= addressSize; remaining > 0; {
		if remaining < 3 {
			return nil, errProxyProtocolHeader
		}
		var tlv [3]byte
		if _, err := io.ReadFull(conn, tlv[:]); err != nil {
			return nil, fmt.Errorf("read PROXY TLV: %w", err)
		}
		length := int(binary.BigEndian.Uint16(tlv[1:]))
		remaining -= 3
		if length > remaining {
			return nil, errProxyProtocolHeader
		}
		if _, err := io.CopyN(io.Discard, conn, int64(length)); err != nil {
			return nil, fmt.Errorf("read PROXY TLV value: %w", err)
		}
		remaining -= length
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &proxySourceConn{Conn: conn, source: net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, port))}, nil
}
