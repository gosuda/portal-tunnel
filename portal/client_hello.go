package portal

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	tlsRecordHeaderLen          = 5
	tlsContentTypeHandshake     = 22
	tlsHandshakeTypeClientHello = 1
	maxTLSRecordPayload         = 1 << 14
	maxClientHelloSize          = 1 << 20
	maxClientHelloWireSize      = 8 << 20
)

type clientHelloAccumulator struct {
	pending  []byte
	hello    []byte
	expected int
	wireSize int
}

func (a *clientHelloAccumulator) clone() clientHelloAccumulator {
	clone := *a
	clone.pending = append([]byte(nil), a.pending...)
	clone.hello = append([]byte(nil), a.hello...)
	return clone
}

func (a *clientHelloAccumulator) add(p []byte) ([]byte, bool, error) {
	if len(p) > maxClientHelloWireSize-a.wireSize {
		return nil, false, errors.New("client hello wire encoding exceeds limit")
	}
	a.wireSize += len(p)
	a.pending = append(a.pending, p...)
	for len(a.pending) >= tlsRecordHeaderLen {
		if a.pending[0] != tlsContentTypeHandshake {
			return nil, false, errors.New("client hello contains a non-handshake TLS record")
		}
		recordLen := int(a.pending[3])<<8 | int(a.pending[4])
		if recordLen == 0 || recordLen > maxTLSRecordPayload {
			return nil, false, errors.New("client hello TLS record has invalid length")
		}
		if len(a.pending) < tlsRecordHeaderLen+recordLen {
			return nil, false, nil
		}
		body := a.pending[tlsRecordHeaderLen : tlsRecordHeaderLen+recordLen]
		a.pending = a.pending[tlsRecordHeaderLen+recordLen:]
		if a.expected == 0 && len(a.hello) < 4 {
			need := min(4-len(a.hello), len(body))
			a.hello = append(a.hello, body[:need]...)
			body = body[need:]
			if len(a.hello) == 4 {
				if a.hello[0] != tlsHandshakeTypeClientHello {
					return nil, false, errors.New("first TLS handshake message is not a client hello")
				}
				messageLen := int(a.hello[1])<<16 | int(a.hello[2])<<8 | int(a.hello[3])
				a.expected = 4 + messageLen
				if messageLen == 0 || a.expected > maxClientHelloSize {
					return nil, false, errors.New("client hello handshake has invalid length")
				}
			}
		}
		if a.expected > 0 {
			need := min(a.expected-len(a.hello), len(body))
			a.hello = append(a.hello, body[:need]...)
			if len(a.hello) == a.expected {
				return append([]byte(nil), a.hello...), true, nil
			}
		}
	}
	return nil, false, nil
}

// captureClientHello reads complete TLS records until the first ClientHello
// handshake message is complete and replays every captured wire byte unchanged.
func captureClientHello(conn net.Conn, timeout time.Duration) ([]byte, net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var accumulator clientHelloAccumulator
	captured := make([]byte, 0, 4096)
	for {
		header := make([]byte, tlsRecordHeaderLen)
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, nil, fmt.Errorf("read TLS record header: %w", err)
		}
		recordLen := int(header[3])<<8 | int(header[4])
		if recordLen == 0 || recordLen > maxTLSRecordPayload {
			return nil, nil, errors.New("client hello TLS record has invalid length")
		}
		body := make([]byte, recordLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, nil, fmt.Errorf("read TLS record body: %w", err)
		}
		record := append(header, body...)
		if len(record) > maxClientHelloWireSize-len(captured) {
			return nil, nil, errors.New("client hello wire encoding exceeds limit")
		}
		captured = append(captured, record...)
		hello, complete, err := accumulator.add(record)
		if err != nil {
			return nil, nil, err
		}
		if complete {
			return hello, &replayedConn{Conn: conn, pending: captured}, nil
		}
	}
}

type replayedConn struct {
	net.Conn
	pending []byte
}

func (c *replayedConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func clientHelloServerName(hello []byte) (string, error) {
	if len(hello) < 4 || hello[0] != tlsHandshakeTypeClientHello {
		return "", errors.New("invalid client hello handshake")
	}
	body := hello[4:]
	if len(body) < 34 {
		return "", errors.New("client hello body is too short")
	}
	i := 34
	if i >= len(body) {
		return "", errors.New("client hello is missing session id")
	}
	sessionLen := int(body[i])
	i++
	if i+sessionLen+2 > len(body) {
		return "", errors.New("invalid client hello session id")
	}
	i += sessionLen
	cipherLen := int(body[i])<<8 | int(body[i+1])
	i += 2
	if cipherLen < 2 || i+cipherLen >= len(body) {
		return "", errors.New("invalid client hello cipher suites")
	}
	i += cipherLen
	compressionLen := int(body[i])
	i++
	if compressionLen < 1 || i+compressionLen > len(body) {
		return "", errors.New("invalid client hello compression methods")
	}
	i += compressionLen
	if i == len(body) {
		return "", nil
	}
	if i+2 > len(body) {
		return "", errors.New("invalid client hello extensions")
	}
	extensionsLen := int(body[i])<<8 | int(body[i+1])
	i += 2
	if i+extensionsLen != len(body) {
		return "", errors.New("invalid client hello extensions length")
	}
	end := i + extensionsLen
	for i+4 <= end {
		extensionType := int(body[i])<<8 | int(body[i+1])
		extensionLen := int(body[i+2])<<8 | int(body[i+3])
		i += 4
		if i+extensionLen > end {
			return "", errors.New("invalid client hello extension")
		}
		if extensionType == 0 {
			return serverNameFromExtension(body[i : i+extensionLen])
		}
		i += extensionLen
	}
	if i != end {
		return "", errors.New("invalid client hello extension trailer")
	}
	return "", nil
}

func serverNameFromExtension(extension []byte) (string, error) {
	if len(extension) < 2 {
		return "", errors.New("invalid server name extension")
	}
	listLen := int(extension[0])<<8 | int(extension[1])
	if listLen == 0 || listLen+2 != len(extension) {
		return "", errors.New("invalid server name list")
	}
	i, end := 2, 2+listLen
	for i+3 <= end {
		nameType := extension[i]
		nameLen := int(extension[i+1])<<8 | int(extension[i+2])
		i += 3
		if i+nameLen > end {
			return "", errors.New("invalid server name entry")
		}
		if nameType == 0 {
			if nameLen == 0 {
				return "", errors.New("server name is empty")
			}
			return string(extension[i : i+nameLen]), nil
		}
		i += nameLen
	}
	if i != end {
		return "", errors.New("invalid server name list trailer")
	}
	return "", nil
}
