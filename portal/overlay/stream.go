package overlay

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

func writeHopToken(conn net.Conn, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("next hop token is required")
	}
	payload := []byte(token)
	if len(payload) > maxHopTokenBytes {
		return errors.New("next hop token is too large")
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	_, err := conn.Write(frame)
	return err
}

func readHopStream(conn net.Conn) (HopStream, error) {
	if err := conn.SetReadDeadline(time.Now().Add(defaultTokenTimeout)); err != nil {
		return HopStream{}, err
	}
	var size [4]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return HopStream{}, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > uint32(maxHopTokenBytes) {
		return HopStream{}, errors.New("invalid hop token size")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return HopStream{}, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return HopStream{}, err
	}
	token := strings.TrimSpace(string(payload))
	if token == "" {
		return HopStream{}, errors.New("next hop token is required")
	}
	remoteAddr := ""
	if conn.RemoteAddr() != nil {
		remoteAddr = conn.RemoteAddr().String()
	}
	return HopStream{Conn: conn, Token: token, RemoteAddr: remoteAddr}, nil
}
