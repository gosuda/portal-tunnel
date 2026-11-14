package e2e_test

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
)

func serveHalfCloseOrigin(origin *net.TCPListener, originDone chan error) {
	conn, err := origin.AcceptTCP()
	if err != nil {
		originDone <- err
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request, err := io.ReadAll(conn)
	if err == nil {
		_, err = conn.Write(append([]byte("after-eof:"), request...))
	}
	originDone <- err
}

func assertRequestHalfClose(t *testing.T, client *net.TCPConn, originDone chan error) {
	t.Helper()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "after-eof:request" {
		t.Fatalf("response = %q", response)
	}
	if err := <-originDone; err != nil {
		t.Fatal(err)
	}
}

func TestTCPProxyRequestHalfClose(t *testing.T) {
	origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	publicAddr, _, _ := startRawTCPTestTunnel(t, "127.0.0.1", origin.Addr().String())
	originDone := make(chan error, 1)
	go serveHalfCloseOrigin(origin, originDone)
	client, err := net.DialTCP("tcp", nil, mustTCPAddr(t, publicAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	assertRequestHalfClose(t, client, originDone)
}

func acceptHalfCloseConn(t *testing.T, origin *net.TCPListener) *net.TCPConn {
	t.Helper()
	_ = origin.SetDeadline(time.Now().Add(10 * time.Second))
	conn, err := origin.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

func uploadAfterResponseEOF(t *testing.T, client *net.TCPConn, conn *net.TCPConn) {
	t.Helper()
	if _, err := client.Write([]byte("request-after-response-eof")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "request-after-response-eof" {
		t.Fatalf("request = %q, want complete upload after response EOF", request)
	}
}

func confirmHalfCloseResponse(t *testing.T, origin *net.TCPListener, client *net.TCPConn) *net.TCPConn {
	t.Helper()
	conn := acceptHalfCloseConn(t, origin)
	if _, err := conn.Write([]byte("response-first")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response-first" {
		t.Fatalf("response = %q", response)
	}
	return conn
}

func TestTCPProxyResponseHalfClosePreservesRequestUpload(t *testing.T) {
	origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	publicAddr, _, _ := startRawTCPTestTunnel(t, "127.0.0.1", origin.Addr().String())
	client, err := net.DialTCP("tcp", nil, mustTCPAddr(t, publicAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	conn := confirmHalfCloseResponse(t, origin, client)
	defer conn.Close()
	uploadAfterResponseEOF(t, client, conn)
}

func dialHalfClosePair(t *testing.T, origin *net.TCPListener, publicAddr string) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	client, err := net.DialTCP("tcp", nil, mustTCPAddr(t, publicAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = origin.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := origin.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var payload [1]byte
	if _, err := io.ReadFull(conn, payload[:]); err != nil {
		t.Fatal(err)
	}
	return client, conn
}

func revokeHalfCloseBridge(t *testing.T, runtime *tunnel.Runtime, stop func(), client *net.TCPConn, mode string) {
	t.Helper()
	switch mode {
	case "cancel":
		stop()
	case "exposure-close":
		if err := runtime.Exposure.Close(); err != nil {
			t.Fatal(err)
		}
	case "reset":
		if err := client.SetLinger(0); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
	}
}

func checkSingleOriginEOF(t *testing.T, mode string) {
	t.Helper()
	origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	publicAddr, runtime, stop := startRawTCPTestTunnel(t, "127.0.0.1", origin.Addr().String())
	client, conn := dialHalfClosePair(t, origin, publicAddr)
	revokeHalfCloseBridge(t, runtime, stop, client, mode)
	var payload [1]byte
	if _, err := conn.Read(payload[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("origin did not observe EOF after %s: %v", mode, err)
	}
	stop()
}

func TestTCPProxyOriginEOFOnShutdownOrPublicReset(t *testing.T) {
	for _, mode := range []string{"cancel", "exposure-close", "reset"} {
		t.Run(mode, func(t *testing.T) {
			for range 2 {
				checkSingleOriginEOF(t, mode)
			}
		})
	}
}
