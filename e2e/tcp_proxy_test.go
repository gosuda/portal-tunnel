package e2e_test

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPProxyRequestHalfClose(t *testing.T) {
	origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	publicAddr, _, _ := startRawTCPTestTunnel(t, "127.0.0.1", origin.Addr().String())
	originDone := make(chan error, 1)
	go func() {
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
	}()
	client, err := net.DialTCP("tcp", nil, mustTCPAddr(t, publicAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
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

// A public reset may reach the SDK as clean reverse EOF. This test proves
// origin EOF propagation only; full local socket/worker release on explicit
// SDK cancellation is protected by the SDK owner shutdown test.
func TestTCPProxyOriginEOFOnShutdownOrPublicReset(t *testing.T) {
	for _, mode := range []string{"cancel", "exposure-close", "reset"} {
		t.Run(mode, func(t *testing.T) {
			for range 2 {
				origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = origin.Close() })
				publicAddr, runtime, stop := startRawTCPTestTunnel(t, "127.0.0.1", origin.Addr().String())
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
				if _, err := conn.Read(payload[:]); !errors.Is(err, io.EOF) {
					t.Fatalf("origin did not observe EOF after %s: %v", mode, err)
				}
				stop()
			}
		})
	}
}

func mustTCPAddr(t *testing.T, address string) *net.TCPAddr {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}
