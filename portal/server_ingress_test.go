package portal

import (
	"net"
	"testing"
)

func TestPublicIngressAggregateAdmissionAndRelease(t *testing.T) {
	var server Server
	var conns []net.Conn
	for range publicIngressLimit {
		conn, peer := net.Pipe()
		t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
		if !server.admitIngress(conn, false) {
			t.Fatal("connection below aggregate limit rejected")
		}
		conns = append(conns, conn)
	}
	extra, peer := net.Pipe()
	defer extra.Close()
	defer peer.Close()
	if server.admitIngress(extra, false) {
		t.Fatal("raw TCP bypassed tenant connection budget")
	}
	if !server.admitIngress(extra, true) {
		t.Fatal("tenant saturation blocked root inspection")
	}
	if server.promoteIngress() {
		t.Fatal("SNI tenant bypassed tenant connection budget")
	}
	server.releaseIngress(conns[0], false)
	if !server.promoteIngress() {
		t.Fatal("released tenant capacity was not reusable")
	}
	server.closeIngress()
	if server.admitIngress(conns[0], false) {
		t.Fatal("connection admitted after shutdown")
	}
	server.releaseIngress(extra, false)
	for _, conn := range conns[1:] {
		server.releaseIngress(conn, false)
	}
	server.ingressWorkers.Wait()
}
