package portal

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	ksigner "github.com/gosuda/keyless_tls/relay/signer"

	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
)

func testClientHello(host string) []byte {
	serverName := append([]byte{0, byte(len(host) >> 8), byte(len(host))}, host...)
	serverNameList := append([]byte{byte(len(serverName) >> 8), byte(len(serverName))}, serverName...)
	serverNameExtension := append([]byte{0, 0, byte(len(serverNameList) >> 8), byte(len(serverNameList))}, serverNameList...)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body,
		0,
		0, 2, 0x13, 0x01,
		1, 0,
		byte(len(serverNameExtension)>>8), byte(len(serverNameExtension)),
	)
	body = append(body, serverNameExtension...)
	hello := []byte{tlsHandshakeTypeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hello, body...)
}

func testTLSRecord(payload []byte) []byte {
	record := []byte{tlsContentTypeHandshake, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}
	return append(record, payload...)
}

func fragmentedClientHelloWire(hello []byte) [][]byte {
	return [][]byte{
		testTLSRecord(hello[:2]),
		testTLSRecord(hello[2:31]),
		testTLSRecord(hello[31:]),
	}
}

func TestCaptureClientHelloReassemblesFragmentedRecords(t *testing.T) {
	t.Parallel()
	hello := testClientHello("fragmented.example.com")
	records := fragmentedClientHelloWire(hello)
	wire := bytes.Join(records, nil)

	client, relay := net.Pipe()
	defer relay.Close()
	writeErr := make(chan error, 1)
	go func() {
		defer client.Close()
		_, err := client.Write(wire)
		writeErr <- err
	}()

	gotHello, replay, err := captureClientHello(relay, time.Second)
	if err != nil {
		t.Fatalf("captureClientHello() error = %v", err)
	}
	if !bytes.Equal(gotHello, hello) {
		t.Fatal("captureClientHello() did not return the exact reassembled handshake")
	}
	if host, err := clientHelloServerName(gotHello); err != nil || host != "fragmented.example.com" {
		t.Fatalf("clientHelloServerName() = (%q, %v), want fragmented.example.com", host, err)
	}
	replayed := make([]byte, len(wire))
	if _, err := io.ReadFull(replay, replayed); err != nil {
		t.Fatalf("read replayed records: %v", err)
	}
	if !bytes.Equal(replayed, wire) {
		t.Fatal("replayed TLS records differ from the original wire bytes")
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write fragmented records: %v", err)
	}
}

func TestHelloFixingConnReassemblesAcrossWrites(t *testing.T) {
	t.Parallel()
	hello := testClientHello("cache.example.com")
	records := fragmentedClientHelloWire(hello)
	wire := bytes.Join(records, nil)
	bindings := keyless.NewBindingRegistry(time.Minute)
	binding := bindings.Issue("lease-1", nil)

	client, tenant := net.Pipe()
	defer client.Close()
	defer tenant.Close()
	conn := newHelloFixingConn(client, bindings, binding)
	received := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		got := make([]byte, len(wire))
		_, err := io.ReadFull(tenant, got)
		received <- got
		readErr <- err
	}()

	if _, err := conn.Write(records[0]); err != nil {
		t.Fatalf("Write(first fragment) error = %v", err)
	}
	if err := bindings.ValidateAndConsume(binding[:], "lease-1", hello); !errors.Is(err, ksigner.ErrPermissionDenied) {
		t.Fatalf("binding validated before complete ClientHello: %v", err)
	}
	for _, record := range records[1:] {
		if _, err := conn.Write(record); err != nil {
			t.Fatalf("Write(fragment) error = %v", err)
		}
	}
	if err := bindings.ValidateAndConsume(binding[:], "lease-1", hello); err != nil {
		t.Fatalf("binding did not validate exact reassembled ClientHello: %v", err)
	}
	if err := <-readErr; err != nil {
		t.Fatalf("read forwarded records: %v", err)
	}
	if got := <-received; !bytes.Equal(got, wire) {
		t.Fatal("forwarded TLS records differ from the original writes")
	}
}

func TestClientHelloAccumulatorRejectsOversizedRecord(t *testing.T) {
	t.Parallel()
	recordLen := maxTLSRecordPayload + 1
	header := []byte{tlsContentTypeHandshake, 0x03, 0x03, byte(recordLen >> 8), byte(recordLen)}
	var accumulator clientHelloAccumulator
	if _, _, err := accumulator.add(header); err == nil {
		t.Fatal("add(oversized record) error = nil")
	}
}

func TestCaptureClientHelloRejectsIncompleteRecord(t *testing.T) {
	t.Parallel()
	client, relay := net.Pipe()
	go func() {
		_, _ = client.Write([]byte{tlsContentTypeHandshake, 0x03, 0x03, 0, 8, 1, 0})
		_ = client.Close()
	}()
	defer relay.Close()
	if _, _, err := captureClientHello(relay, time.Second); err == nil {
		t.Fatal("captureClientHello(incomplete record) error = nil")
	}
}
