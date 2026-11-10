package embedded

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

func listenDNS(addr string) (net.PacketConn, net.Listener, error) {
	listenConfig := net.ListenConfig{}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse embedded dns listen address %q: %w", addr, err)
	}
	if portStr != "0" {
		return listenDNSFixedAddr(addr, listenConfig)
	}
	return listenDNSCompanionPort(addr, host, listenConfig)
}

func listenDNSFixedAddr(addr string, listenConfig net.ListenConfig) (net.PacketConn, net.Listener, error) {
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen embedded dns udp %s: %w", addr, err)
	}
	listener, err := listenConfig.Listen(context.Background(), "tcp", addr)
	if err != nil {
		_ = packetConn.Close()
		return nil, nil, fmt.Errorf("listen embedded dns tcp %s: %w", addr, err)
	}
	return packetConn, listener, nil
}

func listenDNSCompanionPort(addr, host string, listenConfig net.ListenConfig) (net.PacketConn, net.Listener, error) {
	var lastErr error
	for range 5 {
		packetConn, err := listenConfig.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("listen embedded dns udp %s: %w", addr, err)
		}
		port := packetConn.LocalAddr().(*net.UDPAddr).Port
		listener, err := listenConfig.Listen(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err == nil {
			return packetConn, listener, nil
		}
		lastErr = err
		_ = packetConn.Close()
	}
	return nil, nil, fmt.Errorf("listen embedded dns tcp companion port: %w", lastErr)
}
