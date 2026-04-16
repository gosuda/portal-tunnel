package overlay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	DefaultMTU                 = 1420
	DefaultListenPort          = 51820
	DefaultPersistentKeepalive = 25
	defaultEndpointResolveTTL  = 3 * time.Second
)

type stack struct {
	device    *device.Device
	net       *netstack.Net
	overlayIP netip.Addr

	mu            sync.Mutex
	closed        bool
	peerEndpoints map[string]string
}

func newStack(cfg Config) (*stack, error) {
	canonicalPrivateKey, err := utils.NormalizeWireGuardPrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("normalize wireguard private key: %w", err)
	}

	listenPort, err := utils.WireGuardListenPort(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	overlayIP, err := netip.ParseAddr(cfg.OverlayIPv4)
	if err != nil || !overlayIP.Is4() {
		return nil, errors.New("overlay ipv4 must be a valid IPv4 address")
	}

	tunDevice, network, err := netstack.CreateNetTUN([]netip.Addr{overlayIP}, nil, DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	wgDevice := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "portal-wg"))
	privateKeyHex, err := utils.WireGuardKeyHex(canonicalPrivateKey)
	if err != nil {
		wgDevice.Close()
		<-wgDevice.Wait()
		return nil, err
	}

	config := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", privateKeyHex, listenPort)
	if err := wgDevice.IpcSet(config); err != nil {
		wgDevice.Close()
		<-wgDevice.Wait()
		return nil, fmt.Errorf("configure wireguard device: %w", err)
	}
	if err := wgDevice.Up(); err != nil {
		wgDevice.Close()
		<-wgDevice.Wait()
		return nil, fmt.Errorf("bring wireguard device up: %w", err)
	}

	return &stack{
		device:        wgDevice,
		net:           network,
		overlayIP:     overlayIP,
		peerEndpoints: map[string]string{},
	}, nil
}

func (s *stack) ListenTCP(port int) (net.Listener, error) {
	if s == nil || s.net == nil {
		return nil, errors.New("wireguard is not initialized")
	}
	return s.net.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP(s.overlayIP.String()),
		Port: port,
	})
}

func (s *stack) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if s == nil || s.net == nil {
		return nil, errors.New("wireguard is not initialized")
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}

	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, errors.New("invalid tcp port")
	}
	return s.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip, uint16(port)))
}

func (s *stack) ApplyPeers(peers []desiredPeer) error {
	if s == nil || s.device == nil {
		return errors.New("wireguard is not initialized")
	}

	var builder strings.Builder
	builder.WriteString("replace_peers=true\n")
	var warnErr error
	nextPeerEndpoints := map[string]string{}

	for _, peer := range peers {
		peerKey := strings.TrimSpace(peer.wireGuardPublicKey)
		publicKeyHex, err := utils.WireGuardKeyHex(peer.wireGuardPublicKey)
		if err != nil {
			return fmt.Errorf("normalize peer %q public key: %w", peerKey, err)
		}

		resolvedEndpoint := ""
		if endpoint := peer.wireGuardEndpoint; endpoint != "" {
			resolvedEndpoint, err = resolvePeerEndpoint(endpoint)
			if err != nil {
				s.mu.Lock()
				currentEndpoint := s.peerEndpoints[publicKeyHex]
				s.mu.Unlock()
				if currentEndpoint != "" {
					warnErr = errors.Join(warnErr, fmt.Errorf("resolve peer %q endpoint: %w; using current endpoint %q", peerKey, err, currentEndpoint))
					resolvedEndpoint = currentEndpoint
				} else {
					warnErr = errors.Join(warnErr, fmt.Errorf("resolve peer %q endpoint: %w", peerKey, err))
					continue
				}
			}
		}

		builder.WriteString("public_key=")
		builder.WriteString(publicKeyHex)
		builder.WriteByte('\n')
		if resolvedEndpoint != "" {
			builder.WriteString("endpoint=")
			builder.WriteString(resolvedEndpoint)
			builder.WriteByte('\n')
			nextPeerEndpoints[publicKeyHex] = resolvedEndpoint
		}

		allowedIPs := utils.NormalizeIPPrefixes(peer.allowedIPs)
		for _, allowedIP := range allowedIPs {
			builder.WriteString("allowed_ip=")
			builder.WriteString(allowedIP)
			builder.WriteByte('\n')
		}
		if DefaultPersistentKeepalive > 0 {
			builder.WriteString("persistent_keepalive_interval=")
			builder.WriteString(strconv.Itoa(DefaultPersistentKeepalive))
			builder.WriteByte('\n')
		}
	}

	if err := s.device.IpcSet(builder.String()); err != nil {
		return err
	}
	s.mu.Lock()
	s.peerEndpoints = nextPeerEndpoints
	s.mu.Unlock()
	return warnErr
}

func resolvePeerEndpoint(raw string) (string, error) {
	endpoint := strings.TrimSpace(raw)
	if endpoint == "" {
		return "", errors.New("wireguard endpoint is required")
	}

	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}

	host = strings.Trim(host, "[]")
	if host == "" {
		return "", errors.New("wireguard endpoint host is required")
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(ip.String(), port), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultEndpointResolveTTL)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", fmt.Errorf("lookup %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("lookup %q: no IP addresses found", host)
	}

	selected := addrs[0]
	for _, addr := range addrs {
		if addr.Is4() {
			selected = addr
			break
		}
	}
	return net.JoinHostPort(selected.String(), port), nil
}

func (s *stack) Close() error {
	if s == nil || s.device == nil {
		return nil
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	device := s.device
	s.mu.Unlock()

	device.Close()
	<-device.Wait()
	return nil
}
