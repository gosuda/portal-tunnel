package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	DefaultMTU                 = 1420
	DefaultPeerAPIHTTPPort     = 7777
	DefaultPersistentKeepalive = 25

	defaultPeerRequestTimeout = 15 * time.Second
)

type RuntimeConfig struct {
	PrivateKey  string
	Endpoint    string
	OverlayIPv4 string
	MTU         int
}

type Runtime struct {
	device    *device.Device
	net       *netstack.Net
	overlayIP netip.Addr

	mu     sync.Mutex
	closed bool
}

func NewRuntime(cfg RuntimeConfig) (*Runtime, error) {
	privateKey, err := utils.NormalizeWireGuardPrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("normalize wireguard private key: %w", err)
	}
	listenPort, err := utils.WireGuardListenPort(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	ip, err := netip.ParseAddr(strings.TrimSpace(cfg.OverlayIPv4))
	if err != nil || !ip.Is4() {
		return nil, errors.New("overlay ipv4 must be a valid IPv4 address")
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	tunDev, network, err := netstack.CreateNetTUN([]netip.Addr{ip}, nil, mtu)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	wgDevice := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "portal-wg"))
	privateKeyHex, err := utils.WireGuardKeyHex(privateKey)
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

	return &Runtime{
		device:    wgDevice,
		net:       network,
		overlayIP: ip,
	}, nil
}

func (r *Runtime) ListenTCP(port int) (net.Listener, error) {
	if r == nil || r.net == nil {
		return nil, errors.New("wireguard runtime not initialized")
	}
	return r.net.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP(r.overlayIP.String()),
		Port: port,
	})
}

func (r *Runtime) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if r == nil || r.net == nil {
		return nil, errors.New("wireguard runtime not initialized")
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
	return r.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip, uint16(port)))
}

func (r *Runtime) Discover(ctx context.Context, overlayIPv4 string, port int) (types.DiscoveryResponse, error) {
	var resp types.DiscoveryResponse
	if err := r.getPeerJSON(ctx, overlayIPv4, port, types.PathDiscovery, &resp); err != nil {
		return types.DiscoveryResponse{}, err
	}
	return resp, nil
}

func (r *Runtime) FetchOverlayHealth(ctx context.Context, overlayIPv4 string, port int) (types.OverlayHealthResponse, error) {
	var resp types.OverlayHealthResponse
	if err := r.getPeerJSON(ctx, overlayIPv4, port, types.PathOverlayHealth, &resp); err != nil {
		return types.OverlayHealthResponse{}, err
	}
	return resp, nil
}

func (r *Runtime) getPeerJSON(ctx context.Context, overlayIPv4 string, port int, path string, out any) error {
	if r == nil {
		return errors.New("wireguard runtime not initialized")
	}
	if port == 0 {
		port = DefaultPeerAPIHTTPPort
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(overlayIPv4))
	if err != nil || !ip.Is4() {
		return errors.New("overlay ipv4 must be a valid IPv4 address")
	}

	baseURL := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(ip.String(), strconv.Itoa(port)),
		Path:   path,
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL.String(), nil)
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext:       r.DialContext,
			ForceAttemptHTTP2: false,
		},
		Timeout: defaultPeerRequestTimeout,
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return utils.DecodeAPIRequestError(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (r *Runtime) ApplyPeers(peers []types.DesiredPeer) error {
	if r == nil || r.device == nil {
		return errors.New("wireguard runtime not initialized")
	}

	var builder strings.Builder
	builder.WriteString("replace_peers=true\n")

	for _, peer := range peers {
		publicKeyHex, err := utils.WireGuardKeyHex(peer.WireGuardPublicKey)
		if err != nil {
			return fmt.Errorf("normalize peer %q public key: %w", peer.RelayID, err)
		}
		builder.WriteString("public_key=")
		builder.WriteString(publicKeyHex)
		builder.WriteByte('\n')
		if endpoint := strings.TrimSpace(peer.WireGuardEndpoint); endpoint != "" {
			builder.WriteString("endpoint=")
			builder.WriteString(endpoint)
			builder.WriteByte('\n')
		}

		allowedIPs := utils.NormalizeIPPrefixes(peer.AllowedIPs)
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

	return r.device.IpcSet(builder.String())
}

func (r *Runtime) Close() error {
	if r == nil || r.device == nil {
		return nil
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	device := r.device
	r.mu.Unlock()

	device.Close()
	<-device.Wait()
	return nil
}
