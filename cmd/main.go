package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/rs/zerolog/log"
	"gosuda.org/portal/sdk"
	"gosuda.org/portal/utils"
)

var (
	flagConfigPath string
	flagRelayURLs  string
	flagHost       string
	flagPort       string
	flagName       string
)

func main() {
	if len(os.Args) < 2 {
		printTunnelUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "expose":
		fs := flag.NewFlagSet("expose", flag.ExitOnError)
		fs.StringVar(&flagConfigPath, "config", "", "Path to portal-tunnel config file")
		fs.StringVar(&flagRelayURLs, "relay", "ws://localhost:4017/relay", "Portal relay server URLs when config is not provided (comma-separated)")
		fs.StringVar(&flagHost, "host", "localhost", "Local host to proxy to when config is not provided")
		fs.StringVar(&flagPort, "port", "4018", "Local port to proxy to when config is not provided")
		fs.StringVar(&flagName, "name", "", "Service name when config is not provided (auto-generated if empty)")
		_ = fs.Parse(os.Args[2:])

		if err := runExpose(); err != nil {
			log.Fatal().Err(err).Msg("Failed to expose")
		}
	case "-h", "--help", "help":
		printTunnelUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printTunnelUsage()
		os.Exit(2)
	}
}

func printTunnelUsage() {
	fmt.Println("portal-tunnel — Expose local services through Portal relay")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  portal-tunnel expose --config <file>")
	fmt.Println("  portal-tunnel expose [--relay URL1,URL2] [--host HOST] [--port PORT] [--name NAME]")
}

func runExpose() error {
	if flagConfigPath == "" {
		return runExposeWithFlags()
	}
	return runExposeWithConfig()
}

func runExposeWithConfig() error {
	cfg, err := LoadConfig(flagConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	relayDir := NewRelayDirectory(cfg.Relays)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info().Msg("")
		log.Info().Msg("Shutting down tunnels...")
		cancel()
	}()

	errCh := make(chan error, len(cfg.Services))
	var wg sync.WaitGroup

	for i := range cfg.Services {
		service := &cfg.Services[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runServiceTunnel(ctx, relayDir, service, fmt.Sprintf("config=%s", flagConfigPath)); err != nil {
				errCh <- err
			}
		}()
	}

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case err := <-errCh:
		cancel()
		<-doneCh
		return err
	case <-ctx.Done():
		<-doneCh
		log.Info().Msg("Tunnel stopped")
		return nil
	case <-doneCh:
		return nil
	}
}

func runExposeWithFlags() error {
	relayURLs := utils.ParseURLs(flagRelayURLs)
	if len(relayURLs) == 0 {
		return fmt.Errorf("--relay must include at least one non-empty URL when --config is not provided")
	}

	target := net.JoinHostPort(flagHost, flagPort)
	service := &ServiceConfig{
		Name:            strings.TrimSpace(flagName),
		Target:          target,
		RelayPreference: []string{"flags"},
	}
	applyServiceDefaults(service)

	relayDir := NewRelayDirectory([]RelayConfig{
		{
			Name: "flags",
			URLs: relayURLs,
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info().Msg("")
		log.Info().Msg("Shutting down tunnel...")
		cancel()
	}()

	if err := runServiceTunnel(ctx, relayDir, service, "flags"); err != nil {
		return err
	}

	log.Info().Msg("Tunnel stopped")
	return nil
}

func proxyConnection(ctx context.Context, localAddr string, relayConn net.Conn) error {
	defer relayConn.Close()

	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to local service %s: %w", localAddr, err)
	}
	defer localConn.Close()

	errCh := make(chan error, 2)
	stopCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			relayConn.Close()
			localConn.Close()
		case <-stopCh:
		}
	}()

	go func() {
		_, err := io.Copy(localConn, relayConn)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(relayConn, localConn)
		errCh <- err
	}()

	err = <-errCh
	close(stopCh)
	relayConn.Close()
	<-errCh

	return err
}

func runServiceTunnel(ctx context.Context, relayDir *RelayDirectory, service *ServiceConfig, origin string) error {
	localAddr := service.Target
	serviceName := strings.TrimSpace(service.Name)
	bootstrapServers, err := relayDir.BootstrapServers(service.RelayPreference)
	if err != nil {
		return fmt.Errorf("service %s: resolve relay servers: %w", serviceName, err)
	}

	cred := sdk.NewCredential()
	leaseID := cred.ID()
	if serviceName == "" {
		serviceName = fmt.Sprintf("tunnel-%s", leaseID[:8])
		log.Info().Str("service", serviceName).Msg("No service name provided; generated automatically")
	}
	log.Info().Str("service", serviceName).Msgf("Local service is reachable at %s", localAddr)
	log.Info().Str("service", serviceName).Msgf("Starting Portal Tunnel (%s)...", origin)
	log.Info().Str("service", serviceName).Msgf("  Local:    %s", localAddr)
	log.Info().Str("service", serviceName).Msgf("  Relays:   %s", strings.Join(bootstrapServers, ", "))
	log.Info().Str("service", serviceName).Msgf("  Lease ID: %s", leaseID)

	client, err := sdk.NewClient(func(c *sdk.ClientConfig) {
		c.BootstrapServers = bootstrapServers
	})
	if err != nil {
		return fmt.Errorf("service %s: failed to connect to relay: %w", serviceName, err)
	}
	defer client.Close()

	listener, err := client.Listen(cred, serviceName, service.Protocols)
	if err != nil {
		return fmt.Errorf("service %s: failed to register service: %w", serviceName, err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	log.Info().Str("service", serviceName).Msg("")
	log.Info().Str("service", serviceName).Msg("Access via:")
	log.Info().Str("service", serviceName).Msgf("- Name:     /peer/%s", serviceName)
	log.Info().Str("service", serviceName).Msgf("- Lease ID: /peer/%s", leaseID)
	log.Info().Str("service", serviceName).Msgf("- Example:  http://%s/peer/%s", bootstrapServers[0], serviceName)

	log.Info().Str("service", serviceName).Msg("")

	connCount := 0
	var connWG sync.WaitGroup
	defer connWG.Wait()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		relayConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Error().Str("service", serviceName).Err(err).Msg("Failed to accept connection")
				continue
			}
		}

		connCount++
		log.Info().Str("service", serviceName).Msgf("→ [#%d] New connection from %s", connCount, relayConn.RemoteAddr())

		connWG.Add(1)
		go func(relayConn net.Conn) {
			defer connWG.Done()
			if err := proxyConnection(ctx, localAddr, relayConn); err != nil {
				log.Error().Str("service", serviceName).Err(err).Msg("Proxy error")
			}
			log.Info().Str("service", serviceName).Msg("Connection closed")
		}(relayConn)
	}
}
