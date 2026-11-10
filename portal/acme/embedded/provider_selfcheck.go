package embedded

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

func (p *Provider) verifyDelegatedPath(ip net.IP) {
	label := make([]byte, 8)
	if _, err := rand.Read(label); err != nil {
		log.Warn().Err(err).Msg("dns self-check random label")
		return
	}
	name := hex.EncodeToString(label) + "." + p.zone
	ctx, cancel := context.WithTimeout(context.Background(), selfCheckTimeout)
	defer cancel()
	started := time.Now()
	network := "ip4"
	if ip.To4() == nil {
		network = "ip6"
	}
	addrs, err := net.DefaultResolver.LookupIP(ctx, network, name)
	elapsed := time.Since(started)
	if err != nil {
		log.Warn().Err(err).Str("name", name).Dur("elapsed", elapsed).Msg("dns self-check failed")
		return
	}
	if slices.ContainsFunc(addrs, func(addr net.IP) bool { return addr.Equal(ip) }) {
		log.Info().Str("name", name).Str("resolved", ip.String()).Dur("elapsed", elapsed).Msg("dns self-check passed")
		return
	}
	resolved := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		resolved = append(resolved, addr.String())
	}
	log.Warn().
		Str("name", name).
		Str("resolved", strings.Join(resolved, ",")).
		Str("expected", ip.String()).
		Dur("elapsed", elapsed).
		Msg("dns self-check resolved a different address")
}
