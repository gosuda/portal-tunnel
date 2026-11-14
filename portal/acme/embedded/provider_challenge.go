package embedded

import (
	"context"
	"slices"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
)

func (p *Provider) ChallengeProvider(ctx context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errEmbeddedDNSProviderIsNil
	}
	return dnsrecord.NewChallengeProvider(ctx, dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval, p.presentTXT), nil
}

func (p *Provider) presentTXT(ctx context.Context, fqdn, value string) (dnsrecord.Cleanup, error) {
	name, err := p.zoneHostname(fqdn)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if slices.Contains(p.txt[name], value) {
		return nil, nil
	}
	p.txt[name] = append(p.txt[name], value)
	p.bumpSerialLocked()
	return func(ctx context.Context) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		values := p.txt[name]
		idx := slices.Index(values, value)
		if idx < 0 {
			return nil
		}
		values = slices.Delete(values, idx, idx+1)
		if len(values) == 0 {
			delete(p.txt, name)
		} else {
			p.txt[name] = values
		}
		p.bumpSerialLocked()
		return nil
	}, nil
}
