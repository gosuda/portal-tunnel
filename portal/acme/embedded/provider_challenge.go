package embedded

import (
	"context"
	"slices"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

func (p *Provider) ChallengeProvider(context.Context) (challenge.Provider, error) {
	return p, nil
}

func (p *Provider) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	name, err := p.zoneHostname(info.EffectiveFQDN)
	if err != nil {
		return err
	}
	return p.EnsureTXTRecord(context.Background(), name, info.Value)
}

func (p *Provider) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	name, err := p.zoneHostname(info.EffectiveFQDN)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	values := p.txt[name]
	idx := slices.Index(values, info.Value)
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
}
