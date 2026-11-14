package dnsrecord

import (
	"context"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

const challengeCleanupTimeout = 30 * time.Second

// Cleanup removes only the TXT value created by a publication. It must use its
// argument for requests and credentials, rather than retain the publication's
// context. A failed publication may still return Cleanup when the remote write
// could have succeeded. A pre-existing value must return nil instead.
type Cleanup func(context.Context) error

// challengeProvider owns the records for one lego order. Lego calls Present and
// CleanUp synchronously, including cleanup after a failed Present. Keep that
// ownership: returning while a provider is still working would allow the next
// order to overlap publication or cleanup under the manager's issuance lock.
type challengeProvider struct {
	ctx             context.Context
	present         func(context.Context, string, string) (Cleanup, error)
	cleanup         map[challengeKey]Cleanup
	cleanupDeadline time.Time
	timeout         time.Duration
	interval        time.Duration
}

type challengeKey struct {
	domain  string
	keyAuth string
}

// NewChallengeProvider adapts context-aware TXT publication to lego's context-free
// provider interface. The returned cleanup action pins the original DNS target,
// so cleanup never follows a changed CNAME or removes a pre-existing value.
func NewChallengeProvider(ctx context.Context, timeout, interval time.Duration, present func(context.Context, string, string) (Cleanup, error)) challenge.Provider {
	return &challengeProvider{
		ctx: ctx, present: present, timeout: timeout, interval: interval,
		cleanup: make(map[challengeKey]Cleanup),
	}
}

func (p *challengeProvider) Present(domain, _, keyAuth string) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	key := challengeKey{domain: domain, keyAuth: keyAuth}
	if _, exists := p.cleanup[key]; exists {
		return nil
	}
	// Lego's CNAME resolver is still context-free. Check again afterwards, before
	// entering provider work; a strict deadline for all DNS lookups is separate.
	info := dns01.GetChallengeInfo(domain, keyAuth)
	if err := p.ctx.Err(); err != nil {
		return err
	}
	cleanup, err := p.present(p.ctx, info.EffectiveFQDN, info.Value)
	p.cleanup[key] = cleanup
	if ctxErr := p.ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

func (p *challengeProvider) CleanUp(domain, _, keyAuth string) error {
	key := challengeKey{domain: domain, keyAuth: keyAuth}
	cleanup := p.cleanup[key]
	if cleanup == nil {
		delete(p.cleanup, key)
		return nil
	}
	// One budget covers every cleanup in this order, not thirty seconds for each
	// name. WithoutCancel alone would remove the deadline as well as cancellation.
	if p.cleanupDeadline.IsZero() {
		p.cleanupDeadline = time.Now().Add(challengeCleanupTimeout)
	}
	ctx, cancel := context.WithDeadline(context.WithoutCancel(p.ctx), p.cleanupDeadline)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cleanup(ctx); err != nil {
		return err
	}
	delete(p.cleanup, key)
	return nil
}

func (p *challengeProvider) Timeout() (time.Duration, time.Duration) {
	return p.timeout, p.interval
}
