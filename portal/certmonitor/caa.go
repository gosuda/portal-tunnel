package certmonitor

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/miekg/dns"
)

func canonicalCAA(records []caaRecord) ([]caaRecord, error) {
	result := slices.Clone(records)
	if result == nil {
		result = []caaRecord{}
	}
	for i := range result {
		// DNS character-strings are octets. Refuse a lossy JSON conversion
		// rather than recording different policy bytes as an accepted value.
		if !utf8.ValidString(result[i].Value) {
			return nil, errMonitorCAAValueInvalid
		}
		result[i].Tag = strings.ToLower(result[i].Tag)
		if result[i].Tag == "" || len(result[i].Tag) > 255 {
			return nil, errMonitorCAATagInvalid
		}
		for _, c := range result[i].Tag {
			if c < 'a' || c > 'z' {
				if c < '0' || c > '9' {
					return nil, errMonitorCAATagInvalid
				}
			}
		}
	}
	slices.SortFunc(result, func(a, b caaRecord) int {
		if a.Flags != b.Flags {
			return int(a.Flags) - int(b.Flags)
		}
		if comparison := strings.Compare(a.Tag, b.Tag); comparison != 0 {
			return comparison
		}
		return strings.Compare(a.Value, b.Value)
	})
	return slices.Compact(result), nil
}

// RFC 8659 section 3: each CAA(domain) lookup follows aliases; if empty,
// the walk continues with the original domain's parent, not the alias's parent.
func (m *certificateMonitor) observeCAA(ctx context.Context) caaObservation {
	observation := caaObservation{ObservedAt: time.Now().UTC(), Resolver: m.config.DNSResolver}
	for owner := dns.Fqdn(m.hostname); owner != "."; {
		records, foundAt, err := m.lookupCAA(ctx, owner)
		if err != nil {
			observation.Error = err.Error()
			return observation // nil Records is unknown, never a removed policy.
		}
		if len(records) > 0 {
			observation.Records, observation.Owner = records, foundAt
			return observation
		}
		_, rest, _ := strings.Cut(owner, ".")
		owner = dns.Fqdn(rest)
	}
	observation.Records = []caaRecord{}
	return observation
}

func (m *certificateMonitor) lookupCAA(ctx context.Context, owner string) ([]caaRecord, string, error) {
	seen := map[string]bool{}
	for range 16 {
		owner = strings.ToLower(dns.Fqdn(owner))
		if seen[owner] {
			return nil, "", errMonitorCAAAliasLoop
		}
		seen[owner] = true
		query := new(dns.Msg)
		query.SetQuestion(owner, dns.TypeCAA)
		client := &dns.Client{Timeout: 3 * time.Second}
		reply, _, err := client.ExchangeContext(ctx, query, m.config.DNSResolver)
		if err == nil && reply.Truncated {
			client.Net = "tcp"
			reply, _, err = client.ExchangeContext(ctx, query, m.config.DNSResolver)
		}
		if err != nil {
			return nil, "", err
		}
		records, alias, err := caaAnswer(reply, owner)
		if err != nil {
			return nil, "", err
		}
		if len(records) != 0 {
			return records, owner, nil
		}
		if alias == "" {
			return nil, "", nil
		}
		if _, ok := dns.IsDomainName(alias); !ok {
			return nil, "", errMonitorCAAAliasInvalid
		}
		owner = alias
	}
	return nil, "", errMonitorCAAAliasLimit
}

// caaAnswer validates one DNS answer without treating aliases, referrals, or
// malformed responses as evidence that a policy was removed.
func caaAnswer(reply *dns.Msg, owner string) ([]caaRecord, string, error) {
	validEnvelope := reply.Response && len(reply.Question) == 1
	validAuthority := reply.RecursionAvailable || reply.Authoritative
	if !validEnvelope || !validAuthority {
		return nil, "", errMonitorCAAResponseInvalid
	}
	question := reply.Question[0]
	if !strings.EqualFold(question.Name, owner) || question.Qtype != dns.TypeCAA || question.Qclass != dns.ClassINET {
		return nil, "", errMonitorCAAResponseInvalid
	}
	if reply.Truncated || (reply.Rcode != dns.RcodeSuccess && reply.Rcode != dns.RcodeNameError) {
		return nil, "", fmt.Errorf("CAA DNS response unavailable: %s", dns.RcodeToString[reply.Rcode])
	}
	var records []caaRecord
	var alias string
	// Examine only this owner. Recursive replies may contain target CAA too;
	// query that target explicitly to preserve alias-loop/error semantics.
	for _, rr := range reply.Answer {
		if rr.Header().Class != dns.ClassINET {
			continue
		}
		var target string
		switch rr := rr.(type) {
		case *dns.CAA:
			if strings.EqualFold(rr.Hdr.Name, owner) {
				records = append(records, caaRecord{Flags: rr.Flag, Tag: rr.Tag, Value: rr.Value})
			}
		case *dns.CNAME:
			if !strings.EqualFold(rr.Hdr.Name, owner) {
				continue
			}
			target = rr.Target
		case *dns.DNAME:
			name := strings.ToLower(rr.Hdr.Name)
			if owner == name || !dns.IsSubDomain(name, owner) {
				continue
			}
			target = strings.TrimSuffix(owner, name) + rr.Target
		}
		if target == "" {
			continue
		}
		if alias != "" && !strings.EqualFold(alias, target) {
			return nil, "", errMonitorCAAConflictingAliases
		}
		alias = target
	}
	if alias != "" && len(records) != 0 {
		return nil, "", errMonitorCAARecordsAndAlias
	}
	if reply.Rcode == dns.RcodeNameError && len(records) != 0 {
		return nil, "", errMonitorCAANegativeWithRecords
	}
	records, err := canonicalCAA(records)
	return records, alias, err
}
