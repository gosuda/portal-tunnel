package embedded

import (
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// ServeDNS answers from one signed zone snapshot; it never performs recursion.
func (p *Provider) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	question := dns.Question{Name: ".", Qtype: dns.TypeNone}
	wildcard := false
	if len(r.Question) == 1 {
		question = r.Question[0]
	}
	if r.Opcode != dns.OpcodeQuery {
		m.Rcode = dns.RcodeNotImplemented
	} else if len(r.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
	} else {
		wildcard = p.answerQuery(m, r, question)
	}
	p.writeResponse(w, r, m)
	event := log.Debug()
	if m.Rcode == dns.RcodeServerFailure {
		// SERVFAIL is the only internal failure; client-caused codes (REFUSED,
		// FORMERR, NOTIMP) stay at Debug — :53 is a public listener and every
		// query can be flooded (issue #518 review).
		event = log.Warn()
	}
	event.
		Str("qname", question.Name).
		Str("qtype", dns.TypeToString[question.Qtype]).
		Str("rcode", dns.RcodeToString[m.Rcode]).
		Int("answers", len(m.Answer)).
		Bool("wildcard", wildcard).
		Str("remote", w.RemoteAddr().String()).
		Str("transport", w.LocalAddr().Network()).
		Msg("embedded dns query")
}

// answerQuery resolves an IN-class query against the current signed snapshot
// and sets the response code. It reports whether the answer was synthesized
// from a wildcard owner.
func (p *Provider) answerQuery(m *dns.Msg, r *dns.Msg, question dns.Question) bool {
	name := dns.CanonicalName(question.Name)
	if question.Qclass != dns.ClassINET || !dns.IsSubDomain(p.zone, name) {
		m.Rcode = dns.RcodeRefused
		return false
	}
	if question.Qtype == dns.TypeANY {
		m.Authoritative = true
		m.Rcode = dns.RcodeNotImplemented
		return false
	}
	z, err := p.signedZone(time.Now())
	if err != nil {
		m.Rcode = dns.RcodeServerFailure
		log.Error().Err(err).Msg("sign embedded dns zone")
		return false
	}
	m.Authoritative = true
	edns := r.IsEdns0()
	return p.answer(m, z, name, question.Qtype, edns != nil && edns.Do())
}

// answer fills the response for the queried name from the signed snapshot. It
// reports whether the answer was synthesized from a wildcard owner.
func (p *Provider) answer(m *dns.Msg, z *signedZone, name string, qtype uint16, do bool) bool {
	source := name
	sets, exists := z.records[name]
	var nextCloser string
	if !exists {
		// Walk to the closest existing ancestor, not merely the apex: explicit
		// records and empty non-terminals both block more distant wildcards.
		closest := name
		for z.records[closest] == nil {
			nextCloser = closest
			closest = parentName(closest)
		}
		source = "*." + closest
		sets, exists = z.records[source]
	}
	if exists {
		if qtype == dns.TypeRRSIG {
			// RRSIG is directly queryable even without DO (RFC 4035 section 3.1.1).
			types := make([]uint16, 0, len(sets))
			for typ := range sets {
				types = append(types, typ)
			}
			slices.Sort(types)
			for _, typ := range types {
				sig := dns.Copy(sets[typ].signature)
				sig.Header().Name = name
				m.Answer = append(m.Answer, sig)
			}
		} else {
			m.Answer = appendRRSet(m.Answer, sets[qtype], name, do)
		}
	} else if _, addressed := z.records["*."+p.zone][dns.TypeA]; addressed {
		m.Rcode = dns.RcodeNameError
	} else {
		// The snapshot carries no synthesized addresses, so every missing name
		// is a tenant name whose answer is still pending the public IP sync.
		// REFUSED without an SOA keeps resolvers from negative-caching it for
		// the whole sync window (issue #516); NXDOMAIN stays reserved for the
		// genuinely-missing-name case once the zone is address-capable.
		m.Rcode = dns.RcodeRefused
		return false
	}
	if len(m.Answer) == 0 {
		m.Ns = appendRRSet(m.Ns, z.records[p.zone][dns.TypeSOA], "", do)
	}
	if do {
		proofs := make(map[string]bool)
		addProof := func(set signedRRSet) {
			owner := set.records[0].Header().Name
			if !proofs[owner] {
				m.Ns = appendRRSet(m.Ns, set, "", true)
				proofs[owner] = true
			}
		}
		if nextCloser != "" {
			addProof(z.denial(nextCloser))
		}
		if len(m.Answer) == 0 {
			// Exact/wildcard NODATA proves the missing type at its actual owner.
			// NXDOMAIN additionally proves that the closest-encloser wildcard is
			// absent. Together with next-closer denial this covers deep names too.
			addProof(z.denial(source))
		}
	}
	if qtype == dns.TypeNS && name == p.zone {
		m.Extra = appendRRSet(m.Extra, z.records[p.nsName][dns.TypeA], "", do)
	}
	return exists && source != name
}

func (p *Provider) writeResponse(w dns.ResponseWriter, query, m *dns.Msg) {
	size := dns.MaxMsgSize
	if strings.HasPrefix(w.LocalAddr().Network(), "udp") {
		size = udpResponseSize(query)
	}
	if edns := query.IsEdns0(); edns != nil {
		if edns.Version() != 0 {
			m.Rcode = dns.RcodeBadVers
			m.Answer, m.Ns, m.Extra = nil, nil, nil
		}
		m.SetEdns0(uint16(udpResponseSize(query)), edns.Do())
	}
	m.Truncate(size)
	if err := w.WriteMsg(m); err != nil {
		log.Debug().Err(err).Msg("write embedded dns response")
	}
}

func udpResponseSize(query *dns.Msg) int {
	size := dns.MinMsgSize
	if edns := query.IsEdns0(); edns != nil {
		if advertised := int(edns.UDPSize()); advertised > size {
			size = advertised
		}
	}
	return size
}

func (p *Provider) aRR(name string, ip net.IP) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: recordTTL},
		A:   append(net.IP(nil), ip...),
	}
}

func (p *Provider) nsRR() *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: p.zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: recordTTL},
		Ns:  p.nsName,
	}
}

func (p *Provider) soaRRLocked() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: p.zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: recordTTL},
		Ns:      p.nsName,
		Mbox:    "hostmaster." + p.zone,
		Serial:  p.serial,
		Refresh: soaRefresh,
		Retry:   soaRetry,
		Expire:  soaExpire,
		Minttl:  recordTTL,
	}
}

func (p *Provider) txtRR(name, value string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: recordTTL},
		Txt: []string{value},
	}
}
