package embedded

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
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
	if r.Opcode != dns.OpcodeQuery {
		m.Rcode = dns.RcodeNotImplemented
		p.writeResponse(w, r, m)
		return
	}
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		p.writeResponse(w, r, m)
		return
	}
	question := r.Question[0]
	name := dns.CanonicalName(question.Name)
	if question.Qclass != dns.ClassINET || !dns.IsSubDomain(p.zone, name) {
		m.Rcode = dns.RcodeRefused
		p.writeResponse(w, r, m)
		return
	}
	if question.Qtype == dns.TypeANY {
		m.Authoritative = true
		m.Rcode = dns.RcodeNotImplemented
		p.writeResponse(w, r, m)
		return
	}
	z, err := p.signedZone(time.Now())
	if err != nil {
		m.Rcode = dns.RcodeServerFailure
		log.Error().Err(err).Msg("sign embedded dns zone")
		p.writeResponse(w, r, m)
		return
	}
	m.Authoritative = true
	edns := r.IsEdns0()
	do := edns != nil && edns.Do()
	p.answer(m, z, name, question.Qtype, do)
	p.writeResponse(w, r, m)
}

func (p *Provider) answer(m *dns.Msg, z *signedZone, name string, qtype uint16, do bool) {
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
	} else {
		m.Rcode = dns.RcodeNameError
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

func (p *Provider) httpsRR(name string, record httpsRecordValue) *dns.HTTPS {
	return &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: recordTTL},
		Priority: record.priority,
		Target:   ".",
		Value:    record.value,
	}}
}

// parseSvcParams converts the presentation-format service parameters built
// by the ACME package (`ech="…" port=…`) into SVCB key/value pairs.
func parseSvcParams(svcParams string) ([]dns.SVCBKeyValue, error) {
	fields := strings.Fields(svcParams)
	if len(fields) == 0 {
		return nil, errors.New("https record svc params are required")
	}
	values := make([]dns.SVCBKeyValue, 0, len(fields))
	for _, field := range fields {
		key, rawValue, found := strings.Cut(field, "=")
		if !found {
			return nil, fmt.Errorf("invalid https svc param %q", field)
		}
		rawValue = strings.Trim(rawValue, `"`)
		switch key {
		case "ech":
			ech, err := base64.StdEncoding.DecodeString(rawValue)
			if err != nil {
				return nil, fmt.Errorf("decode https ech svc param: %w", err)
			}
			values = append(values, &dns.SVCBECHConfig{ECH: ech})
		case "port":
			port, err := strconv.ParseUint(rawValue, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("parse https port svc param: %w", err)
			}
			values = append(values, &dns.SVCBPort{Port: uint16(port)})
		default:
			return nil, fmt.Errorf("unsupported https svc param %q", key)
		}
	}
	return values, nil
}
