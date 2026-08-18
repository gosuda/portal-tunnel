package embedded

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// ServeDNS answers authoritatively for the relay zone. Recursion is never
// performed: queries outside the zone are refused and unknown names resolve
// through wildcard-style A synthesis instead of NXDOMAIN.
func (p *Provider) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = true

	if r.Opcode != dns.OpcodeQuery || len(r.Question) == 0 {
		m.Rcode = dns.RcodeNotImplemented
		p.writeResponse(w, r, m)
		return
	}

	question := r.Question[0]
	name := strings.ToLower(question.Name)
	if !dns.IsSubDomain(p.zone, name) {
		m.Rcode = dns.RcodeRefused
		p.writeResponse(w, r, m)
		return
	}

	p.answer(m, name, question.Qtype)
	p.writeResponse(w, r, m)
}

func (p *Provider) answer(m *dns.Msg, name string, qtype uint16) {
	switch qtype {
	case dns.TypeA:
		if ip := p.publicIPv4(); ip != nil {
			m.Answer = append(m.Answer, p.aRR(name, ip))
		}
	case dns.TypeNS:
		if name == p.zone {
			m.Answer = append(m.Answer, p.nsRR())
			if dns.IsSubDomain(p.zone, p.nsName) {
				if ip := p.publicIPv4(); ip != nil {
					m.Extra = append(m.Extra, p.aRR(p.nsName, ip))
				}
			}
		}
	case dns.TypeSOA:
		if name == p.zone {
			m.Answer = append(m.Answer, p.soaRR())
		}
	case dns.TypeTXT:
		for _, value := range p.txtValues(name) {
			m.Answer = append(m.Answer, p.txtRR(name, value))
		}
	case dns.TypeHTTPS:
		if record := p.httpsValue(name); record.value != nil {
			m.Answer = append(m.Answer, p.httpsRR(name, record))
		}
	case dns.TypeANY:
		m.Rcode = dns.RcodeNotImplemented
		return
	}

	if len(m.Answer) == 0 && m.Rcode == dns.RcodeSuccess {
		m.Ns = append(m.Ns, p.soaRR())
	}
}

func (p *Provider) writeResponse(w dns.ResponseWriter, query, m *dns.Msg) {
	size := dns.MaxMsgSize
	if strings.HasPrefix(w.LocalAddr().Network(), "udp") {
		size = udpResponseSize(query)
		if query.IsEdns0() != nil {
			m.SetEdns0(uint16(size), false)
		}
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

func (p *Provider) publicIPv4() net.IP {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.ipv4 == nil {
		return nil
	}
	return append(net.IP(nil), p.ipv4...)
}

func (p *Provider) txtValues(name string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.txt[name]...)
}

func (p *Provider) httpsValue(name string) httpsRecordValue {
	p.mu.RLock()
	defer p.mu.RUnlock()
	record := p.https[name]
	return httpsRecordValue{priority: record.priority, value: record.value}
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

func (p *Provider) soaRR() *dns.SOA {
	p.mu.RLock()
	serial := p.serial
	p.mu.RUnlock()
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: p.zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: recordTTL},
		Ns:      p.nsName,
		Mbox:    "hostmaster." + p.zone,
		Serial:  serial,
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
