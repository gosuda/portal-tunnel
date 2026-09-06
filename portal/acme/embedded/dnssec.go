package embedded

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const signatureLifetime = 24 * time.Hour
const signatureRefresh = 12 * time.Hour
const signatureSkew = 5 * time.Minute

// A single file binds the private key to its zone and DNSKEY. Never regenerate
// an unreadable or malformed existing key: the parent DS may already trust it.
func loadSigningKey(path, zone string) (*dns.DNSKEY, crypto.Signer, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, errors.New("dnssec key path is required")
	}
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: recordTTL}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	type storedKey struct {
		DNSKEY     string
		PrivateKey string
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		private, err := key.Generate(256)
		if err != nil {
			return nil, nil, err
		}
		// miekg/dns treats key tag zero as an unset signing parameter. Avoid
		// persisting that otherwise-valid key, which this signer cannot use.
		for key.KeyTag() == 0 {
			private, err = key.Generate(256)
			if err != nil {
				return nil, nil, err
			}
		}
		data, err := json.Marshal(storedKey{key.String(), key.PrivateKeyString(private)})
		if err != nil {
			return nil, nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, nil, err
		}
		// Exclusive creation prevents simultaneous starts from replacing a key. A
		// partial write fails closed on subsequent starts, rather than rotating it.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, nil, fmt.Errorf("create dnssec key: %w", err)
		}
		if err := restrictKeyPermissions(path); err != nil {
			_ = f.Close()
			return nil, nil, fmt.Errorf("restrict dnssec key permissions: %w", err)
		}
		_, writeErr := f.Write(data)
		syncErr := f.Sync()
		closeErr := f.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return nil, nil, fmt.Errorf("persist dnssec key: %w", err)
		}
		return key, private.(crypto.Signer), nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("stat dnssec key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("dnssec key must be a regular file, not a symlink")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, nil, errors.New("dnssec private key permissions must be 0600 or stricter")
	}
	if err := restrictKeyPermissions(path); err != nil {
		return nil, nil, fmt.Errorf("restrict dnssec key permissions: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, nil, errors.New("dnssec key changed while opening")
	}
	var stored storedKey
	decoder := json.NewDecoder(io.LimitReader(f, 16384))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return nil, nil, fmt.Errorf("decode dnssec key: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, nil, errors.New("unexpected trailing dnssec key data")
	}
	rr, err := dns.NewRR(stored.DNSKEY)
	if err != nil {
		return nil, nil, fmt.Errorf("parse dnskey: %w", err)
	}
	loaded, ok := rr.(*dns.DNSKEY)
	if !ok || loaded.Hdr.Name != zone || loaded.Hdr.Class != dns.ClassINET || loaded.Flags != key.Flags || loaded.Protocol != key.Protocol || loaded.Algorithm != key.Algorithm {
		return nil, nil, errors.New("dnssec key does not match zone or supported CSK parameters")
	}
	loaded.Hdr.Ttl = recordTTL
	private, err := loaded.NewPrivateKey(stored.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse dnssec private key: %w", err)
	}
	signer, ok := private.(*ecdsa.PrivateKey)
	if !ok || signer.D == nil || signer.D.Sign() <= 0 || signer.D.Cmp(signer.Curve.Params().N) >= 0 {
		return nil, nil, errors.New("invalid dnssec private key")
	}
	// The BIND parser does not check that the public and private keys match.
	sig := &dns.RRSIG{KeyTag: loaded.KeyTag(), SignerName: zone, Algorithm: loaded.Algorithm, Inception: 1, Expiration: 2}
	if err := sig.Sign(signer, []dns.RR{loaded}); err != nil {
		return nil, nil, err
	}
	if err := sig.Verify(loaded, []dns.RR{loaded}); err != nil {
		return nil, nil, fmt.Errorf("dnssec public/private key mismatch: %w", err)
	}
	return loaded, signer, nil
}

type signedRRSet struct {
	records   []dns.RR
	signature *dns.RRSIG
}

type signedZone struct {
	serial    uint32
	refresh   time.Time
	inception time.Time
	names     []string
	records   map[string]map[uint16]signedRRSet
}

// signedZone is the one immutable authoritative snapshot. Mutations invalidate
// it by serial; refresh is lazy, before answering, so idle zones cannot serve
// expired signatures. Failed signing returns SERVFAIL, never unsigned data.
func (p *Provider) signedZone(now time.Time) (*signedZone, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if z := p.signed; z != nil && z.serial == p.serial && now.Before(z.refresh) && !now.Before(z.inception) {
		return z, nil
	}
	z := &signedZone{serial: p.serial, refresh: now.Add(signatureRefresh), inception: now.Add(-signatureSkew), records: make(map[string]map[uint16]signedRRSet)}
	add := func(rr dns.RR) {
		h := rr.Header()
		if z.records[h.Name] == nil {
			z.records[h.Name] = make(map[uint16]signedRRSet)
		}
		set := z.records[h.Name][h.Rrtype]
		if h.Rrtype == dns.TypeA && len(set.records) != 0 {
			return
		}
		set.records = append(set.records, rr)
		z.records[h.Name][h.Rrtype] = set
	}
	add(p.nsRR())
	add(p.soaRRLocked())
	add(p.key)
	for name, values := range p.txt {
		for _, value := range values {
			add(p.txtRR(name, value))
		}
	}
	for name, value := range p.https {
		add(p.httpsRR(name, value))
	}
	// Include empty non-terminals. When the relay has an address, materialize A
	// and wildcard A at every closest encloser so explicit TXT/HTTPS records do
	// not shadow zone-wide address synthesis (RFC 4592).
	if p.ipv4 != nil {
		add(p.aRR(p.nsName, p.ipv4))
	}
	for name := range z.records {
		z.names = append(z.names, name)
	}
	for _, name := range z.names {
		for parent := parentName(name); dns.IsSubDomain(p.zone, parent); parent = parentName(parent) {
			if z.records[parent] == nil {
				z.records[parent] = make(map[uint16]signedRRSet)
			}
			if parent == p.zone {
				break
			}
		}
	}
	if p.ipv4 != nil {
		nodes := make([]string, 0, len(z.records))
		for name := range z.records {
			nodes = append(nodes, name)
		}
		for _, name := range nodes {
			add(p.aRR(name, p.ipv4))
			// An explicit wildcard already represents synthesis at its parent, not a
			// separate closest encloser requiring another wildcard beneath it.
			if _, valid := dns.IsDomainName("*." + name); valid && !strings.HasPrefix(name, "*.") {
				add(p.aRR("*."+name, p.ipv4))
			}
		}
	}
	z.names = z.names[:0]
	for name := range z.records {
		z.names = append(z.names, name)
	}
	slices.SortFunc(z.names, compareDNSNames)
	for i, name := range z.names {
		types := []uint16{dns.TypeNSEC, dns.TypeRRSIG}
		for typ := range z.records[name] {
			types = append(types, typ)
		}
		slices.Sort(types)
		add(&dns.NSEC{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: recordTTL}, NextDomain: z.names[(i+1)%len(z.names)], TypeBitMap: types})
	}
	for name, sets := range z.records {
		for typ, set := range sets {
			sig := &dns.RRSIG{Hdr: dns.RR_Header{Ttl: recordTTL}, KeyTag: p.key.KeyTag(), SignerName: p.zone, Algorithm: p.key.Algorithm, Inception: uint32(z.inception.Unix()), Expiration: uint32(now.Add(signatureLifetime).Unix())}
			if err := sig.Sign(p.signer, set.records); err != nil {
				return nil, fmt.Errorf("sign %s %s: %w", name, dns.TypeToString[typ], err)
			}
			set.signature = sig
			sets[typ] = set
		}
	}
	p.signed = z
	return z, nil
}

func parentName(name string) string {
	offset, end := dns.NextLabel(name, 0)
	if end {
		return "."
	}
	return name[offset:]
}

// RFC 4034 section 6.1 orders labels from the root outward, by unsigned
// unescaped octets, with a shorter label sorting first. Wire packing also
// handles escaped labels in queries, not only hostname-style owner names.
func compareDNSNames(a, b string) int {
	var x, y [256]byte
	var xi, yi [128]int
	labels := func(name string, wire []byte, offsets []int) int {
		n, _ := dns.PackDomainName(dns.CanonicalName(name), wire, 0, nil, false)
		count := 0
		for i := 0; i < n && wire[i] != 0; {
			offsets[count] = i
			count++
			i += int(wire[i]) + 1
		}
		return count
	}
	xn, yn := labels(a, x[:], xi[:]), labels(b, y[:], yi[:])
	for i, j := xn-1, yn-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		xo, yo := xi[i], yi[j]
		if c := bytes.Compare(x[xo+1:xo+1+int(x[xo])], y[yo+1:yo+1+int(y[yo])]); c != 0 {
			return c
		}
	}
	return xn - yn
}

func (z *signedZone) denial(name string) signedRRSet {
	i, found := slices.BinarySearchFunc(z.names, name, compareDNSNames)
	if !found {
		i = (i + len(z.names) - 1) % len(z.names)
	}
	return z.records[z.names[i]][dns.TypeNSEC]
}

func appendRRSet(section []dns.RR, set signedRRSet, owner string, do bool) []dns.RR {
	for _, rr := range set.records {
		copy := dns.Copy(rr)
		if owner != "" {
			copy.Header().Name = owner
		}
		section = append(section, copy)
	}
	if do && set.signature != nil {
		sig := dns.Copy(set.signature)
		if owner != "" {
			sig.Header().Name = owner
		}
		section = append(section, sig)
	}
	return section
}
