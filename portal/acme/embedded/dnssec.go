package embedded

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	errDnssecKeyPathIsRequired   = errors.New("dnssec key path is required")
	errDnssecKeyDoesNotMatchZone = errors.New("dnssec key does not match zone or supported CSK parameters")
	errInvalidDnssecPrivateKey   = errors.New("invalid dnssec private key")
)

const signatureLifetime = 24 * time.Hour
const signatureRefresh = 12 * time.Hour
const signatureSkew = 5 * time.Minute

func loadSigningKey(path, zone string) (*dns.DNSKEY, crypto.Signer, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, errDnssecKeyPathIsRequired
	}
	key := loadSigningKeyTemplate(zone)
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("read dnssec key: %w", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		return loadSigningKeyCreate(path, key)
	}
	return loadSigningKeyOpen(zone, key, data)
}

type loadSigningKeyStored struct {
	DNSKEY     string
	PrivateKey string
}

func loadSigningKeyTemplate(zone string) *dns.DNSKEY {
	return &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: recordTTL}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
}

func loadSigningKeyFresh(key *dns.DNSKEY) (crypto.PrivateKey, error) {
	private, err := key.Generate(256)
	if err != nil {
		return nil, err
	}
	for key.KeyTag() == 0 {
		if private, err = key.Generate(256); err != nil {
			return nil, err
		}
	}
	return private, nil
}

func loadSigningKeyStore(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".dnssec-key-*")
	if err != nil {
		return fmt.Errorf("create dnssec key: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("persist dnssec key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("publish dnssec key: %w", err)
	}
	return nil
}

func loadSigningKeyCreate(path string, key *dns.DNSKEY) (*dns.DNSKEY, crypto.Signer, error) {
	private, err := loadSigningKeyFresh(key)
	if err != nil {
		return nil, nil, err
	}
	data, err := json.Marshal(loadSigningKeyStored{key.String(), key.PrivateKeyString(private)})
	if err != nil {
		return nil, nil, err
	}
	if err := loadSigningKeyStore(path, data); err != nil {
		return nil, nil, err
	}
	return key, private.(crypto.Signer), nil
}

func loadSigningKeyParse(zone string, template *dns.DNSKEY, stored loadSigningKeyStored) (*dns.DNSKEY, error) {
	rr, err := dns.NewRR(stored.DNSKEY)
	if err != nil {
		return nil, fmt.Errorf("parse dnskey: %w", err)
	}
	loaded, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, errDnssecKeyDoesNotMatchZone
	}
	if loaded.Hdr.Name != zone || loaded.Hdr.Class != dns.ClassINET {
		return nil, errDnssecKeyDoesNotMatchZone
	}
	if loaded.Flags != template.Flags || loaded.Protocol != template.Protocol || loaded.Algorithm != template.Algorithm {
		return nil, errDnssecKeyDoesNotMatchZone
	}
	loaded.Hdr.Ttl = recordTTL
	return loaded, nil
}

func loadSigningKeyVerifyPair(zone string, loaded *dns.DNSKEY, privateKey string) (crypto.Signer, error) {
	private, err := loaded.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parse dnssec private key: %w", err)
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		return nil, errInvalidDnssecPrivateKey
	}
	sig := &dns.RRSIG{KeyTag: loaded.KeyTag(), SignerName: zone, Algorithm: loaded.Algorithm, Inception: 1, Expiration: 2}
	if err := sig.Sign(signer, []dns.RR{loaded}); err != nil {
		return nil, err
	}
	if err := sig.Verify(loaded, []dns.RR{loaded}); err != nil {
		return nil, fmt.Errorf("dnssec public/private key mismatch: %w", err)
	}
	return signer, nil
}

func loadSigningKeyOpen(zone string, template *dns.DNSKEY, data []byte) (*dns.DNSKEY, crypto.Signer, error) {
	var stored loadSigningKeyStored
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, nil, fmt.Errorf("decode dnssec key: %w", err)
	}
	loaded, err := loadSigningKeyParse(zone, template, stored)
	if err != nil {
		return nil, nil, err
	}
	signer, err := loadSigningKeyVerifyPair(zone, loaded, stored.PrivateKey)
	if err != nil {
		return nil, nil, err
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

func (p *Provider) signedZone(now time.Time) (*signedZone, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if z := p.signed; z != nil && z.serial == p.serial && now.Before(z.refresh) && !now.Before(z.inception) {
		return z, nil
	}
	z := &signedZone{serial: p.serial, refresh: now.Add(signatureRefresh), inception: now.Add(-signatureSkew), records: make(map[string]map[uint16]signedRRSet)}
	p.signedZoneBaseLocked(z)
	p.signedZoneParentsLocked(z)
	p.signedZoneSynthesizeLocked(z)
	signedZoneSealLocked(z)
	if err := p.signedZoneSignLocked(z, now); err != nil {
		return nil, err
	}
	p.signed = z
	return z, nil
}

func signedZoneAddLocked(z *signedZone, rr dns.RR) {
	h := rr.Header()
	if z.records[h.Name] == nil {
		z.records[h.Name] = make(map[uint16]signedRRSet)
	}
	set := z.records[h.Name][h.Rrtype]
	if (h.Rrtype == dns.TypeA || h.Rrtype == dns.TypeAAAA) && len(set.records) != 0 {
		return
	}
	set.records = append(set.records, rr)
	z.records[h.Name][h.Rrtype] = set
}

func (p *Provider) signedZoneBaseLocked(z *signedZone) {
	signedZoneAddLocked(z, p.nsRR())
	signedZoneAddLocked(z, p.soaRRLocked())
	signedZoneAddLocked(z, p.key)
	for name, values := range p.txt {
		for _, value := range values {
			signedZoneAddLocked(z, p.txtRR(name, value))
		}
	}
	if p.ipv4 != nil {
		signedZoneAddLocked(z, p.aRR(p.nsName, p.ipv4))
	}
	if p.ipv6 != nil {
		signedZoneAddLocked(z, p.aaaaRR(p.nsName, p.ipv6))
	}
}

func (p *Provider) signedZoneParentsLocked(z *signedZone) {
	z.names = slices.Collect(maps.Keys(z.records))
	for _, name := range z.names {
		for parent := parentName(name); dns.IsSubDomain(p.zone, parent); parent = parentName(parent) {
			if z.records[parent] == nil {
				z.records[parent] = make(map[uint16]signedRRSet)
			}
		}
	}
}

func (p *Provider) signedZoneSynthesizeLocked(z *signedZone) {
	nodes := slices.Collect(maps.Keys(z.records))
	for _, name := range nodes {
		p.signedZoneSynthesizeAddressLocked(z, name)
	}
}

func (p *Provider) signedZoneSynthesizeAddressLocked(z *signedZone, name string) {
	if p.ipv4 != nil {
		signedZoneAddLocked(z, p.aRR(name, p.ipv4))
	}
	if p.ipv6 != nil {
		signedZoneAddLocked(z, p.aaaaRR(name, p.ipv6))
	}
	if _, valid := dns.IsDomainName("*." + name); valid && !strings.HasPrefix(name, "*.") {
		if p.ipv4 != nil {
			signedZoneAddLocked(z, p.aRR("*."+name, p.ipv4))
		}
		if p.ipv6 != nil {
			signedZoneAddLocked(z, p.aaaaRR("*."+name, p.ipv6))
		}
	}
}

func signedZoneSealLocked(z *signedZone) {
	z.names = slices.Collect(maps.Keys(z.records))
	slices.SortFunc(z.names, compareDNSNames)
	for i, name := range z.names {
		types := signedZoneSealTypesLocked(z, name)
		signedZoneAddLocked(z, &dns.NSEC{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: recordTTL}, NextDomain: z.names[(i+1)%len(z.names)], TypeBitMap: types})
	}
}

func signedZoneSealTypesLocked(z *signedZone, name string) []uint16 {
	types := []uint16{dns.TypeNSEC, dns.TypeRRSIG}
	types = append(types, slices.Collect(maps.Keys(z.records[name]))...)
	slices.Sort(types)
	return types
}

func (p *Provider) signedZoneSignLocked(z *signedZone, now time.Time) error {
	for name, sets := range z.records {
		if err := p.signedZoneSignNameLocked(z, name, sets, now); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provider) signedZoneSignNameLocked(z *signedZone, name string, sets map[uint16]signedRRSet, now time.Time) error {
	for typ, set := range sets {
		sig := &dns.RRSIG{Hdr: dns.RR_Header{Ttl: recordTTL}, KeyTag: p.key.KeyTag(), SignerName: p.zone, Algorithm: p.key.Algorithm, Inception: uint32(z.inception.Unix()), Expiration: uint32(now.Add(signatureLifetime).Unix())}
		if err := sig.Sign(p.signer, set.records); err != nil {
			return fmt.Errorf("sign embedded dns zone %s %s: %w", name, dns.TypeToString[typ], err)
		}
		set.signature = sig
		sets[typ] = set
	}
	return nil
}

func parentName(name string) string {
	offset, end := dns.NextLabel(name, 0)
	if end {
		return "."
	}
	return name[offset:]
}

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
