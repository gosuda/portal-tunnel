// Package dns implements PGNS Stage 1 deterministic epoch pre-signed DNSSEC
// (Algorithm 13 ECDSAP256SHA256 + RFC 5155/9276 NSEC3) with zero hot-path signing.
package dns

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"

	"github.com/gosuda/portal-tunnel/v2/pgns"
)

const (
	BaseRecordTTL         uint32 = 30
	BaseAuthRecordTTL     uint32 = 60
	ApexRecordTTL         uint32 = 300
	RRSIGInceptionSkew    uint64 = 5 * 60
	DefaultRRSIGLifetime  uint64 = 12 * 3600
	ACMEChallengeLifetime uint64 = 15 * 60
	LeafExpiryGrace       uint64 = 5 * 60
	RRSIGRefreshThreshold uint64 = 6 * 3600
	DefaultRefreshBuckets uint64 = 24
)

var (
	errDNSSECKeyInvalid = errors.New("pgns/dns: invalid DNSSEC Algorithm 13 key")
)

// NameserverGlue defines one authoritative NS host and optional in-bailiwick glue IPs.
type NameserverGlue struct {
	Host string
	IPv4 net.IP
	IPv6 net.IP
}

// Stage1Keys holds the Algorithm 13 KSK-signed DNSKEY RRset and the ZSK signer.
// The KSK private key is not retained after DNSKEY RRset signing.
type Stage1Keys struct {
	KSK         *dns.DNSKEY
	ZSK         *dns.DNSKEY
	ZSKSigner   crypto.Signer
	DNSKEYRRSIG *dns.RRSIG
}

// GenerateStage1Keys generates a fresh Algorithm 13 KSK (Flags=257) + ZSK (Flags=256),
// signs the apex DNSKEY RRset with the offline KSK, and discards the KSK private key.
func GenerateStage1Keys(zone string, inception, expiration uint32) (Stage1Keys, error) {
	normZone, err := pgns.NormalizeZone(zone)
	if err != nil {
		return Stage1Keys{}, err
	}
	zoneFQDN := dns.Fqdn(normZone)
	ksk, kskSigner, err := generateAlg13Key(zoneFQDN, 257)
	if err != nil {
		return Stage1Keys{}, err
	}
	zsk, zskSigner, err := generateAlg13Key(zoneFQDN, 256)
	if err != nil {
		return Stage1Keys{}, err
	}
	return NewStage1KeysWithKSK(normZone, ksk, kskSigner, zsk, zskSigner, inception, expiration)
}

// NewStage1KeysWithKSK builds Stage1Keys from caller-supplied Algorithm 13 KSK & ZSK pairs.
func NewStage1KeysWithKSK(zone string, ksk *dns.DNSKEY, kskSigner crypto.Signer, zsk *dns.DNSKEY, zskSigner crypto.Signer, inception, expiration uint32) (Stage1Keys, error) {
	normZone, err := pgns.NormalizeZone(zone)
	if err != nil {
		return Stage1Keys{}, err
	}
	zoneFQDN := dns.Fqdn(normZone)
	if ksk == nil || zsk == nil || kskSigner == nil || zskSigner == nil {
		return Stage1Keys{}, errDNSSECKeyInvalid
	}
	if ksk.Algorithm != dns.ECDSAP256SHA256 || zsk.Algorithm != dns.ECDSAP256SHA256 {
		return Stage1Keys{}, fmt.Errorf("%w: must use ECDSAP256SHA256", errDNSSECKeyInvalid)
	}
	kskCopy := dns.Copy(ksk).(*dns.DNSKEY)
	zskCopy := dns.Copy(zsk).(*dns.DNSKEY)
	kskCopy.Hdr.Name = zoneFQDN
	kskCopy.Hdr.Ttl = ApexRecordTTL
	zskCopy.Hdr.Name = zoneFQDN
	zskCopy.Hdr.Ttl = ApexRecordTTL

	kskSigner = wrapDeterministicP256Signer(kskSigner)
	zskSigner = wrapDeterministicP256Signer(zskSigner)
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: zoneFQDN, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ApexRecordTTL},
		KeyTag:     kskCopy.KeyTag(),
		SignerName: zoneFQDN,
		Algorithm:  kskCopy.Algorithm,
		Inception:  inception,
		Expiration: expiration,
	}
	if err := rrsig.Sign(kskSigner, []dns.RR{kskCopy, zskCopy}); err != nil {
		return Stage1Keys{}, fmt.Errorf("sign apex DNSKEY with KSK: %w", err)
	}
	return Stage1Keys{
		KSK:         kskCopy,
		ZSK:         zskCopy,
		ZSKSigner:   zskSigner,
		DNSKEYRRSIG: rrsig,
	}, nil
}

// DSRecord returns the SHA-256 DS delegation record for the parent zone.
func (k Stage1Keys) DSRecord() *dns.DS {
	return k.KSK.ToDS(dns.SHA256)
}

var p256Order, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

type deterministicP256Signer struct {
	pub    crypto.PublicKey
	d      *big.Int
	dBytes [32]byte
}

func wrapDeterministicP256Signer(signer crypto.Signer) crypto.Signer {
	ecPriv, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		return signer
	}
	ecdhKey, err := ecPriv.ECDH()
	if err != nil || ecdhKey.Curve() != ecdh.P256() {
		return signer
	}
	raw := ecdhKey.Bytes()
	if len(raw) != 32 {
		return signer
	}
	var dBytes [32]byte
	copy(dBytes[:], raw)
	return &deterministicP256Signer{
		pub:    ecPriv.Public(),
		d:      new(big.Int).SetBytes(raw),
		dBytes: dBytes,
	}
}

func (s *deterministicP256Signer) Public() crypto.PublicKey {
	return s.pub
}

func (s *deterministicP256Signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("%w: expected 32-byte SHA-256 digest, got %d", errDNSSECKeyInvalid, len(digest))
	}
	z := new(big.Int).SetBytes(digest)
	zModQ := new(big.Int).Mod(z, p256Order)
	var h1Octets [32]byte
	zModQ.FillBytes(h1Octets[:])

	var v, k [32]byte
	for i := range v {
		v[i] = 0x01
	}
	k = hmacSHA256(k[:], v[:], []byte{0x00}, s.dBytes[:], h1Octets[:])
	v = hmacSHA256(k[:], v[:])
	k = hmacSHA256(k[:], v[:], []byte{0x01}, s.dBytes[:], h1Octets[:])
	v = hmacSHA256(k[:], v[:])

	for {
		v = hmacSHA256(k[:], v[:])
		kCand := new(big.Int).SetBytes(v[:])
		if kCand.Sign() > 0 && kCand.Cmp(p256Order) < 0 {
			if ecdhK, err := ecdh.P256().NewPrivateKey(v[:]); err == nil {
				pubBytes := ecdhK.PublicKey().Bytes()
				r := new(big.Int).SetBytes(pubBytes[1:33])
				r.Mod(r, p256Order)
				if r.Sign() != 0 {
					kInv := new(big.Int).ModInverse(kCand, p256Order)
					sv := new(big.Int).Mul(r, s.d)
					sv.Add(sv, z)
					sv.Mul(sv, kInv)
					sv.Mod(sv, p256Order)
					if sv.Sign() != 0 {
						return asn1.Marshal(struct{ R, S *big.Int }{R: r, S: sv})
					}
				}
			}
		}
		k = hmacSHA256(k[:], v[:], []byte{0x00})
		v = hmacSHA256(k[:], v[:])
	}
}

func hmacSHA256(key []byte, parts ...[]byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	for _, p := range parts {
		_, _ = mac.Write(p)
	}
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func generateAlg13Key(zoneFQDN string, flags uint16) (*dns.DNSKEY, crypto.Signer, error) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zoneFQDN, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: ApexRecordTTL},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		return nil, nil, err
	}
	for key.KeyTag() == 0 {
		if priv, err = key.Generate(256); err != nil {
			return nil, nil, err
		}
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, nil, errDNSSECKeyInvalid
	}
	return key, signer, nil
}

// Config configures a PGNS authoritative DNSSEC signer and zero-signing edge server.
type Config struct {
	Zone           string
	WitnessSet     pgns.WitnessSet
	Keys           Stage1Keys
	Nameservers    []NameserverGlue
	RefreshBuckets uint64
}

type signedRRSet struct {
	records   []dns.RR
	rrsig     *dns.RRSIG
	expiresAt uint64 // max source leaf expiry; 0 if permanent apex/glue
}

type nsec3Entry struct {
	hashUpper string
	rr        *dns.NSEC3
	rrsig     *dns.RRSIG
}

type zoneSnapshot struct {
	zoneFQDN     string
	rrsets       map[string]map[uint16]signedRRSet
	activeOwners map[string]struct{}
	nsec3ByHash  map[string]nsec3Entry
	sortedHashes []string
	soaSet       signedRRSet
}

// Server maintains deterministic epoch pre-signed DNSSEC state and answers
// queries directly from the static in-memory snapshot with zero online crypto.
type Server struct {
	zone           string
	zoneFQDN       string
	witnessSet     pgns.WitnessSet
	keys           Stage1Keys
	nameservers    []NameserverGlue
	refreshBuckets uint64

	applyMu   sync.Mutex
	hasEpoch  bool
	lastEpoch uint64
	lastTime  uint64
	leaves    map[string]pgns.PortalLeafRecord
	rrCache   map[string]map[uint16]signedRRSet
	nsec3Map  map[string]nsec3Entry
	snapshot  atomic.Pointer[zoneSnapshot]
}

// New initializes a deterministic PGNS DNSSEC signer and query server.
func New(cfg Config) (*Server, error) {
	normZone, err := pgns.NormalizeZone(cfg.Zone)
	if err != nil {
		return nil, err
	}
	if cfg.WitnessSet.Threshold <= 0 || cfg.WitnessSet.Threshold > len(cfg.WitnessSet.Witnesses) {
		return nil, pgns.ErrInvalidCheckpoint
	}
	if cfg.Keys.KSK == nil || cfg.Keys.ZSK == nil || cfg.Keys.ZSKSigner == nil || cfg.Keys.DNSKEYRRSIG == nil {
		return nil, errDNSSECKeyInvalid
	}
	nsList := cfg.Nameservers
	if len(nsList) == 0 {
		nsList = []NameserverGlue{{Host: "ns1." + normZone, IPv4: net.IPv4(192, 0, 2, 53)}}
	}
	buckets := cfg.RefreshBuckets
	if buckets == 0 {
		buckets = DefaultRefreshBuckets
	}
	return &Server{
		zone:           normZone,
		zoneFQDN:       dns.Fqdn(normZone),
		witnessSet:     cfg.WitnessSet,
		keys:           cfg.Keys,
		nameservers:    slices.Clone(nsList),
		refreshBuckets: buckets,
		leaves:         make(map[string]pgns.PortalLeafRecord),
		rrCache:        make(map[string]map[uint16]signedRRSet),
		nsec3Map:       make(map[string]nsec3Entry),
	}, nil
}

// ApplyEpoch verifies rawCheckpoint (witness quorum) and rawBatch against SMTRoot_e,
// deterministically updates RRsets and NSEC3 intervals anchored strictly to T_e,
// and swaps the active DNS snapshot atomically.
func (s *Server) ApplyEpoch(rawCheckpoint, rawBatch []byte) error {
	cp, _, err := pgns.ParseAndVerifySignedCheckpoint(rawCheckpoint, s.zone, s.witnessSet)
	if err != nil {
		return err
	}
	batch, err := pgns.UnmarshalBatchTransitionProof(rawBatch)
	if err != nil {
		return err
	}
	if batch.Zone != s.zone || batch.Epoch != cp.Epoch || batch.Timestamp != cp.Timestamp || batch.NewSMTRoot != cp.SMTRoot {
		return fmt.Errorf("%w: checkpoint/batch header mismatch", pgns.ErrInvalidBatch)
	}

	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	if !s.hasEpoch && cp.Epoch != 0 {
		return fmt.Errorf("%w: expected genesis epoch 0, got %d", pgns.ErrInvalidBatch, cp.Epoch)
	}
	if s.hasEpoch && cp.Epoch != s.lastEpoch+1 {
		return fmt.Errorf("%w: expected epoch %d, got %d", pgns.ErrInvalidBatch, s.lastEpoch+1, cp.Epoch)
	}

	dirtyLeaves := make(map[string]struct{}, len(batch.TxEntries))
	for _, tx := range batch.TxEntries {
		s.leaves[tx.Leaf.FQDN] = tx.Leaf
		dirtyLeaves[tx.Leaf.FQDN] = struct{}{}
	}
	te := cp.Timestamp
	// Prune leaves expired at T_e or mark leaves whose clamping/bucket refresh triggers.
	for fqdn, leaf := range s.leaves {
		if te >= leaf.ExpiresAt {
			delete(s.leaves, fqdn)
			dirtyLeaves[fqdn] = struct{}{}
			continue
		}
		if s.leafNeedsRefresh(fqdn, leaf, cp.Epoch, te) {
			dirtyLeaves[fqdn] = struct{}{}
		}
	}

	if err := s.rebuildZoneLocked(cp.Epoch, te, dirtyLeaves); err != nil {
		return err
	}
	s.hasEpoch = true
	s.lastEpoch = cp.Epoch
	s.lastTime = te
	return nil
}

func (s *Server) leafNeedsRefresh(fqdn string, leaf pgns.PortalLeafRecord, epoch, te uint64) bool {
	if leaf.ExpiresAt-te <= uint64(BaseAuthRecordTTL) {
		return true
	}
	owner := dns.Fqdn(fqdn)
	sets := s.rrCache[owner]
	if len(sets) == 0 {
		return true
	}
	key := pgns.SMTKey(fqdn)
	bucket := binary.BigEndian.Uint64(key[:8]) % s.refreshBuckets
	isBucketEpoch := bucket == (epoch % s.refreshBuckets)
	for rtype, set := range sets {
		if set.rrsig == nil {
			return true
		}
		exp := uint64(set.rrsig.Expiration)
		if exp <= te {
			return true
		}
		if isBucketEpoch && (exp-te <= RRSIGRefreshThreshold || rtype == dns.TypeA || rtype == dns.TypeAAAA || rtype == dns.TypeHTTPS || rtype == dns.TypeCAA) {
			return true
		}
	}
	return s.subownerNeedsRefresh(fqdn, te)
}

func (s *Server) subownerNeedsRefresh(fqdn string, te uint64) bool {
	for _, prefix := range []string{"_acme-challenge.", "_validation-persist."} {
		sets := s.rrCache[prefix+dns.Fqdn(fqdn)]
		for _, set := range sets {
			if set.rrsig == nil || uint64(set.rrsig.Expiration) <= te+5*60 {
				return true
			}
		}
	}
	return false
}

func (s *Server) rebuildZoneLocked(epoch, te uint64, dirtyLeaves map[string]struct{}) error {
	nextRR := make(map[string]map[uint16]signedRRSet, len(s.rrCache)+len(dirtyLeaves))
	for fqdn, leaf := range s.leaves {
		owner := dns.Fqdn(fqdn)
		_, isDirty := dirtyLeaves[fqdn]
		if !isDirty {
			if existing, ok := s.rrCache[owner]; ok {
				nextRR[owner] = cloneTypeMap(existing)
				for _, sub := range []string{"_acme-challenge." + owner, "_validation-persist." + owner} {
					if subSet, ok := s.rrCache[sub]; ok {
						nextRR[sub] = cloneTypeMap(subSet)
					}
				}
				continue
			}
		}
		if err := s.synthesizeLeafOwner(nextRR, leaf, te); err != nil {
			return err
		}
	}

	if err := s.synthesizeApexAndGlue(nextRR, epoch, te); err != nil {
		return err
	}

	activeOwners := make(map[string]struct{}, len(nextRR)+8)
	for owner := range nextRR {
		activeOwners[owner] = struct{}{}
	}
	// Structural Empty Non-Terminals: id.<zone>., app.<zone>., and active <id-tag>.id.<zone>.
	activeOwners["id."+s.zoneFQDN] = struct{}{}
	activeOwners["app."+s.zoneFQDN] = struct{}{}
	for fqdn := range s.leaves {
		if parsed, err := pgns.ParseScopedFQDN(fqdn, s.zone); err == nil && parsed.Class == pgns.ClassSelfCertifying {
			activeOwners[parsed.IDTag+".id."+s.zoneFQDN] = struct{}{}
		}
	}

	nextNSEC3, sortedHashes, err := s.rebuildNSEC3RingLocked(activeOwners, nextRR, epoch, te)
	if err != nil {
		return err
	}

	soaSet := nextRR[s.zoneFQDN][dns.TypeSOA]
	s.rrCache = nextRR
	s.nsec3Map = nextNSEC3
	s.snapshot.Store(&zoneSnapshot{
		zoneFQDN:     s.zoneFQDN,
		rrsets:       nextRR,
		activeOwners: activeOwners,
		nsec3ByHash:  nextNSEC3,
		sortedHashes: sortedHashes,
		soaSet:       soaSet,
	})
	return nil
}

func (s *Server) synthesizeLeafOwner(dst map[string]map[uint16]signedRRSet, leaf pgns.PortalLeafRecord, te uint64) error {
	owner := dns.Fqdn(leaf.FQDN)
	ttl30 := clampTTL(BaseRecordTTL, leaf.ExpiresAt, te)
	ttl60 := clampTTL(BaseAuthRecordTTL, leaf.ExpiresAt, te)
	leafExp := min(te+DefaultRRSIGLifetime, leaf.ExpiresAt+LeafExpiryGrace)
	inception := uint32(te - min(te, RRSIGInceptionSkew))

	sets := make(map[uint16]signedRRSet, 4)
	primary := leaf.Endpoints[0]
	if primary.IPv4 != ([4]byte{}) {
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl30},
			A:   net.IP(append([]byte(nil), primary.IPv4[:]...)),
		}
		signed, err := s.signRRSet([]dns.RR{rr}, inception, uint32(leafExp), leaf.ExpiresAt)
		if err != nil {
			return err
		}
		sets[dns.TypeA] = signed
	}
	if primary.IPv6 != ([16]byte{}) {
		rr := &dns.AAAA{
			Hdr:  dns.RR_Header{Name: owner, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl30},
			AAAA: net.IP(append([]byte(nil), primary.IPv6[:]...)),
		}
		signed, err := s.signRRSet([]dns.RR{rr}, inception, uint32(leafExp), leaf.ExpiresAt)
		if err != nil {
			return err
		}
		sets[dns.TypeAAAA] = signed
	}

	alpn := []string{"http/1.1"}
	if leaf.Flags&pgns.FlagHTTP2 != 0 {
		alpn = []string{"h2", "http/1.1"}
	}
	httpsRR := &dns.HTTPS{
		SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: owner, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: ttl30},
			Priority: 1,
			Target:   ".",
			Value:    []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: alpn}},
		},
	}
	signedHTTPS, err := s.signRRSet([]dns.RR{httpsRR}, inception, uint32(leafExp), leaf.ExpiresAt)
	if err != nil {
		return err
	}
	sets[dns.TypeHTTPS] = signedHTTPS

	// RFC 8659 §3/§5.3: ALWAYS publish both issuewild ";" AND issue at active leaves.
	issueVal := ";"
	if leaf.ACMECAIssuer != "" {
		issueVal = fmt.Sprintf("%s; validationmethods=dns-01; accounturi=%s", leaf.ACMECAIssuer, leaf.ACMEAccountURI)
	}
	caaRRs := []dns.RR{
		&dns.CAA{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: ttl60}, Flag: 0, Tag: "issuewild", Value: ";"},
		&dns.CAA{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: ttl60}, Flag: 0, Tag: "issue", Value: issueVal},
	}
	signedCAA, err := s.signRRSet(caaRRs, inception, uint32(leafExp), leaf.ExpiresAt)
	if err != nil {
		return err
	}
	sets[dns.TypeCAA] = signedCAA
	dst[owner] = sets

	if leaf.ACMEDNS01Digest != ([32]byte{}) {
		txtOwner := "_acme-challenge." + owner
		txtExp := min(te+ACMEChallengeLifetime, leaf.ExpiresAt+LeafExpiryGrace)
		txtRR := &dns.TXT{
			Hdr: dns.RR_Header{Name: txtOwner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl60},
			Txt: []string{base64.RawURLEncoding.EncodeToString(leaf.ACMEDNS01Digest[:])},
		}
		signed, err := s.signRRSet([]dns.RR{txtRR}, inception, uint32(txtExp), leaf.ExpiresAt)
		if err != nil {
			return err
		}
		dst[txtOwner] = map[uint16]signedRRSet{dns.TypeTXT: signed}
	}

	if leaf.Flags&pgns.FlagPersist01Enabled != 0 {
		pOwner := "_validation-persist." + owner
		txtVal := fmt.Sprintf("%s; accounturi=%s; persistUntil=%d", leaf.ACMECAIssuer, leaf.ACMEAccountURI, leaf.ExpiresAt)
		pRR := &dns.TXT{
			Hdr: dns.RR_Header{Name: pOwner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl60},
			Txt: []string{txtVal},
		}
		signed, err := s.signRRSet([]dns.RR{pRR}, inception, uint32(leafExp), leaf.ExpiresAt)
		if err != nil {
			return err
		}
		dst[pOwner] = map[uint16]signedRRSet{dns.TypeTXT: signed}
	}
	return nil
}

func (s *Server) synthesizeApexAndGlue(dst map[string]map[uint16]signedRRSet, epoch, te uint64) error {
	inception := uint32(te - min(te, RRSIGInceptionSkew))
	exp := uint32(te + DefaultRRSIGLifetime)

	apex := make(map[uint16]signedRRSet, 6)
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: s.zoneFQDN, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ApexRecordTTL},
		Ns:      dns.Fqdn(s.nameservers[0].Host),
		Mbox:    "hostmaster." + s.zoneFQDN,
		Serial:  uint32(epoch + 1),
		Refresh: 300,
		Retry:   60,
		Expire:  86400,
		Minttl:  BaseRecordTTL,
	}
	var err error
	if apex[dns.TypeSOA], err = s.signRRSet([]dns.RR{soa}, inception, exp, 0); err != nil {
		return err
	}

	nsRRs := make([]dns.RR, 0, len(s.nameservers))
	for _, ns := range s.nameservers {
		nsName := dns.Fqdn(ns.Host)
		nsRRs = append(nsRRs, &dns.NS{
			Hdr: dns.RR_Header{Name: s.zoneFQDN, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ApexRecordTTL},
			Ns:  nsName,
		})
		if dns.IsSubDomain(s.zoneFQDN, nsName) {
			glue := dst[nsName]
			if glue == nil {
				glue = make(map[uint16]signedRRSet, 2)
			}
			if ip4 := ns.IPv4.To4(); ip4 != nil {
				aRR := &dns.A{Hdr: dns.RR_Header{Name: nsName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ApexRecordTTL}, A: append(net.IP(nil), ip4...)}
				if glue[dns.TypeA], err = s.signRRSet([]dns.RR{aRR}, inception, exp, 0); err != nil {
					return err
				}
			}
			if ns.IPv6 != nil && ns.IPv6.To4() == nil {
				aaaaRR := &dns.AAAA{Hdr: dns.RR_Header{Name: nsName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ApexRecordTTL}, AAAA: append(net.IP(nil), ns.IPv6...)}
				if glue[dns.TypeAAAA], err = s.signRRSet([]dns.RR{aaaaRR}, inception, exp, 0); err != nil {
					return err
				}
			}
			dst[nsName] = glue
		}
	}
	if apex[dns.TypeNS], err = s.signRRSet(nsRRs, inception, exp, 0); err != nil {
		return err
	}
	apex[dns.TypeDNSKEY] = signedRRSet{
		records: []dns.RR{dns.Copy(s.keys.KSK), dns.Copy(s.keys.ZSK)},
		rrsig:   dns.Copy(s.keys.DNSKEYRRSIG).(*dns.RRSIG),
	}
	param := &dns.NSEC3PARAM{
		Hdr:        dns.RR_Header{Name: s.zoneFQDN, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: ApexRecordTTL},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 0,
		SaltLength: 0,
		Salt:       "",
	}
	if apex[dns.TypeNSEC3PARAM], err = s.signRRSet([]dns.RR{param}, inception, exp, 0); err != nil {
		return err
	}
	apexCAA := []dns.RR{
		&dns.CAA{Hdr: dns.RR_Header{Name: s.zoneFQDN, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: ApexRecordTTL}, Flag: 0, Tag: "issue", Value: ";"},
		&dns.CAA{Hdr: dns.RR_Header{Name: s.zoneFQDN, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: ApexRecordTTL}, Flag: 0, Tag: "issuewild", Value: ";"},
	}
	if apex[dns.TypeCAA], err = s.signRRSet(apexCAA, inception, exp, 0); err != nil {
		return err
	}
	dst[s.zoneFQDN] = apex
	return nil
}

func (s *Server) rebuildNSEC3RingLocked(activeOwners map[string]struct{}, rrsets map[string]map[uint16]signedRRSet, epoch, te uint64) (map[string]nsec3Entry, []string, error) {
	type hashedOwner struct {
		hashUpper string
		owner     string
	}
	byHash := make(map[string]hashedOwner, len(activeOwners))
	hashes := make([]string, 0, len(activeOwners))
	for owner := range activeOwners {
		h := strings.ToUpper(dns.HashName(owner, dns.SHA1, 0, ""))
		byHash[h] = hashedOwner{hashUpper: h, owner: owner}
		hashes = append(hashes, h)
	}
	slices.Sort(hashes)

	out := make(map[string]nsec3Entry, len(hashes))
	inception := uint32(te - min(te, RRSIGInceptionSkew))
	exp := uint32(te + DefaultRRSIGLifetime)

	for i, h := range hashes {
		nextH := hashes[(i+1)%len(hashes)]
		owner := byHash[h].owner
		typeBitmap := ownerTypeBitMap(rrsets[owner])
		nsec3Owner := strings.ToLower(h) + "." + s.zoneFQDN
		rr := &dns.NSEC3{
			Hdr:        dns.RR_Header{Name: nsec3Owner, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: BaseRecordTTL},
			Hash:       dns.SHA1,
			Flags:      0,
			Iterations: 0,
			SaltLength: 0,
			Salt:       "",
			HashLength: 20,
			NextDomain: nextH,
			TypeBitMap: typeBitmap,
		}
		if cached, ok := s.nsec3Map[h]; ok && cached.rrsig != nil && uint64(cached.rrsig.Expiration) > te+RRSIGRefreshThreshold &&
			cached.rr.NextDomain == nextH && slices.Equal(cached.rr.TypeBitMap, typeBitmap) &&
			(binary.BigEndian.Uint64([]byte(h[:8]))%s.refreshBuckets != epoch%s.refreshBuckets) {
			out[h] = cached
			continue
		}
		sig := &dns.RRSIG{
			Hdr:        dns.RR_Header{Name: nsec3Owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: BaseRecordTTL},
			KeyTag:     s.keys.ZSK.KeyTag(),
			SignerName: s.zoneFQDN,
			Algorithm:  s.keys.ZSK.Algorithm,
			Inception:  inception,
			Expiration: exp,
		}
		if err := sig.Sign(s.keys.ZSKSigner, []dns.RR{rr}); err != nil {
			return nil, nil, fmt.Errorf("sign NSEC3 %s: %w", owner, err)
		}
		out[h] = nsec3Entry{hashUpper: h, rr: rr, rrsig: sig}
	}
	return out, hashes, nil
}

func ownerTypeBitMap(sets map[uint16]signedRRSet) []uint16 {
	if len(sets) == 0 {
		// ENT NSEC3 carries an empty TypeBitMap per RFC 5155 / RFC 9156.
		return nil
	}
	types := make([]uint16, 0, len(sets)+1)
	for typ := range sets {
		if typ == dns.TypeNSEC3 {
			continue // RFC 5155 §3.2.1 omits NSEC3 bit from TypeBitMap.
		}
		types = append(types, typ)
	}
	types = append(types, dns.TypeRRSIG)
	slices.Sort(types)
	return types
}

func (s *Server) signRRSet(records []dns.RR, inception, expiration uint32, leafExpiresAt uint64) (signedRRSet, error) {
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: records[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: records[0].Header().Ttl},
		KeyTag:     s.keys.ZSK.KeyTag(),
		SignerName: s.zoneFQDN,
		Algorithm:  s.keys.ZSK.Algorithm,
		Inception:  inception,
		Expiration: expiration,
	}
	if err := sig.Sign(s.keys.ZSKSigner, records); err != nil {
		return signedRRSet{}, err
	}
	return signedRRSet{records: records, rrsig: sig, expiresAt: leafExpiresAt}, nil
}

// ServeDNS implements miekg/dns.Handler purely from the pre-signed memory snapshot.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true

	if len(r.Question) == 0 {
		resp.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(resp)
		return
	}
	snap := s.snapshot.Load()
	q := r.Question[0]
	qname := dns.CanonicalName(q.Name)
	if snap == nil || q.Qclass != dns.ClassINET || !dns.IsSubDomain(snap.zoneFQDN, qname) {
		resp.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(resp)
		return
	}
	do := hasDNSSECOK(r)

	if sets, exists := snap.rrsets[qname]; exists {
		if set, hasType := sets[q.Qtype]; hasType {
			appendRRSetTo(&resp.Answer, set, do)
			_ = w.WriteMsg(resp)
			return
		}
		// NODATA on existing owner name.
		appendRRSetTo(&resp.Ns, snap.soaSet, do)
		if entry, ok := snap.matchNSEC3(qname); ok {
			appendNSEC3Entry(&resp.Ns, entry, do)
		}
		_ = w.WriteMsg(resp)
		return
	}

	// Check Empty Non-Terminal (ENT): exists in activeOwners with zero RRsets -> NOERROR NODATA.
	if _, isENT := snap.activeOwners[qname]; isENT {
		appendRRSetTo(&resp.Ns, snap.soaSet, do)
		if entry, ok := snap.matchNSEC3(qname); ok {
			appendNSEC3Entry(&resp.Ns, entry, do)
		}
		_ = w.WriteMsg(resp)
		return
	}

	// NXDOMAIN: RFC 5155 §7.2.2 closest encloser + next closer + wildcard proofs.
	resp.Rcode = dns.RcodeNameError
	appendRRSetTo(&resp.Ns, snap.soaSet, do)
	if do {
		for _, entry := range snap.nxdomainProof(qname) {
			appendNSEC3Entry(&resp.Ns, entry, true)
		}
	}
	_ = w.WriteMsg(resp)
}

func (snap *zoneSnapshot) matchNSEC3(owner string) (nsec3Entry, bool) {
	h := strings.ToUpper(dns.HashName(owner, dns.SHA1, 0, ""))
	entry, ok := snap.nsec3ByHash[h]
	return entry, ok
}

func (snap *zoneSnapshot) coverNSEC3(name string) (nsec3Entry, bool) {
	if len(snap.sortedHashes) == 0 {
		return nsec3Entry{}, false
	}
	h := strings.ToUpper(dns.HashName(name, dns.SHA1, 0, ""))
	idx, found := slices.BinarySearch(snap.sortedHashes, h)
	if found {
		return snap.nsec3ByHash[snap.sortedHashes[idx]], true
	}
	prevIdx := (idx + len(snap.sortedHashes) - 1) % len(snap.sortedHashes)
	return snap.nsec3ByHash[snap.sortedHashes[prevIdx]], true
}

func (snap *zoneSnapshot) nxdomainProof(qname string) []nsec3Entry {
	ce := closestEncloser(qname, snap.zoneFQDN, snap.activeOwners)
	nc := nextCloserChild(qname, ce)
	seen := make(map[string]struct{}, 3)
	var proof []nsec3Entry
	for _, lookup := range []struct {
		name  string
		exact bool
	}{
		{ce, true},
		{nc, false},
		{"*." + ce, false},
	} {
		var entry nsec3Entry
		var ok bool
		if lookup.exact {
			entry, ok = snap.matchNSEC3(lookup.name)
		} else {
			entry, ok = snap.coverNSEC3(lookup.name)
		}
		if !ok {
			continue
		}
		if _, dup := seen[entry.hashUpper]; dup {
			continue
		}
		seen[entry.hashUpper] = struct{}{}
		proof = append(proof, entry)
	}
	return proof
}

func closestEncloser(qname, zoneFQDN string, owners map[string]struct{}) string {
	cur := qname
	for cur != zoneFQDN {
		offset, end := dns.NextLabel(cur, 0)
		if end || offset >= len(cur) {
			break
		}
		cur = cur[offset:]
		if _, ok := owners[cur]; ok {
			return cur
		}
	}
	return zoneFQDN
}

func nextCloserChild(qname, ce string) string {
	cur := qname
	for {
		offset, end := dns.NextLabel(cur, 0)
		if end || offset >= len(cur) {
			return qname
		}
		parent := cur[offset:]
		if parent == ce {
			return cur
		}
		cur = parent
	}
}

func clampTTL(baseTTL uint32, expiresAt, te uint64) uint32 {
	if expiresAt <= te {
		return 1
	}
	rem := expiresAt - te
	if rem < uint64(baseTTL) {
		return uint32(max(1, rem))
	}
	return baseTTL
}

func cloneTypeMap(src map[uint16]signedRRSet) map[uint16]signedRRSet {
	out := make(map[uint16]signedRRSet, len(src))
	maps.Copy(out, src)
	return out
}

func appendRRSetTo(dst *[]dns.RR, set signedRRSet, do bool) {
	for _, rr := range set.records {
		*dst = append(*dst, dns.Copy(rr))
	}
	if do && set.rrsig != nil {
		*dst = append(*dst, dns.Copy(set.rrsig))
	}
}

func appendNSEC3Entry(dst *[]dns.RR, entry nsec3Entry, do bool) {
	*dst = append(*dst, dns.Copy(entry.rr))
	if do && entry.rrsig != nil {
		*dst = append(*dst, dns.Copy(entry.rrsig))
	}
}

func hasDNSSECOK(r *dns.Msg) bool {
	opt := r.IsEdns0()
	return opt != nil && opt.Do()
}
