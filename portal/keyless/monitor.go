package keyless

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/idna"
)

const (
	certificateMonitorSource = "https://api.certspotter.com/v1/issuances"
	certificateMonitorPages  = 8
	certificateMonitorBytes  = 2 << 20
)

var (
	errMonitorStateDirectoryRequired = errors.New("certificate monitoring requires a state directory")
	errMonitorResolverInvalid        = errors.New("certificate monitor DNS resolver must be an IP:port")
	errMonitorHostnameInvalid        = errors.New("certificate monitor requires a DNS hostname")
	errMonitorLocalHistoryLimit      = errors.New("local public certificate history exceeds observation limit")
	errMonitorBaselineUnconfigured   = errors.New("CAA baseline is unconfigured; explicitly review and configure a baseline file")
	errMonitorBaselineRead           = errors.New("cannot read bounded certificate monitor baseline")
	errMonitorBaselineInvalid        = errors.New("baseline must name the canonical hostname and explicitly specify caa, including [] for no policy")
	errMonitorBaselineSPKIInvalid    = errors.New("baseline SPKI hashes must be lowercase SHA256 hex")
	errMonitorCAAValueInvalid        = errors.New("CAA value is not valid UTF-8; policy observation unavailable")
	errMonitorCAATagInvalid          = errors.New("invalid CAA property tag")
	errMonitorCAAAliasLoop           = errors.New("CAA alias loop")
	errMonitorCAAResponseInvalid     = errors.New("CAA response is not a recursive or authoritative answer to the question")
	errMonitorCAAConflictingAliases  = errors.New("CAA response contains conflicting aliases")
	errMonitorCAARecordsAndAlias     = errors.New("CAA response contains both alias and CAA records")
	errMonitorCAANegativeWithRecords = errors.New("CAA negative answer contains CAA records")
	errMonitorCAAAliasInvalid        = errors.New("invalid CAA alias target")
	errMonitorCAAAliasLimit          = errors.New("CAA alias chain exceeds observation limit")
	errMonitorEvidenceReadLimit      = errors.New("monitor evidence exceeds read limit; archive and review public state")
	errMonitorEvidenceInvalid        = errors.New("invalid monitor evidence; preserve and repair the public state file")
	errMonitorEvidenceCountLimit     = errors.New("monitor evidence exceeds observation limit")
	errMonitorEvidenceWriteLimit     = errors.New("monitor evidence limit reached; archive and review public state")
	errMonitorLocalHistorySize       = errors.New("invalid local public certificate history size")
	errMonitorLocalHistoryInvalid    = errors.New("invalid local public certificate history")
	errMonitorCTResponseLimit        = errors.New("CT response exceeds observation limit")
	errMonitorCTPageInvalid          = errors.New("invalid CT issuance page")
	errMonitorCTIdentityInvalid      = errors.New("invalid CT issuance identity")
	errMonitorCTCursorStalled        = errors.New("CT pagination did not advance")
	errMonitorCTPageLimit            = errors.New("CT page budget reached; continuing from durable cursor next poll")
)

// MonitorConfig opts into warning-only observations of the primary tenant
// hostname. Observations never change certificates, DNS, or signing mode.
// StateDir contains public evidence, not private certificate bundles.
// BaselineFile is an operator-maintained JSON policy, reread each hour. An empty
// path leaves CAA unconfigured; observed policies are never accepted implicitly.
// DNSResolver is an IP:port, defaulting to Cloudflare's 1.1.1.1:53. Certificate
// observations use Cert Spotter over ordinary system-trusted HTTPS without
// relay credentials. Neither source provides a guarantee of completeness.
type MonitorConfig struct {
	StateDir     string
	BaselineFile string
	DNSResolver  string
}

// Validate checks configuration without filesystem or network operations.
func (config MonitorConfig) Validate() error {
	if strings.TrimSpace(config.StateDir) == "" {
		return errMonitorStateDirectoryRequired
	}
	if config.DNSResolver != "" {
		addr, err := netip.ParseAddrPort(config.DNSResolver)
		if err != nil || addr.Port() == 0 {
			return errMonitorResolverInvalid
		}
	}
	return nil
}

type caaRecord struct {
	Flags uint8  `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

type monitorBaseline struct {
	Hostname           string      `json:"hostname"`
	CAA                []caaRecord `json:"caa"`
	ApprovedSPKISHA256 []string    `json:"approved_spki_sha256,omitempty"`
}

type caaObservation struct {
	ObservedAt time.Time   `json:"observed_at"`
	Resolver   string      `json:"resolver"`
	Owner      string      `json:"owner,omitempty"`
	Records    []caaRecord `json:"records"`
	Error      string      `json:"error,omitempty"`
}

// DER, not API names or issuer descriptions, supplies identity and key evidence.
// SourceID/TBS identify the API's issuance grouping, not a verified CT proof.
type ctObservation struct {
	SourceID       string    `json:"source_id"`
	TBSSHA256      string    `json:"tbs_sha256"`
	Certificate    []byte    `json:"certificate_der"`
	SHA256         string    `json:"certificate_sha256"`
	SPKISHA256     string    `json:"spki_sha256"`
	DNSNames       []string  `json:"dns_names"`
	CoversHostname bool      `json:"covers_hostname"`
	Precertificate bool      `json:"precertificate"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
}

type monitorEvidence struct {
	Hostname       string                   `json:"hostname"`
	Source         string                   `json:"ct_source"`
	Cursor         string                   `json:"ct_cursor,omitempty"`
	CTChecked      time.Time                `json:"ct_checked_at,omitempty"`
	CTError        string                   `json:"ct_error,omitempty"`
	CTNextCheck    time.Time                `json:"ct_next_check,omitempty"`
	CTLastComplete time.Time                `json:"ct_last_complete_at,omitempty"`
	CAA            []caaObservation         `json:"caa_observations"`
	Certificates   map[string]ctObservation `json:"certificates"`
}

type certificateMonitor struct {
	hostname string
	dir      string
	config   MonitorConfig
	http     *http.Client
	events   chan []byte
}

func newCertificateMonitor(hostname string, config MonitorConfig) (*certificateMonitor, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	hostname, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(hostname), "."))
	if err != nil || hostname == "" || strings.Contains(hostname, "*") || net.ParseIP(hostname) != nil {
		return nil, errMonitorHostnameInvalid
	}
	if _, ok := dns.IsDomainName(hostname); !ok {
		return nil, errMonitorHostnameInvalid
	}
	if config.DNSResolver == "" {
		config.DNSResolver = "1.1.1.1:53"
	}
	return &certificateMonitor{
		hostname: hostname,
		dir:      filepath.Join(config.StateDir, publicSHA256([]byte(hostname))),
		config:   config,
		events:   make(chan []byte, 16),
		http: &http.Client{
			Timeout:       15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func publicSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// CertificateObserver owns optional public observations independently of TLS.
// Event delivery is bounded and best-effort; a lost installation event can only
// cause a conservative unrecognized-key warning, never approve an unknown key.
type CertificateObserver struct {
	events chan []byte
	cancel context.CancelFunc
	done   chan struct{}
}

// StartCertificateObserver starts a lease-scoped, warning-only observer.
func StartCertificateObserver(hostname string, config MonitorConfig) (*CertificateObserver, error) {
	monitor, err := newCertificateMonitor(hostname, config)
	if err != nil {
		return nil, err
	}
	return monitor.start(), nil
}

func (m *certificateMonitor) start() *CertificateObserver {
	ctx, cancel := context.WithCancel(context.Background())
	observer := &CertificateObserver{events: m.events, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(observer.done)
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		m.poll(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case der := <-m.events:
				m.rememberEvent(der)
			case <-ticker.C:
				m.poll(ctx)
			}
		}
	}()
	return observer
}

// Events returns the observer's input. Send nonblocking copied local leaf DER;
// callers must not close the channel, including after Close.
func (o *CertificateObserver) Events() chan<- []byte {
	if o == nil {
		return nil
	}
	return o.events
}

// Close cancels observations and waits for their worker. It does not touch TLS.
func (o *CertificateObserver) Close() {
	if o == nil {
		return
	}
	o.cancel()
	<-o.done
}

func (m *certificateMonitor) rememberEvent(der []byte) {
	if len(der) > 256<<10 {
		m.warn("local public certificate exceeds history size limit", nil)
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		m.warn("invalid installed public certificate", err)
		return
	}
	if err := cert.VerifyHostname(m.hostname); err != nil {
		m.warn("installed public certificate does not cover hostname", err)
		return
	}
	m.rememberLocalCertificate(cert)
}

// Drain only the bounded queue snapshot so a producer cannot delay polls.
func (m *certificateMonitor) rememberEvents() {
	for range len(m.events) {
		m.rememberEvent(<-m.events)
	}
}

// Only the observation worker writes public history. No monitor disk or network
// operation runs on the TLS/issuance path. A crash before the next poll may cause
// a conservative historical-key warning; it cannot silently approve a key.
func (m *certificateMonitor) rememberLocalCertificate(cert *x509.Certificate) {
	if len(cert.Raw) > 256<<10 {
		m.warn("local public certificate exceeds history size limit", nil)
		return
	}
	dir := filepath.Join(m.dir, "local")
	path := filepath.Join(dir, publicSHA256(cert.Raw)+".der")
	if _, err := os.Stat(path); err == nil {
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		m.warn("cannot retain local public certificate history", err)
		return
	}
	// Installation events and polls share one worker, but multiple SDK leases
	// or processes may use the same hostname's public history.
	lock, err := lockCertificate(filepath.Join(m.dir, "local.lock"))
	if err != nil {
		m.warn("cannot lock local public certificate history", err)
		return
	}
	defer lock.Close()
	files, err := m.localHistoryFiles()
	if err != nil || len(files) >= 4096 {
		m.warn("local public certificate history limit reached; archive and review public state", err)
		return
	}
	if err := writeMonitorFile(path, cert.Raw); err != nil {
		m.warn("cannot retain local public certificate history", err)
	}
}

func (m *certificateMonitor) localHistoryFiles() ([]os.DirEntry, error) {
	dir, err := os.Open(filepath.Join(m.dir, "local"))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	files, err := dir.ReadDir(4097)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(files) > 4096 {
		return nil, errMonitorLocalHistoryLimit
	}
	return files, nil
}

func (m *certificateMonitor) warn(message string, err error) {
	log.Warn().Str("hostname", m.hostname).Err(err).Msg("certificate monitor: " + message)
}

func (m *certificateMonitor) readBaseline() (*monitorBaseline, error) {
	if m.config.BaselineFile == "" {
		return nil, errMonitorBaselineUnconfigured
	}
	f, err := os.Open(m.config.BaselineFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return nil, errMonitorBaselineRead
	}
	var baseline monitorBaseline
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baseline); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF || baseline.Hostname != m.hostname || baseline.CAA == nil {
		return nil, errMonitorBaselineInvalid
	}
	baseline.CAA, err = canonicalCAA(baseline.CAA)
	if err != nil {
		return nil, err
	}
	for _, key := range baseline.ApprovedSPKISHA256 {
		if !validSHA256(key) {
			return nil, errMonitorBaselineSPKIInvalid
		}
	}
	return &baseline, nil
}

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

func (m *certificateMonitor) loadEvidence() (monitorEvidence, error) {
	evidence := monitorEvidence{Hostname: m.hostname, Source: certificateMonitorSource, Certificates: map[string]ctObservation{}}
	f, err := os.Open(filepath.Join(m.dir, "evidence.json"))
	if errors.Is(err, os.ErrNotExist) {
		return evidence, nil
	}
	if err != nil {
		return evidence, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	if err != nil || len(data) > 64<<20 {
		return evidence, errMonitorEvidenceReadLimit
	}
	if err := json.Unmarshal(data, &evidence); err != nil {
		return evidence, err
	}
	if evidence.Hostname != m.hostname || evidence.Source != certificateMonitorSource || evidence.Certificates == nil {
		return evidence, errMonitorEvidenceInvalid
	}
	if len(evidence.Cursor) > 256 || len(evidence.Certificates) > 10000 {
		return evidence, errMonitorEvidenceCountLimit
	}
	return evidence, nil
}

func (m *certificateMonitor) saveEvidence(evidence monitorEvidence) error {
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > 64<<20 || len(evidence.Certificates) > 10000 {
		return errMonitorEvidenceWriteLimit
	}
	return writeMonitorFile(filepath.Join(m.dir, "evidence.json"), data)
}

// Unlike ordinary configuration writes, an evidence checkpoint flushes bytes
// before rename so its cursor and the evidence it acknowledges move together.
func writeMonitorFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".monitor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (m *certificateMonitor) knownKeys(baseline *monitorBaseline) (map[string]bool, error) {
	keys := map[string]bool{}
	if baseline != nil {
		for _, key := range baseline.ApprovedSPKISHA256 {
			keys[key] = true
		}
	}
	files, err := m.localHistoryFiles()
	if errors.Is(err, os.ErrNotExist) {
		return keys, nil
	}
	if err != nil {
		return keys, err
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".der") || file.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(m.dir, "local", file.Name()))
		if err != nil {
			return keys, err
		}
		data, err := io.ReadAll(io.LimitReader(f, (256<<10)+1))
		_ = f.Close()
		if err != nil || len(data) > 256<<10 {
			return keys, errMonitorLocalHistorySize
		}
		cert, err := x509.ParseCertificate(data)
		if err != nil || cert.VerifyHostname(m.hostname) != nil || publicSHA256(data)+".der" != file.Name() {
			return keys, errMonitorLocalHistoryInvalid
		}
		keys[publicSHA256(cert.RawSubjectPublicKeyInfo)] = true
	}
	return keys, nil
}

func (m *certificateMonitor) poll(parent context.Context) {
	if parent.Err() != nil {
		return
	}
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		m.warn("cannot open evidence storage", err)
		return
	}
	// Reuse the existing cross-process lock, without coupling to issuance locks.
	lock, err := lockCertificate(filepath.Join(m.dir, "evidence.json.lock"))
	if err != nil {
		m.warn("cannot lock evidence storage", err)
		return
	}
	defer lock.Close()
	m.rememberEvents()
	evidence, err := m.loadEvidence()
	if err != nil {
		m.warn("cannot load evidence storage", err)
		return
	}
	baseline, err := m.readBaseline()
	if err != nil {
		m.warn("CAA baseline unavailable or unconfigured", err)
	}
	// Each independent source gets its own bounded budget; a DNS outage must
	// not suppress CT observations and neither can stall issuance or handshakes.
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	observation := m.observeCAA(ctx)
	cancel()
	evidence.CAA = append(evidence.CAA, observation)
	// Keep recent observations (including failures), not an unbounded DNS log.
	if len(evidence.CAA) > 168 {
		evidence.CAA = evidence.CAA[len(evidence.CAA)-168:]
	}
	if observation.Error != "" {
		m.warn("CAA observation unavailable; policy state is unknown", errors.New(observation.Error))
	} else if baseline != nil && !slices.Equal(observation.Records, baseline.CAA) {
		m.warn("CAA policy differs from the explicitly accepted baseline", nil)
	}
	if err := m.saveEvidence(evidence); err != nil {
		m.warn("cannot save CAA evidence", err)
		return
	}
	ctx, cancel = context.WithTimeout(parent, 30*time.Second)
	err = m.pollCT(ctx, &evidence)
	cancel()
	if err != nil {
		m.warn("CT observation unavailable or incomplete; issuance coverage is unknown", err)
	}
	// Include installation events arriving during network observations.
	m.rememberEvents()
	keys, err := m.knownKeys(baseline)
	if err != nil {
		m.warn("local public key history unavailable", err)
	}
	warned := map[string]bool{}
	for _, certificate := range evidence.Certificates {
		warningID := certificate.TBSSHA256 + ":" + certificate.SPKISHA256
		if certificate.CoversHostname && time.Now().Before(certificate.NotAfter) && !keys[certificate.SPKISHA256] && !warned[warningID] {
			warned[warningID] = true
			log.Warn().Str("hostname", m.hostname).Str("source", certificateMonitorSource).
				Str("spki_sha256", certificate.SPKISHA256).Str("certificate_sha256", certificate.SHA256).
				Bool("precertificate", certificate.Precertificate).
				Msg("certificate monitor: unrecognized public key observed; review evidence, not proof of unauthorized issuance or CT inclusion")
		}
	}
}

type ctIssuance struct {
	ID        string `json:"id"`
	TBSSHA256 string `json:"tbs_sha256"`
	CertDER   []byte `json:"cert_der"`
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func (m *certificateMonitor) fetchCT(ctx context.Context, cursor string) ([]ctIssuance, time.Time, error) {
	query := url.Values{"domain": {m.hostname}, "match_wildcards": {"true"}, "expand": {"cert_der"}}
	if cursor != "" {
		query.Set("after", cursor)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certificateMonitorSource+"?"+query.Encode(), nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	var retryAfter time.Time
	if seconds, err := strconv.ParseUint(resp.Header.Get("Retry-After"), 10, 32); err == nil {
		retryAfter = time.Now().Add(time.Duration(seconds) * time.Second).UTC()
	} else if when, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil {
		retryAfter = when.UTC()
	}
	if resp.StatusCode != http.StatusOK {
		return nil, retryAfter, fmt.Errorf("cert spotter returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, certificateMonitorBytes+1))
	if err != nil {
		return nil, retryAfter, err
	}
	if len(data) > certificateMonitorBytes {
		return nil, retryAfter, errMonitorCTResponseLimit
	}
	var issuances []ctIssuance
	if err := json.Unmarshal(data, &issuances); err != nil {
		return nil, retryAfter, err
	}
	if issuances == nil || len(issuances) > 1000 {
		return nil, retryAfter, errMonitorCTPageInvalid
	}
	return issuances, retryAfter, nil
}

func (m *certificateMonitor) decodeCT(issuance ctIssuance, now time.Time) (ctObservation, error) {
	if issuance.ID == "" || len(issuance.ID) > 256 || !validSHA256(issuance.TBSSHA256) {
		return ctObservation{}, errMonitorCTIdentityInvalid
	}
	certificate, err := x509.ParseCertificate(issuance.CertDER)
	if err != nil {
		return ctObservation{}, err
	}
	// The API can match legacy Common Names as well as SANs. Valid DER with
	// no modern SAN coverage is retained but must not wedge the pagination
	// cursor or be mistaken for a certificate usable for this hostname.
	coversHostname := certificate.VerifyHostname(m.hostname) == nil
	precertificate := false
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}) {
			precertificate = true
		}
	}
	return ctObservation{
		SourceID: issuance.ID, TBSSHA256: issuance.TBSSHA256, Certificate: issuance.CertDER,
		SHA256: publicSHA256(certificate.Raw), SPKISHA256: publicSHA256(certificate.RawSubjectPublicKeyInfo),
		DNSNames: certificate.DNSNames, CoversHostname: coversHostname, Precertificate: precertificate,
		NotBefore: certificate.NotBefore, NotAfter: certificate.NotAfter, FirstSeen: now, LastSeen: now,
	}, nil
}

func (m *certificateMonitor) pollCT(ctx context.Context, evidence *monitorEvidence) (result error) {
	if time.Now().Before(evidence.CTNextCheck) {
		return nil
	}
	defer func() {
		if result != nil {
			evidence.CTChecked, evidence.CTError = time.Now().UTC(), result.Error()
			result = errors.Join(result, m.saveEvidence(*evidence))
		}
	}()
	seenCursors := map[string]bool{}
	observedNoncovering := false
	defer func() {
		if observedNoncovering {
			m.warn("CT source returned certificates without DNS SAN coverage; retained as non-covering public evidence", nil)
		}
	}()
	for range certificateMonitorPages {
		seenCursors[evidence.Cursor] = true
		page, retryAfter, err := m.fetchCT(ctx, evidence.Cursor)
		if err != nil {
			evidence.CTNextCheck = retryAfter
			return err
		}
		now := time.Now().UTC()
		next := *evidence
		next.CTNextCheck = retryAfter
		next.Certificates = make(map[string]ctObservation, len(evidence.Certificates)+len(page))
		for hash, old := range evidence.Certificates {
			next.Certificates[hash] = old
		}
		seenIDs := map[string]bool{}
		for _, issuance := range page {
			if seenCursors[issuance.ID] || seenIDs[issuance.ID] {
				return errMonitorCTCursorStalled
			}
			seenIDs[issuance.ID] = true
			observation, err := m.decodeCT(issuance, now)
			if err != nil {
				return err // No cursor or partial page is committed.
			}
			observedNoncovering = observedNoncovering || !observation.CoversHostname
			if now.Before(observation.NotAfter) {
				if old, ok := next.Certificates[observation.SHA256]; ok {
					observation.FirstSeen = old.FirstSeen
				}
				next.Certificates[observation.SHA256] = observation
			}
			next.Cursor = issuance.ID
		}
		next.CTChecked, next.CTError = now, ""
		if len(page) == 0 {
			// Restart only after a complete traversal. Later passes can see a
			// final certificate for a previously observed precertificate.
			next.Cursor = ""
			next.CTLastComplete = now
		}
		// Evidence and cursor are one atomic checkpoint: failure cannot skip
		// an issuance on retry/restart. Preserve old, even expired evidence.
		if err := m.saveEvidence(next); err != nil {
			return err
		}
		*evidence = next
		if len(page) == 0 || time.Now().Before(retryAfter) {
			return nil
		}
	}
	return errMonitorCTPageLimit
}
