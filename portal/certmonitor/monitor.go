// Package certmonitor owns warning-only CT and CAA observations independently of TLS.
package certmonitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/idna"

	"github.com/gosuda/portal-tunnel/v2/utils"
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
	lock, err := utils.TryLockFile(filepath.Join(m.dir, "local.lock"))
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
	lock, err := utils.TryLockFile(filepath.Join(m.dir, "evidence.json.lock"))
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
