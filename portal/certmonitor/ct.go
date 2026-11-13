package certmonitor

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

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
