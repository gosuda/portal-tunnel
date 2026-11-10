package route53

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/route53"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
)

type testTXTRecord struct {
	XMLName xml.Name `xml:"ResourceRecordSet"`
	Name    string
	Type    string
	TTL     int64
	Values  []string `xml:"ResourceRecords>ResourceRecord>Value"`
}

func challengeTestConfig(t *testing.T, endpoint string) *route53.Config {
	t.Helper()
	t.Setenv("AWS_ENDPOINT_URL", endpoint)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	cfg := route53.NewDefaultConfig()
	cfg.AccessKeyID, cfg.SecretAccessKey = "test-key", "test-secret"
	cfg.Region, cfg.HostedZoneID = "us-east-1", "pinned-zone"
	cfg.WaitForRecordSetsChanged = false
	cfg.MaxRetries = 1
	return cfg
}

func TestChallengePreservesExistingTXTAndTTL(t *testing.T) {
	var mu sync.Mutex
	record := testTXTRecord{Name: "_acme-challenge.example.test.", Type: "TXT", TTL: 371,
		Values: []string{`"keep"`, `"challenge-prefix"`}}
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.Contains(r.URL.Path, "/hostedzone/pinned-zone/rrset") {
			t.Errorf("unexpected unpinned path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		if r.Method == http.MethodGet {
			fmt.Fprintf(w, `<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>%s</Name><Type>TXT</Type><TTL>%d</TTL><ResourceRecords>`, record.Name, record.TTL)
			for _, value := range record.Values {
				data, _ := xml.Marshal(struct {
					XMLName xml.Name `xml:"ResourceRecord"`
					Value   string
				}{Value: value})
				w.Write(data)
			}
			io.WriteString(w, `</ResourceRecords></ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>`)
			return
		}
		var body struct {
			Changes []struct {
				Action string
				Record testTXTRecord `xml:"ResourceRecordSet"`
			} `xml:"ChangeBatch>Changes>Change"`
		}
		if err := xml.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Changes) != 1 {
			t.Errorf("invalid change: %+v, %v", body, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Changes[0].Action != "UPSERT" {
			t.Errorf("action = %s, want UPSERT preserving other TXT", body.Changes[0].Action)
		}
		record = body.Changes[0].Record
		writes++
		io.WriteString(w, `<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/test</Id><Status>INSYNC</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`)
	}))
	defer server.Close()
	cfg := challengeTestConfig(t, server.URL)
	ctx, cancel := context.WithCancel(t.Context())
	cleanup, err := presentChallenge(ctx, cfg, record.Name, "challenge")
	if err != nil || cleanup == nil {
		t.Fatalf("Present cleanup=%v, err=%v", cleanup != nil, err)
	}
	mu.Lock()
	if record.TTL != 371 || !slices.Equal(record.Values, []string{`"keep"`, `"challenge-prefix"`, `"challenge"`}) {
		t.Errorf("published record = %+v", record)
	}
	// A value added after publication must survive cleanup too.
	record.Values = append(record.Values, `"later"`)
	mu.Unlock()
	cancel()
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup after order cancellation: %v", err)
	}
	if err := cleanup(t.Context()); err != nil {
		t.Fatalf("idempotent cleanup: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if record.TTL != 371 || !slices.Equal(record.Values, []string{`"keep"`, `"challenge-prefix"`, `"later"`}) || writes != 2 {
		t.Errorf("cleaned record = %+v, writes=%d", record, writes)
	}
}

func TestChallengeDoesNotOwnPreexistingValue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("preexisting value was modified by %s", r.Method)
		}
		io.WriteString(w, `<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>_acme-challenge.example.test.</Name><Type>TXT</Type><TTL>400</TTL><ResourceRecords><ResourceRecord><Value>"challenge"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>`)
	}))
	defer server.Close()
	cfg := challengeTestConfig(t, server.URL)
	cleanup, err := presentChallenge(t.Context(), cfg, "_acme-challenge.example.test.", "challenge")
	if err != nil || cleanup != nil {
		t.Fatalf("preexisting value cleanup=%v, err=%v", cleanup != nil, err)
	}
}

func TestChallengeCancellation(t *testing.T) {
	for _, phase := range []string{"lookup", "write", "poll", "credentials", "assume_role", "metadata", "nested_metadata"} {
		t.Run(phase, func(t *testing.T) {
			started, canceled := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				blocked := phase == "credentials" || phase == "assume_role" || phase == "metadata" || phase == "nested_metadata" || phase == "lookup" ||
					phase == "write" && r.Method == http.MethodPost ||
					phase == "poll" && strings.Contains(r.URL.Path, "/change/")
				if blocked {
					io.Copy(io.Discard, r.Body)
					close(started)
					<-r.Context().Done()
					close(canceled)
					return
				}
				if r.Method == http.MethodPost {
					io.WriteString(w, `<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/test</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`)
				} else {
					io.WriteString(w, `<ListResourceRecordSetsResponse><ResourceRecordSets></ResourceRecordSets></ListResourceRecordSetsResponse>`)
				}
			}))
			defer server.Close()
			cfg := challengeTestConfig(t, server.URL)
			cfg.WaitForRecordSetsChanged = phase == "poll"
			configureChallengeCredentials(t, cfg, phase, server.URL)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type result struct {
				cleanup dnsrecord.Cleanup
				err     error
			}
			done := make(chan result, 1)
			go func() {
				cleanup, err := presentChallenge(ctx, cfg, "_acme-challenge.example.test.", "challenge")
				done <- result{cleanup, err}
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not start")
			}
			cancel()
			select {
			case result := <-done:
				if !errors.Is(result.err, context.Canceled) {
					t.Errorf("error = %v, want context.Canceled", result.err)
				}
				wantCleanup := phase == "write" || phase == "poll"
				if (result.cleanup != nil) != wantCleanup {
					t.Errorf("cleanup=%v, want %v", result.cleanup != nil, wantCleanup)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not finish")
			}
			select {
			case <-canceled:
			case <-time.After(5 * time.Second):
				t.Fatal("underlying HTTP request was not canceled")
			}
		})
	}
}

func configureChallengeCredentials(t *testing.T, cfg *route53.Config, phase, endpoint string) {
	t.Helper()
	if phase == "assume_role" {
		cfg.AssumeRoleArn = "arn:aws:iam::123456789012:role/acme"
	}
	if phase != "credentials" && phase != "metadata" && phase != "nested_metadata" {
		return
	}
	cfg.AccessKeyID, cfg.SecretAccessKey = "", ""
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"} {
		t.Setenv(key, "")
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "absent"))
	configFile := filepath.Join(t.TempDir(), "config")
	t.Setenv("AWS_CONFIG_FILE", configFile)
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", endpoint+"/credentials")
	if phase == "metadata" || phase == "nested_metadata" {
		t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "")
		t.Setenv("AWS_EC2_METADATA_DISABLED", "false")
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", endpoint)
	}
	if phase == "nested_metadata" {
		data := "[profile nested]\nrole_arn=arn:aws:iam::123456789012:role/acme\ncredential_source=Ec2InstanceMetadata\n"
		if err := os.WriteFile(configFile, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWS_PROFILE", "nested")
	}
}

func TestChallengeKeepsLegoDefaults(t *testing.T) {
	t.Setenv(route53.EnvPropagationTimeout, "19")
	t.Setenv(route53.EnvPollingInterval, "3")
	provider, err := New(Config{}).ChallengeProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	timeout, interval := provider.(challenge.ProviderTimeout).Timeout()
	if timeout != 19*time.Second || interval != 3*time.Second {
		t.Fatalf("Timeout() = %s, %s", timeout, interval)
	}
}

func TestChallengeAssumeRoleAndRetryConfiguration(t *testing.T) {
	t.Setenv(route53.EnvAssumeRoleArn, "arn:aws:iam::123456789012:role/acme")
	t.Setenv(route53.EnvExternalID, "external-test")
	t.Setenv(route53.EnvMaxRetries, "7")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("RoleArn") != "arn:aws:iam::123456789012:role/acme" || r.Form.Get("ExternalId") != "external-test" {
			t.Errorf("assume role parameters = %v", r.Form)
		}
		io.WriteString(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>assumed-key</AccessKeyId><SecretAccessKey>assumed-secret</SecretAccessKey><SessionToken>assumed-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	defer server.Close()
	cfg := challengeTestConfig(t, server.URL)
	cfg.MaxRetries = route53.NewDefaultConfig().MaxRetries
	client, err := newChallengeClient(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Options().Retryer.MaxAttempts(); got != 7 {
		t.Errorf("retry attempts = %d, want 7", got)
	}
	creds, err := client.Options().Credentials.Retrieve(t.Context())
	if err != nil || creds.AccessKeyID != "assumed-key" {
		t.Fatalf("assumed credentials key = %q, error = %v", creds.AccessKeyID, err)
	}
}

func TestChallengePrivateZoneSelection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<ListHostedZonesByNameResponse><HostedZones><HostedZone><Id>/hostedzone/public</Id><Name>example.test.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone><HostedZone><Id>/hostedzone/private</Id><Name>example.test.</Name><Config><PrivateZone>true</PrivateZone></Config></HostedZone></HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesByNameResponse>`)
	}))
	defer server.Close()
	cfg := challengeTestConfig(t, server.URL)
	cfg.HostedZoneID = ""
	client, err := newChallengeClient(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []bool{false, true} {
		cfg.PrivateZone = private
		zone, err := challengeHostedZone(t.Context(), client, cfg, "_acme-challenge.example.test.")
		want := "public"
		if private {
			want = "private"
		}
		if err != nil || zone != want {
			t.Errorf("private=%t zone=%q, error=%v", private, zone, err)
		}
	}
}
