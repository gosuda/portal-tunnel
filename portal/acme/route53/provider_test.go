package route53

import (
	"context"
	"testing"
)

func TestFindHostedZoneIDExplicitOverride(t *testing.T) {
	t.Parallel()

	got, err := New(Config{HostedZoneID: "/hostedzone/Z123456789"}).findHostedZoneID(context.Background(), nil, "portal.example.com")
	if err != nil {
		t.Fatalf("findHostedZoneID() error = %v", err)
	}
	if got != "Z123456789" {
		t.Fatalf("findHostedZoneID() = %q, want %q", got, "Z123456789")
	}
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name: "access key without secret",
			cfg: Config{
				AccessKeyID: "abc",
			},
			wantErr: "route53 access key id and secret access key must be supplied together",
		},
		{
			name: "secret without access key",
			cfg: Config{
				SecretAccessKey: "def",
			},
			wantErr: "route53 access key id and secret access key must be supplied together",
		},
		{
			name: "session token without static credentials",
			cfg: Config{
				SessionToken: "ghi",
			},
			wantErr: "route53 session token requires access key id and secret access key",
		},
		{
			name: "valid static credentials",
			cfg: Config{
				AccessKeyID:     "abc",
				SecretAccessKey: "def",
				SessionToken:    "ghi",
			},
		},
		{
			name: "ambient credentials",
			cfg:  Config{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateConfig(tc.cfg)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("validateConfig() error = %v", err)
			}
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("validateConfig() error = %v, want %q", err, tc.wantErr)
				}
			}
		})
	}
}
