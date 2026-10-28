//go:build route53 || !slim

package provider

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/libdns/route53"
)

// isolateAWSEnv keeps Route 53 tests independent of the developer's AWS setup.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_PROFILE", "")
}

func TestNewRoute53_MapsCredentials(t *testing.T) {
	isolateAWSEnv(t)
	tests := []struct {
		name       string
		config     map[string]string
		wantRegion string
		wantZoneID string
	}{
		{
			name:       "required only uses default region",
			config:     map[string]string{Route53AccessKeyID: "id", Route53SecretAccessKey: "secret"},
			wantRegion: route53DefaultRegion,
		},
		{
			name: "optional values are mapped",
			config: map[string]string{
				Route53AccessKeyID: "id", Route53SecretAccessKey: "secret",
				Route53Region: "cn-northwest-1", Route53HostedZoneID: "Z123",
			},
			wantRegion: "cn-northwest-1",
			wantZoneID: "Z123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(Route53, tt.config)
			if err != nil {
				t.Fatal(err)
			}
			provider, ok := got.(*route53.Provider)
			if !ok {
				t.Fatalf("New returned %T", got)
			}
			if provider.AccessKeyId != "id" || provider.SecretAccessKey != "secret" ||
				provider.Region != tt.wantRegion || provider.HostedZoneID != tt.wantZoneID {
				t.Fatalf("unexpected provider: %#v", provider)
			}
		})
	}
}

func TestNewRoute53_RequiresStaticCredentials(t *testing.T) {
	for _, config := range []map[string]string{
		{},
		{Route53AccessKeyID: "id"},
		{Route53SecretAccessKey: "secret"},
	} {
		_, err := New(Route53, config)
		if err == nil || err.Error() != "failed to get Route53 Access Key ID or Secret Access Key" {
			t.Fatalf("New(%v) error = %v", config, err)
		}
	}
}

func TestNewRoute53_InvalidAWSEnvReturnsError(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_PROFILE", "missing")
	_, err := New(Route53, map[string]string{Route53AccessKeyID: "id", Route53SecretAccessKey: "secret"})
	if err == nil || !strings.Contains(err.Error(), "failed to load AWS config for Route53") {
		t.Fatalf("New error = %v", err)
	}
}
