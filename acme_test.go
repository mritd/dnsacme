package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"github.com/mritd/dnsacme/internal/provider"
)

type fakeDNSProvider struct{}

func (fakeDNSProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return recs, nil
}

func (fakeDNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return recs, nil
}

func TestDNSProviderForConfig(t *testing.T) {
	oldNewDNSProvider := newDNSProvider
	defer func() { newDNSProvider = oldNewDNSProvider }()

	credentials := map[string]string{"token": "value"}
	newDNSProvider = func(name string, config map[string]string) (certmagic.DNSProvider, error) {
		if name != "FAKE" {
			t.Fatalf("provider received wrong name: %q", name)
		}
		if config["token"] != "value" {
			t.Fatalf("provider received wrong config: %#v", config)
		}
		return fakeDNSProvider{}, nil
	}

	dnsProvider, err := dnsProviderForConfig(&Config{DNSProvider: "FAKE", DNSConfig: credentials})
	if err != nil {
		t.Fatalf("dnsProviderForConfig returned error: %v", err)
	}
	if dnsProvider == nil {
		t.Fatal("dnsProviderForConfig returned nil provider")
	}

	newDNSProvider = provider.New
	if _, err := dnsProviderForConfig(&Config{DNSProvider: "Missing"}); err == nil || err.Error() != "unsupported DNS provider: Missing" {
		t.Fatalf("unexpected unsupported provider error: %v", err)
	}
}

func TestNewACMEIssuerSelectsCAAndEAB(t *testing.T) {
	logger := newACMELogger()
	magic := newCertMagicConfig(&Config{KeyType: "p384", StorageDir: t.TempDir()}, logger)

	issuer := newACMEIssuer(&Config{
		Email:       "ops@example.com",
		ZeroSSLCA:   true,
		EABKeyID:    "kid",
		EABHMACKey:  "mac",
		StorageDir:  t.TempDir(),
		KeyType:     "p384",
		DNSProvider: provider.Cloudflare,
	}, magic, fakeDNSProvider{}, logger)

	if issuer.CA != certmagic.ZeroSSLProductionCA {
		t.Fatalf("expected ZeroSSL CA, got %q", issuer.CA)
	}
	if issuer.ExternalAccount == nil || issuer.ExternalAccount.KeyID != "kid" || issuer.ExternalAccount.MACKey != "mac" {
		t.Fatalf("unexpected external account: %#v", issuer.ExternalAccount)
	}
	if issuer.Email != "ops@example.com" {
		t.Fatalf("unexpected issuer email: %q", issuer.Email)
	}
	if issuer.DNS01Solver == nil {
		t.Fatal("expected DNS01 solver")
	}

	issuer = newACMEIssuer(&Config{Email: "ops@example.com"}, magic, fakeDNSProvider{}, logger)
	if issuer.CA != certmagic.LetsEncryptProductionCA {
		t.Fatalf("expected Let's Encrypt CA, got %q", issuer.CA)
	}
	if issuer.ExternalAccount != nil {
		t.Fatalf("expected no external account: %#v", issuer.ExternalAccount)
	}
}

func TestResolveRenewalWindowRatio(t *testing.T) {
	tests := []struct {
		name   string
		env    string
		config float64
		want   float64
	}{
		{name: "EnvOverridesConfig", env: "0.9", config: 0.5, want: 0.9},
		{name: "EnvBoundaryOne", env: "1", config: 0.5, want: 1},
		{name: "EnvInvalidFallsBackToConfig", env: "not-a-number", config: 0.5, want: 0.5},
		{name: "EnvOutOfRangeFallsBackToConfig", env: "1.5", config: 0.5, want: 0.5},
		{name: "EnvZeroFallsBackToConfig", env: "0", config: 0.5, want: 0.5},
		{name: "ConfigOnly", env: "", config: 0.25, want: 0.25},
		{name: "ConfigOutOfRangeFallsBackToDefault", env: "", config: 1.5, want: certmagic.DefaultRenewalWindowRatio},
		{name: "ConfigNegativeFallsBackToDefault", env: "", config: -0.3, want: certmagic.DefaultRenewalWindowRatio},
		{name: "AllUnsetUsesDefault", env: "", config: 0, want: certmagic.DefaultRenewalWindowRatio},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(renewalWindowRatioEnv, tt.env)
			if got := resolveRenewalWindowRatio(tt.config); got != tt.want {
				t.Fatalf("resolveRenewalWindowRatio(%v) with env %q = %v, want %v", tt.config, tt.env, got, tt.want)
			}
		})
	}

	// The resolved value must reach the CertMagic config used for management.
	t.Setenv(renewalWindowRatioEnv, "")
	magic := newCertMagicConfig(&Config{KeyType: "p384", StorageDir: t.TempDir(), RenewalWindowRatio: 0.9}, newACMELogger())
	if magic.RenewalWindowRatio != 0.9 {
		t.Fatalf("configured renewal window ratio was not plumbed: %v", magic.RenewalWindowRatio)
	}
}

func TestCertMagicConfigAndManagedConfig(t *testing.T) {
	// Keep the default-ratio assertion below hermetic against a developer shell
	// that happens to export the override.
	t.Setenv(renewalWindowRatioEnv, "")
	conf := &Config{
		KeyType:       "rsa2048",
		StorageDir:    t.TempDir(),
		ObtainedHook:  "",
		DNSProvider:   provider.Cloudflare,
		DNSConfig:     map[string]string{provider.CloudflareAPIToken: "token"},
		Domains:       []string{"example.com"},
		Email:         "ops@example.com",
		ObtainingHook: "",
	}

	logger := newACMELogger()
	magic := newCertMagicConfig(conf, logger)
	if source, ok := magic.KeySource.(certmagic.StandardKeyGenerator); !ok || source.KeyType != certmagic.RSA2048 {
		t.Fatalf("unexpected key source: %#v", magic.KeySource)
	}
	if magic.RenewalWindowRatio != certmagic.DefaultRenewalWindowRatio {
		t.Fatalf("unexpected renewal window ratio: %v", magic.RenewalWindowRatio)
	}
	if magic.Storage == nil {
		t.Fatal("expected file storage")
	}
	if magic.OnEvent == nil {
		t.Fatal("expected event hook")
	}
	managed, cache := newManagedConfigWithCache(magic, logger)
	defer cache.Stop()
	if managed == nil {
		t.Fatal("expected managed config")
	}

	magic = newCertMagicConfig(&Config{KeyType: "P384", StorageDir: t.TempDir()}, logger)
	source, ok := magic.KeySource.(certmagic.StandardKeyGenerator)
	if !ok || source.KeyType != certmagic.P384 {
		t.Fatalf("uppercase key type was not normalized: %#v", magic.KeySource)
	}
}

func TestObtainUsesInjectedRuntime(t *testing.T) {
	oldNewDNSProvider := newDNSProvider
	newDNSProvider = func(name string, config map[string]string) (certmagic.DNSProvider, error) {
		if name != "fake-obtain" {
			t.Fatalf("provider received wrong name: %q", name)
		}
		return fakeDNSProvider{}, nil
	}
	defer func() { newDNSProvider = oldNewDNSProvider }()

	oldSignal := signalNotifyContext
	oldManage := manageCertificates
	oldWait := waitForShutdown
	defer func() {
		signalNotifyContext = oldSignal
		manageCertificates = oldManage
		waitForShutdown = oldWait
	}()

	ctx, cancel := context.WithCancel(context.Background())
	signalNotifyContext = func(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
		return ctx, cancel
	}

	var managedDomains []string
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error {
		if cfg == nil {
			t.Fatal("expected certmagic config")
		}
		if len(cfg.Issuers) == 0 {
			t.Fatal("expected ACME issuer on managed config")
		}
		managedDomains = append([]string(nil), domains...)
		cancel()
		return nil
	}
	waitForShutdown = func(ctx context.Context) {}

	Obtain(&Config{
		Domains:     []string{"example.com"},
		Email:       "ops@example.com",
		KeyType:     "p384",
		StorageDir:  t.TempDir(),
		DNSProvider: "fake-obtain",
		DNSConfig:   map[string]string{"token": "value"},
		ZeroSSLCA:   false,
	})

	if len(managedDomains) != 1 || managedDomains[0] != "example.com" {
		t.Fatalf("unexpected managed domains: %#v", managedDomains)
	}
}

func TestNewEABCredentialsRequest(t *testing.T) {
	req, err := newEABCredentialsRequest(context.Background(), "ops@example.com")
	if err != nil {
		t.Fatalf("newEABCredentialsRequest returned error: %v", err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("unexpected method: %s", req.Method)
	}
	if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Fatalf("unexpected content type: %q", got)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "email=ops%40example.com" {
		t.Fatalf("unexpected request body: %q", body)
	}
}

func TestDecodeEABCredentialsResponse(t *testing.T) {
	eab, err := decodeEABCredentialsResponse(http.StatusOK, strings.NewReader(`{"success":true,"eab_kid":"kid","eab_hmac_key":"mac"}`))
	if err != nil {
		t.Fatalf("decodeEABCredentialsResponse returned error: %v", err)
	}
	if eab.KeyID != "kid" || eab.MACKey != "mac" {
		t.Fatalf("unexpected EAB: %#v", eab)
	}

	tests := []struct {
		name       string
		statusCode int
		body       string
		want       string
	}{
		{name: "invalid json", statusCode: http.StatusOK, body: `{`, want: "failed decoding"},
		{name: "api error", statusCode: http.StatusOK, body: `{"error":{"code":42,"type":"bad_email"}}`, want: "bad_email"},
		{name: "http error", statusCode: http.StatusBadGateway, body: `{}`, want: "HTTP 502"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeEABCredentialsResponse(tt.statusCode, strings.NewReader(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestGenerateEABCredentialsUsesHTTPClient(t *testing.T) {
	old := httpClientDo
	defer func() { httpClientDo = old }()

	httpClientDo = func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://api.zerossl.com/acme/eab-credentials-email" {
			t.Fatalf("unexpected URL: %s", req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"eab_kid":"kid","eab_hmac_key":"mac"}`)),
		}, nil
	}

	eab := generateEABCredentials("ops@example.com")
	if eab.KeyID != "kid" || eab.MACKey != "mac" {
		t.Fatalf("unexpected EAB: %#v", eab)
	}
}
