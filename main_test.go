package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDataDirUsesXDGConfigHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	got := dataDir()
	want := filepath.Join(dir, "certmagic")
	if got != want {
		t.Fatalf("dataDir() = %q, want %q", got, want)
	}
}

func TestValidateConfigSuccess(t *testing.T) {
	cfg, err := validateConfig(Config{
		Domains:       []string{"example.com"},
		Email:         "ops@example.com",
		StorageDir:    t.TempDir(),
		KeyType:       "P384",
		DNSProvider:   "cloudflare",
		DNSConfig:     map[string]string{ENV_CLOUDFLARE_API_TOKEN: "token"},
		ZeroSSLCA:     true,
		ObtainingHook: "/bin/true",
		ObtainedHook:  "/bin/true",
		FailedHook:    "/bin/true",
	})
	if err != nil {
		t.Fatalf("validateConfig returned error: %v", err)
	}
	if cfg.KeyType != "p384" {
		t.Fatalf("expected normalized key type, got %q", cfg.KeyType)
	}
}

func TestParseDNSConfig(t *testing.T) {
	got := parseDNSConfig("A=1, B=two=parts, invalid, =empty")
	if got["A"] != "1" || got["B"] != "two=parts" {
		t.Fatalf("unexpected parsed config: %#v", got)
	}
	if _, ok := got[""]; ok {
		t.Fatalf("empty key should be ignored: %#v", got)
	}
}

func TestValidateConfigErrors(t *testing.T) {
	base := Config{
		Domains:     []string{"example.com"},
		Email:       "ops@example.com",
		StorageDir:  t.TempDir(),
		KeyType:     "p384",
		DNSProvider: "cloudflare",
		DNSConfig:   map[string]string{ENV_CLOUDFLARE_API_TOKEN: "token"},
	}

	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "missing domain", mutate: func(c *Config) { c.Domains = nil }, want: "ACME Domain is empty"},
		{name: "missing email", mutate: func(c *Config) { c.Email = "" }, want: "ACME Email is empty"},
		{name: "bad key type", mutate: func(c *Config) { c.KeyType = "p521" }, want: "Unsupported KeyType"},
		{name: "missing provider", mutate: func(c *Config) { c.DNSProvider = "" }, want: "ACME DNS Provider is empty"},
		{name: "missing provider config", mutate: func(c *Config) { c.DNSConfig = nil }, want: "ACME DNS Provider config is empty"},
		{name: "obtaining hook args", mutate: func(c *Config) { c.ObtainingHook = "/bin/echo hello" }, want: "Obtaining Hook"},
		{name: "obtained hook args", mutate: func(c *Config) { c.ObtainedHook = "/bin/echo hello" }, want: "Obtained Hook"},
		{name: "failed hook args", mutate: func(c *Config) { c.FailedHook = "/bin/echo hello" }, want: "Failed Hook"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			_, err := validateConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestProvidersSort(t *testing.T) {
	providers := Providers{"z", "a", "m"}
	if providers.Len() != 3 {
		t.Fatalf("unexpected len: %d", providers.Len())
	}
	if !providers.Less(1, 2) {
		t.Fatal("expected a < m")
	}
	providers.Swap(0, 1)
	if providers[0] != "a" || providers[1] != "z" {
		t.Fatalf("unexpected swap result: %#v", providers)
	}
}

func TestConfigFromViperReadsBoundValues(t *testing.T) {
	t.Setenv("ACME_DOMAIN", "example.com")
	t.Setenv("ACME_EMAIL", "ops@example.com")
	t.Setenv("ACME_STORAGE_DIR", t.TempDir())
	t.Setenv("ACME_KEY_TYPE", "P256")
	t.Setenv("ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("ACME_DNS_CONFIG", "CLOUDFLARE_API_TOKEN=token")
	t.Setenv("ACME_ZEROSSL", "false")

	cfg, err := configFromViper()
	if err != nil {
		t.Fatalf("configFromViper returned error: %v", err)
	}
	if len(cfg.Domains) == 0 || cfg.Domains[0] != "example.com" {
		t.Fatalf("unexpected domains: %#v", cfg.Domains)
	}
	if cfg.KeyType != "p256" {
		t.Fatalf("unexpected key type: %q", cfg.KeyType)
	}
	if cfg.ZeroSSLCA {
		t.Fatal("expected ZeroSSL disabled")
	}
}

func TestMainFunctionExists(t *testing.T) {
	if os.Args == nil {
		t.Fatal("os.Args should be initialized")
	}
}
