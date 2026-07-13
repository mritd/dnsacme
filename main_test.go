package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
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
		{name: "renewal window ratio above one", mutate: func(c *Config) { c.RenewalWindowRatio = 1.5 }, want: "Renewal Window Ratio"},
		{name: "renewal window ratio negative", mutate: func(c *Config) { c.RenewalWindowRatio = -0.2 }, want: "Renewal Window Ratio"},
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
	resetViperForTest(t)
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

func TestConfigFromFile(t *testing.T) {
	resetViperForTest(t)
	path := filepath.Join(t.TempDir(), "dnsacme.yaml")
	storageDir := t.TempDir()
	data := strings.Join([]string{
		"domain:",
		"  - example.com",
		"  - '*.example.com'",
		"email: ops@example.com",
		"storage-dir: " + storageDir,
		"key-type: P256",
		"dns: cloudflare",
		"dns-config:",
		"  CLOUDFLARE_API_TOKEN: token",
		"zerossl: false",
		"obtained-hook: /bin/true",
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	configFile = path
	if err := readConfigFile(); err != nil {
		t.Fatalf("readConfigFile returned error: %v", err)
	}
	cfg, err := configFromViper()
	if err != nil {
		t.Fatalf("configFromViper returned error: %v", err)
	}
	if got := strings.Join(cfg.Domains, ","); got != "example.com,*.example.com" {
		t.Fatalf("unexpected domains: %s", got)
	}
	if cfg.Email != "ops@example.com" || cfg.StorageDir != storageDir || cfg.KeyType != "p256" {
		t.Fatalf("unexpected config from file: %#v", cfg)
	}
	if cfg.ZeroSSLCA {
		t.Fatal("expected zerossl false from config file")
	}
	if cfg.DNSConfig[ENV_CLOUDFLARE_API_TOKEN] != "token" {
		t.Fatalf("unexpected dns config: %#v", cfg.DNSConfig)
	}
}

func TestReadConfigFileFromEnvAndErrors(t *testing.T) {
	resetViperForTest(t)
	path := filepath.Join(t.TempDir(), "missing.yaml")
	t.Setenv("ACME_CONFIG", path)
	if err := readConfigFile(); err == nil || !strings.Contains(err.Error(), "failed to read config file") {
		t.Fatalf("expected config file error, got %v", err)
	}
}

func TestMainFunctionExists(t *testing.T) {
	if os.Args == nil {
		t.Fatal("os.Args should be initialized")
	}
}

func resetViperForTest(t *testing.T) {
	t.Helper()
	oldConfigFile := configFile
	configFile = ""
	viper.Reset()
	bindConfigSources()
	t.Cleanup(func() {
		configFile = oldConfigFile
		viper.Reset()
		bindConfigSources()
	})
}
