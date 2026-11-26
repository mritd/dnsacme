//go:build synology

package main

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mritd/dnsacme/internal/provider"
)

func multiCredentialSynologyConfig(dir string) SynologyConfig {
	cfg := validSynologyConfig(dir)
	cfg.ACME.Domains = []string{"example.com", "*.example.com", "example.org"}
	cfg.DNS.Credentials = []SynologyDNSCredential{
		{Name: "cf-main", Provider: provider.Cloudflare, Config: map[string]string{provider.CloudflareAPIToken: "cf-token"}},
		{Name: "cf-org", Provider: provider.Cloudflare, Config: map[string]string{provider.CloudflareAPIToken: "org-token"}},
	}
	cfg.DNS.Assignments = map[string]string{"example.org": "cf-org"}
	return cfg
}

func TestSynologySingleCredentialKeepsLegacyHash(t *testing.T) {
	legacy := validSynologyConfig(t.TempDir())
	single := legacy
	single.DNS.Credentials = []SynologyDNSCredential{{
		Name:     "renamed",
		Provider: provider.Cloudflare,
		Config:   map[string]string{provider.CloudflareAPIToken: "cf-token"},
	}}
	single.DNS.Assignments = map[string]string{"example.com": "renamed"}

	if single.ConfigHash() != legacy.ConfigHash() {
		t.Fatal("a single named credential must hash like the legacy single-provider config")
	}
	normalized := normalizeSynologyConfig(single)
	if len(normalized.DNS.Credentials) != 0 || len(normalized.DNS.Assignments) != 0 {
		t.Fatalf("single credential was not folded into the legacy shape: %+v", normalized.DNS)
	}
}

func TestSynologyMultiCredentialNormalizesMirrorAndAssignments(t *testing.T) {
	cfg := normalizeSynologyConfig(multiCredentialSynologyConfig(t.TempDir()))
	if cfg.DNS.Provider != provider.Cloudflare || cfg.DNS.Config[provider.CloudflareAPIToken] != "cf-token" {
		t.Fatalf("legacy fields do not mirror the first credential: %+v", cfg.DNS)
	}
	want := map[string]string{"example.com": "cf-main", "*.example.com": "cf-main", "example.org": "cf-org"}
	for domain, name := range want {
		if cfg.DNS.Assignments[domain] != name {
			t.Fatalf("assignment for %s = %q, want %q", domain, cfg.DNS.Assignments[domain], name)
		}
	}

	base := multiCredentialSynologyConfig(t.TempDir())
	changed := base
	changed.DNS.Assignments = map[string]string{"example.org": "cf-main"}
	if base.ConfigHash() == changed.ConfigHash() {
		t.Fatal("changing a domain assignment must change ConfigHash")
	}
}

func TestSynologyMultiCredentialRuntimeRoutes(t *testing.T) {
	runtime := multiCredentialSynologyConfig(t.TempDir()).RuntimeConfig(false)
	if runtime.DNSProvider != provider.Cloudflare || runtime.DNSConfig[provider.CloudflareAPIToken] != "cf-token" {
		t.Fatalf("runtime default provider is not the primary credential: %+v", runtime)
	}
	if got := runtime.DNSRoutes["example.org"].Config[provider.CloudflareAPIToken]; got != "org-token" {
		t.Fatalf("example.org route token = %q", got)
	}
	if got := runtime.DNSRoutes["*.example.com"].Config[provider.CloudflareAPIToken]; got != "cf-token" {
		t.Fatalf("*.example.com route token = %q", got)
	}
	if legacy := validSynologyConfig(t.TempDir()).RuntimeConfig(false); legacy.DNSRoutes != nil {
		t.Fatalf("legacy config must not create DNS routes: %+v", legacy.DNSRoutes)
	}
}

func TestSynologyMultiCredentialValidation(t *testing.T) {
	dir := t.TempDir()
	if err := validateConfigForSynology(multiCredentialSynologyConfig(dir), true); err != nil {
		t.Fatalf("valid multi-credential config rejected: %v", err)
	}

	cases := map[string]func(*SynologyConfig){
		"duplicate DNS credential name": func(cfg *SynologyConfig) { cfg.DNS.Credentials[1].Name = "cf-main" },
		"name is empty":                 func(cfg *SynologyConfig) { cfg.DNS.Credentials[1].Name = " " },
		"unknown DNS credential":        func(cfg *SynologyConfig) { cfg.DNS.Assignments["example.org"] = "missing" },
		"invalid DNS credential name":   func(cfg *SynologyConfig) { cfg.DNS.Credentials[1].Name = "<b>org</b>" },
		"must use the same DNS credential": func(cfg *SynologyConfig) {
			cfg.DNS.Assignments["*.example.com"] = "cf-org"
		},
		"config is empty": func(cfg *SynologyConfig) { cfg.DNS.Credentials[1].Config = map[string]string{} },
	}
	for want, mutate := range cases {
		cfg := multiCredentialSynologyConfig(dir)
		mutate(&cfg)
		if err := validateConfigForSynology(cfg, true); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q validation error, got %v", want, err)
		}
	}
}

func TestSynologyMultiCredentialRedactionAndRenameKeepSecrets(t *testing.T) {
	current := normalizeSynologyConfig(multiCredentialSynologyConfig(t.TempDir()))
	redacted := current.Redacted()
	for _, credential := range redacted.DNS.Credentials {
		if credential.Config[provider.CloudflareAPIToken] != "********" {
			t.Fatalf("credential %s leaked its token: %+v", credential.Name, credential.Config)
		}
	}
	if current.DNS.Credentials[1].Config[provider.CloudflareAPIToken] != "org-token" {
		t.Fatal("redaction mutated the persisted credential")
	}

	next := redacted
	next.DNS.Credentials[1].PreviousName = "cf-org"
	next.DNS.Credentials[1].Name = "org"
	next.DNS.Assignments = map[string]string{"example.org": "org"}
	merged := normalizeSynologyConfig(mergeSecrets(next, current))
	if got := merged.DNS.Credentials[1].Config[provider.CloudflareAPIToken]; got != "org-token" {
		t.Fatalf("renamed credential lost its secret: %q", got)
	}
	if got := merged.DNS.Credentials[0].Config[provider.CloudflareAPIToken]; got != "cf-token" {
		t.Fatalf("primary credential lost its secret: %q", got)
	}
	if merged.DNS.Credentials[1].PreviousName != "" {
		t.Fatal("request-only previous name was persisted")
	}

	// A legacy config is addressed as the "default" credential by the UI.
	legacy := validSynologyConfig(t.TempDir())
	upgrade := legacy.Redacted()
	upgrade.DNS.Credentials = []SynologyDNSCredential{
		{Name: "cloudflare", PreviousName: synologyDefaultCredentialName, Provider: provider.Cloudflare, Config: map[string]string{provider.CloudflareAPIToken: "********"}},
		{Name: "other", Provider: provider.Cloudflare, Config: map[string]string{provider.CloudflareAPIToken: "other-token"}},
	}
	merged = normalizeSynologyConfig(mergeSecrets(upgrade, legacy))
	if got := merged.DNS.Credentials[0].Config[provider.CloudflareAPIToken]; got != "cf-token" {
		t.Fatalf("legacy secret was not carried into the first named credential: %q", got)
	}
}

func TestSynologyMultiDomainDeployConfig(t *testing.T) {
	cfg := normalizeSynologyConfig(multiCredentialSynologyConfig(t.TempDir()))
	first := synologyDeployConfigFor(cfg, "example.com")
	second := synologyDeployConfigFor(cfg, "example.org")
	if first.CertificateDesc != "DNSACME example.com" || second.CertificateDesc != "DNSACME example.org" {
		t.Fatalf("unexpected descriptions %q / %q", first.CertificateDesc, second.CertificateDesc)
	}
	if !first.AsDefault || second.AsDefault {
		t.Fatal("only the first identifier may become the DSM default certificate")
	}

	single := validSynologyConfig(t.TempDir())
	if got := synologyDeployConfigFor(single, "example.com").CertificateDesc; got != "DNSACME" {
		t.Fatalf("single-domain description must stay unchanged, got %q", got)
	}
}

func TestSynologyApplyDeploysEveryDomain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := multiCredentialSynologyConfig(dir)

	var mu sync.Mutex
	imported := map[string]string{}
	server := fakeSynologyServerWithCerts(t, map[string]string{}, func(fields map[string]string) {
		mu.Lock()
		defer mu.Unlock()
		imported[fields["desc"]] = fields["as_default"]
	})
	u, _ := url.Parse(server.URL)
	host, port, _ := strings.Cut(u.Host, ":")
	cfg.Synology.Scheme = u.Scheme
	cfg.Synology.Host = host
	cfg.Synology.Port = atoiForTest(port)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	for _, domain := range cfg.ACME.Domains {
		writeStoredCert(t, cfg.Runtime.StorageDir, domain)
	}

	oldManage := manageCertificates
	var managed []string
	manageCertificates = func(ctx context.Context, magic *certmagic.Config, domains []string) error {
		managed = append([]string(nil), domains...)
		return nil
	}
	defer func() { manageCertificates = oldManage }()

	result, err := runSynologyApply(context.Background(), path)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if result.State != "ok" || len(managed) != 3 {
		t.Fatalf("unexpected apply result %q, managed %v", result.State, managed)
	}
	want := map[string]string{
		"DNSACME example.com":   "true",
		"DNSACME *.example.com": "",
		"DNSACME example.org":   "",
	}
	if len(imported) != len(want) {
		t.Fatalf("imported %v, want %v", imported, want)
	}
	for desc, asDefault := range want {
		got, ok := imported[desc]
		if !ok || got != asDefault {
			t.Fatalf("import %q as_default=%q (found %v), want %q", desc, got, ok, asDefault)
		}
	}
	saved, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.CanRenew() || saved.LastApply.At.After(time.Now()) {
		t.Fatalf("apply did not open the renewal gate: %+v", saved.LastApply)
	}
}

func TestSynologyCGISaveRoundTripsCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := saveSynologyConfig(path, validSynologyConfig(dir)); err != nil {
		t.Fatal(err)
	}

	// A legacy config shown as "default", renamed, alongside a new account.
	body := `{"acme":{"domains":["example.com","example.org"],"email":"admin@example.com"},
	"dns":{"provider":"cloudflare","config":{"CLOUDFLARE_API_TOKEN":"********"},
	"credentials":[
		{"name":"main","previousName":"default","provider":"cloudflare","config":{"CLOUDFLARE_API_TOKEN":"********"}},
		{"name":"org","provider":"cloudflare","config":{"CLOUDFLARE_API_TOKEN":"org-token"}}],
	"assignments":{"example.org":"org"}},
	"synology":{"account":"admin","password":"********","certificateDesc":"DNSACME","create":true}}`
	if _, err := cgiConfig(http.MethodPost, path, strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	saved, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.DNS.Credentials) != 2 || saved.DNS.Credentials[0].Config[provider.CloudflareAPIToken] != "cf-token" {
		t.Fatalf("renamed legacy credential lost its secret: %+v", saved.DNS.Credentials)
	}
	if saved.DNS.Assignments["example.org"] != "org" || saved.DNS.Assignments["example.com"] != "main" {
		t.Fatalf("unexpected assignments: %+v", saved.DNS.Assignments)
	}

	// Dropping back to one credential folds it into the legacy shape; a browser
	// that still calls it "main" must keep the stored secret.
	body = `{"acme":{"domains":["example.com"],"email":"admin@example.com"},
	"dns":{"provider":"cloudflare","config":{"CLOUDFLARE_API_TOKEN":"********"},
	"credentials":[{"name":"main","previousName":"main","provider":"cloudflare","config":{"CLOUDFLARE_API_TOKEN":"********"}}]},
	"synology":{"account":"admin","password":"********","certificateDesc":"DNSACME","create":true}}`
	if _, err := cgiConfig(http.MethodPost, path, strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	body = strings.Replace(body, `"previousName":"main"`, `"previousName":"main-renamed"`, 1)
	if _, err := cgiConfig(http.MethodPost, path, strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	saved, err = loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.DNS.Credentials) != 0 || saved.DNS.Config[provider.CloudflareAPIToken] != "cf-token" {
		t.Fatalf("lone credential did not fold into the legacy shape with its secret: %+v", saved.DNS)
	}

	bad := strings.Replace(body, `"credentials":[`, `"credentials":[{"name":"main","provider":"cloudflare","config":{"CLOUDFLARE_API_TOKEN":"x"}},`, 1)
	if _, err := cgiConfig(http.MethodPost, path, strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate credential error, got %v", err)
	}
}
