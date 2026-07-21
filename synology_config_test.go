//go:build synology

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mritd/dnsacme/internal/provider"
)

func TestSynologyConfigDefaultsSaveLoadAndHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Provider != provider.Default() {
		t.Fatalf("unexpected default provider: %s", cfg.DNS.Provider)
	}

	cfg.ACME.Domains = []string{" example.com ", "", "*.example.com", "example.com"}
	cfg.ACME.Email = "admin@example.com"
	cfg.DNS.Config[provider.CloudflareAPIToken] = "secret-token"
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config permissions = %o, want 600", got)
	}

	loaded, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(loaded.ACME.Domains, ","); got != "example.com,*.example.com" {
		t.Fatalf("unexpected domains: %s", got)
	}
	hash := loaded.ConfigHash()
	loaded.LastTest = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: hash}
	if !loaded.TestPassed() {
		t.Fatal("expected matching staging test to be reported")
	}
	if loaded.CanRenew() {
		t.Fatal("expected renew to stay blocked before apply succeeds")
	}
	loaded.LastApply = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: hash}
	if !loaded.CanRenew() {
		t.Fatal("expected renew to be allowed after matching apply hash")
	}
	loaded.ACME.Domains = append(loaded.ACME.Domains, "www.example.com")
	if loaded.TestPassed() {
		t.Fatal("expected config change to invalidate the staging result")
	}
	if loaded.CanRenew() {
		t.Fatal("expected config change to invalidate renew")
	}
}

func TestSynologyReconfigurationStateDoesNotChangeConfigHash(t *testing.T) {
	cfg := validSynologyConfig(t.TempDir())
	want := cfg.ConfigHash()
	cfg.Reconfiguring = true
	if got := cfg.ConfigHash(); got != want {
		t.Fatalf("reconfiguration state changed config hash: got %s, want %s", got, want)
	}
}

func TestSynologyConfigPathEnvAndInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env.yaml")
	t.Setenv("DNSACME_CONFIG", path)
	if got := synologyConfigPath(""); got != path {
		t.Fatalf("unexpected env config path: %s", got)
	}
	if got := synologyConfigPath("explicit.yaml"); got != "explicit.yaml" {
		t.Fatalf("explicit path should win: %s", got)
	}
	if err := os.WriteFile(path, []byte("acme: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSynologyConfig(""); err == nil {
		t.Fatal("expected invalid YAML error")
	}
}

func TestNormalizeSynologyConfigFillsDefaults(t *testing.T) {
	cfg := normalizeSynologyConfig(SynologyConfig{})
	if cfg.ACME.KeyType != "rsa4096" ||
		cfg.ACME.CA != "letsencrypt" ||
		cfg.DNS.Provider != provider.Default() ||
		cfg.Synology.Scheme != "https" ||
		cfg.Synology.Port != 5001 ||
		cfg.Runtime.StorageDir == "" ||
		cfg.Runtime.StagingDir == "" ||
		cfg.Runtime.LogPath == "" {
		t.Fatalf("defaults were not normalized: %+v", cfg)
	}
}

func TestSynologyRuntimeConfigStagingAndProduction(t *testing.T) {
	cfg := validSynologyConfig(t.TempDir())
	staging := cfg.RuntimeConfig(true)
	if staging.CA == "" || staging.ZeroSSLCA {
		t.Fatalf("unexpected staging runtime: %+v", staging)
	}
	if staging.StorageDir != cfg.Runtime.StagingDir {
		t.Fatalf("unexpected staging dir: %s", staging.StorageDir)
	}

	cfg.ACME.CA = "zerossl"
	production := cfg.RuntimeConfig(false)
	if !production.ZeroSSLCA || production.StorageDir != cfg.Runtime.StorageDir {
		t.Fatalf("unexpected production runtime: %+v", production)
	}
}

func TestLegacyForceStagingCannotAffectProductionRuntime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	legacy := []byte("acme:\n  ca: letsencrypt\nforceStaging: true\n")
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	production := cfg.RuntimeConfig(false)
	if production.CA != certmagic.LetsEncryptProductionCA {
		t.Fatalf("legacy forceStaging changed production CA: %q", production.CA)
	}
	if production.StorageDir != cfg.Runtime.StorageDir {
		t.Fatalf("legacy forceStaging changed production storage: %s", production.StorageDir)
	}
}

func TestConfigHashKeepsLegacyProductionShape(t *testing.T) {
	cfg := normalizeSynologyConfig(validSynologyConfig(t.TempDir()))
	legacyShape := struct {
		ACME         SynologyACMEConfig    `json:"acme"`
		DNS          SynologyDNSConfig     `json:"dns"`
		Synology     SynologyDeployConfig  `json:"synology"`
		Runtime      SynologyRuntimeConfig `json:"runtime"`
		ForceStaging bool                  `json:"forceStaging"`
	}{cfg.ACME, cfg.DNS, cfg.Synology, cfg.Runtime, false}
	data, err := json.Marshal(legacyShape)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	if got := cfg.ConfigHash(); got != hex.EncodeToString(want[:]) {
		t.Fatalf("production config hash changed across ForceStaging removal: got %s", got)
	}
	legacyShape.ForceStaging = true
	data, err = json.Marshal(legacyShape)
	if err != nil {
		t.Fatal(err)
	}
	stagingHash := sha256.Sum256(data)
	cfg.LastApply = SynologyOperationState{Success: true, ConfigHash: hex.EncodeToString(stagingHash[:])}
	if cfg.CanRenew() {
		t.Fatal("a legacy staging deployment must not renew after the option is removed")
	}
}

func TestProviderMetadataAndRedaction(t *testing.T) {
	meta := provider.Definitions()
	if len(meta) == 0 {
		return
	}
	if meta[0].Name != provider.Default() {
		t.Fatalf("default provider should be first: %+v", meta)
	}
	if provider.Default() != provider.Cloudflare {
		t.Skip("full redaction compatibility assertions require Cloudflare")
	}
	if meta[0].Name != provider.Cloudflare {
		t.Fatalf("Cloudflare should be the first provider: %+v", meta)
	}
	var foundToken bool
	for _, field := range meta[0].Fields {
		if field.Key == provider.CloudflareAPIToken && field.Secret && field.Required {
			foundToken = true
		}
	}
	if !foundToken {
		t.Fatal("missing Cloudflare token field metadata")
	}

	cfg := validSynologyConfig(t.TempDir())
	cfg.Synology.Password = "dsm-password"
	redacted := cfg.Redacted()
	if redacted.DNS.Config[provider.CloudflareAPIToken] != "********" {
		t.Fatal("expected DNS token redaction")
	}
	if redacted.Synology.Password != "********" {
		t.Fatal("expected DSM password redaction")
	}
	if _, ok := provider.FieldByKey(provider.AliDNSAccessKeyID); !ok {
		return
	}

	cfg.DNS.Provider = provider.AliDNS
	cfg.DNS.Config = map[string]string{
		provider.AliDNSAccessKeyID:     "LTAI1234567890",
		provider.AliDNSAccessKeySecret: "secret-value",
		provider.AliDNSRegionID:        "cn-hangzhou",
	}
	redacted = cfg.Redacted()
	if redacted.DNS.Config[provider.AliDNSAccessKeyID] != "LTAI1234567890" {
		t.Fatalf("AliDNS AccessKey ID should not be redacted: %q", redacted.DNS.Config[provider.AliDNSAccessKeyID])
	}
	if redacted.DNS.Config[provider.AliDNSAccessKeySecret] != "********" {
		t.Fatal("AliDNS AccessKey Secret should be redacted")
	}
	if redacted.DNS.Config[provider.AliDNSRegionID] != "cn-hangzhou" {
		t.Fatalf("AliDNS Region ID should not be redacted: %q", redacted.DNS.Config[provider.AliDNSRegionID])
	}
}

func TestProviderMetadata_CompleteCatalog(t *testing.T) {
	want := expectedProviderDefinitions()
	if len(provider.Definitions()) != len(want) {
		t.Skip("complete catalog compatibility requires a non-slim build")
	}
	if got := provider.Definitions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("provider definitions = %#v, want %#v", got, want)
	}
	if provider.DefaultName != provider.Cloudflare {
		t.Fatalf("default provider = %q, want %q", provider.DefaultName, provider.Cloudflare)
	}
	for _, definition := range want {
		for _, field := range definition.Fields {
			got, ok := provider.FieldByKey(field.Key)
			if !ok || !reflect.DeepEqual(got, field) {
				t.Fatalf("FieldByKey(%q) = %#v, %v, want %#v", field.Key, got, ok, field)
			}
		}
	}
}

func TestCGIMetadata_JSONCompatibility(t *testing.T) {
	var out bytes.Buffer
	if err := serveSynologyCGI(
		context.Background(),
		filepath.Join(t.TempDir(), "config.yaml"),
		queryEnv("action=metadata", http.MethodGet),
		strings.NewReader(""),
		&out,
	); err != nil {
		t.Fatal(err)
	}
	resp := parseCGIResponse(t, out.String())
	if len(provider.Definitions()) == 0 {
		if resp.Success || !strings.Contains(resp.Error, "no DNS providers") {
			t.Fatalf("empty provider catalog response = %+v", resp)
		}
		return
	}
	if !resp.Success {
		t.Fatalf("metadata CGI failed: %s", resp.Error)
	}
	if len(provider.Definitions()) != len(expectedProviderDefinitions()) {
		t.Skip("complete catalog compatibility requires a non-slim build")
	}
	want, err := json.Marshal(map[string]any{"providers": expectedProviderDefinitions()})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp.Data, want) {
		t.Fatalf("metadata JSON = %s, want %s", resp.Data, want)
	}
}

func expectedProviderDefinitions() []provider.Definition {
	return []provider.Definition{
		{Name: provider.Cloudflare, Label: "Cloudflare", Fields: []provider.Field{
			{Key: provider.CloudflareAPIToken, Label: "API Token", Secret: true, Required: true, Placeholder: "Zone DNS edit token"},
		}},
		{Name: provider.AliDNS, Label: "AliDNS", Fields: []provider.Field{
			{Key: provider.AliDNSAccessKeyID, Label: "AccessKey ID", Required: true, Placeholder: "LTAI..."},
			{Key: provider.AliDNSAccessKeySecret, Label: "AccessKey Secret", Secret: true, Required: true},
			{Key: provider.AliDNSRegionID, Label: "Region ID", Placeholder: "cn-hangzhou"},
		}},
		{Name: provider.Azure, Label: "Azure DNS", Fields: []provider.Field{
			{Key: provider.AzureTenantID, Label: "Tenant ID", Required: true},
			{Key: provider.AzureClientID, Label: "Client ID", Required: true},
			{Key: provider.AzureClientSecret, Label: "Client Secret", Secret: true, Required: true},
			{Key: provider.AzureSubscriptionID, Label: "Subscription ID", Required: true},
			{Key: provider.AzureResourceGroupName, Label: "Resource Group", Required: true},
		}},
		{Name: provider.DuckDNS, Label: "Duck DNS", Fields: []provider.Field{
			{Key: provider.DuckDNSAPIToken, Label: "API Token", Secret: true, Required: true, Placeholder: "duckdns token"},
			{Key: provider.DuckDNSOverrideDomain, Label: "Override Domain"},
		}},
		{Name: provider.Gandi, Label: "Gandi", Fields: []provider.Field{
			{Key: provider.GandiAPIToken, Label: "API Token", Secret: true, Required: true, Placeholder: "Personal Access Token"},
		}},
		{Name: provider.GoDaddy, Label: "GoDaddy", Fields: []provider.Field{
			{Key: provider.GoDaddyAPIToken, Label: "API Token", Secret: true, Required: true, Placeholder: "key:secret"},
		}},
		{Name: provider.HuaweiCloud, Label: "Huawei Cloud DNS", Fields: []provider.Field{
			{Key: provider.HuaweiCloudAccessKeyID, Label: "AccessKey ID", Required: true, Placeholder: "access key id"},
			{Key: provider.HuaweiCloudAccessKeySecret, Label: "Secret AccessKey", Secret: true, Required: true},
			{Key: provider.HuaweiCloudRegionID, Label: "Region ID", Placeholder: "cn-south-1"},
		}},
		{Name: provider.TencentCloud, Label: "Tencent Cloud DNS", Fields: []provider.Field{
			{Key: provider.TencentCloudAccessKeyID, Label: "Secret ID", Required: true, Placeholder: "AKID..."},
			{Key: provider.TencentCloudAccessKeySecret, Label: "Secret Key", Secret: true, Required: true},
		}},
	}
}

func TestMergeSecretsPreservesMaskedValues(t *testing.T) {
	current := validSynologyConfig(t.TempDir())
	current.Synology.Password = "old-password"
	next := current.Redacted()
	next.ACME.Email = "new@example.com"

	merged := mergeSecrets(next, current)
	if merged.Synology.Password != "old-password" {
		t.Fatalf("masked DSM password was not preserved: %q", merged.Synology.Password)
	}
	if merged.DNS.Config[provider.CloudflareAPIToken] != "cf-token" {
		t.Fatalf("masked DNS token was not preserved: %q", merged.DNS.Config[provider.CloudflareAPIToken])
	}
	if merged.ACME.Email != "new@example.com" {
		t.Fatalf("non-secret field was not updated: %q", merged.ACME.Email)
	}

	next.Synology.Password = "new-password"
	merged = mergeSecrets(next, current)
	if merged.Synology.Password != "new-password" {
		t.Fatalf("new password was not stored: %+v", merged.Synology)
	}

	next = current.Redacted()
	next.DNS.Config[provider.CloudflareAPIToken] = ""
	next.Synology.Password = ""
	merged = mergeSecrets(next, current)
	if merged.DNS.Config[provider.CloudflareAPIToken] != "cf-token" {
		t.Fatalf("blank DNS secret should preserve stored value: %q", merged.DNS.Config[provider.CloudflareAPIToken])
	}
	if merged.Synology.Password != "old-password" {
		t.Fatalf("blank DSM password should preserve stored value: %q", merged.Synology.Password)
	}

	current.DNS.Provider = provider.AliDNS
	current.DNS.Config = map[string]string{
		provider.AliDNSAccessKeyID:     "stored-id",
		provider.AliDNSAccessKeySecret: "stored-secret",
		provider.AliDNSRegionID:        "stored-region",
	}
	next = current.Redacted()
	next.DNS.Config[provider.AliDNSAccessKeyID] = ""
	next.DNS.Config[provider.AliDNSAccessKeySecret] = ""
	next.DNS.Config[provider.AliDNSRegionID] = ""
	merged = mergeSecrets(next, current)
	if merged.DNS.Config[provider.AliDNSAccessKeyID] != "stored-id" {
		t.Fatalf("blank required AliDNS AccessKey ID should preserve stored value: %q", merged.DNS.Config[provider.AliDNSAccessKeyID])
	}
	if merged.DNS.Config[provider.AliDNSAccessKeySecret] != "stored-secret" {
		t.Fatalf("blank AliDNS secret should preserve stored value: %q", merged.DNS.Config[provider.AliDNSAccessKeySecret])
	}
	if merged.DNS.Config[provider.AliDNSRegionID] != "" {
		t.Fatalf("blank optional AliDNS Region ID should be allowed, got %q", merged.DNS.Config[provider.AliDNSRegionID])
	}
}

func TestConfigHash_CoversDeployConnAuth(t *testing.T) {
	base := defaultSynologyConfig()
	base.ACME.Domains = []string{"example.com"}
	base.Synology.Account = "admin"
	base.Synology.Password = "pw"
	h := base.ConfigHash()

	cases := map[string]func(c *SynologyConfig){
		"scheme":           func(c *SynologyConfig) { c.Synology.Scheme = "http" },
		"host":             func(c *SynologyConfig) { c.Synology.Host = "10.0.0.2" },
		"port":             func(c *SynologyConfig) { c.Synology.Port = 5555 },
		"account":          func(c *SynologyConfig) { c.Synology.Account = "root" },
		"password":         func(c *SynologyConfig) { c.Synology.Password = "pw2" },
		"certificate desc": func(c *SynologyConfig) { c.Synology.CertificateDesc = "other" },
		"create":           func(c *SynologyConfig) { c.Synology.Create = !c.Synology.Create },
		"as default":       func(c *SynologyConfig) { c.Synology.AsDefault = !c.Synology.AsDefault },
		"storage dir":      func(c *SynologyConfig) { c.Runtime.StorageDir = "/tmp/other-certmagic" },
		"staging dir":      func(c *SynologyConfig) { c.Runtime.StagingDir = "/tmp/other-staging" },
		"log path":         func(c *SynologyConfig) { c.Runtime.LogPath = "/tmp/other.log" },
	}
	for name, mut := range cases {
		c := base
		mut(&c)
		if c.ConfigHash() == h {
			t.Errorf("%s change should change ConfigHash", name)
		}
	}
}

func TestMergeSecrets_GuardsEmptyStored(t *testing.T) {
	current := defaultSynologyConfig()
	current.Synology.Password = ""
	next := defaultSynologyConfig()
	next.Synology.Password = "********"
	next.DNS.Config[provider.CloudflareAPIToken] = "********"
	got := mergeSecrets(next, current)
	if got.Synology.Password != "" {
		t.Errorf("password sentinel must not become a stored password, got %q", got.Synology.Password)
	}
	if got.DNS.Config[provider.CloudflareAPIToken] != "" {
		t.Errorf("DNS sentinel must not become a stored token, got %q", got.DNS.Config[provider.CloudflareAPIToken])
	}

	current.Synology.Password = "real"
	next.Synology.Password = "********"
	got = mergeSecrets(next, current)
	if got.Synology.Password != "real" {
		t.Errorf("configured install should restore stored password, got %q", got.Synology.Password)
	}
}

func TestRedacted_StripsOperationHashes(t *testing.T) {
	cfg := defaultSynologyConfig()
	cfg.LastTest = SynologyOperationState{Success: true, ConfigHash: "deadbeef"}
	cfg.LastApply = SynologyOperationState{Success: true, ConfigHash: "cafebabe"}
	if cfg.Redacted().LastTest.ConfigHash != "" {
		t.Error("Redacted must not expose LastTest.ConfigHash")
	}
	if cfg.Redacted().LastApply.ConfigHash != "" {
		t.Error("Redacted must not expose LastApply.ConfigHash")
	}
}

func TestCGIConfigStatusLogsAndErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	appendSynologyLog(cfg, "hello")

	var out bytes.Buffer
	err := serveSynologyCGI(context.Background(), path, queryEnv("action=config", http.MethodGet), strings.NewReader(""), &out)
	if err != nil {
		t.Fatal(err)
	}
	resp := parseCGIResponse(t, out.String())
	if !resp.Success {
		t.Fatalf("unexpected CGI failure: %+v", resp)
	}

	next := cfg
	next.ACME.Email = "new@example.com"
	next.Runtime = SynologyRuntimeConfig{StorageDir: "/tmp/client-storage", StagingDir: "/tmp/client-staging", LogPath: "/tmp/client.log"}
	body, _ := json.Marshal(next)
	out.Reset()
	err = serveSynologyCGI(context.Background(), path, queryEnv("action=config", http.MethodPost), bytes.NewReader(body), &out)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ACME.Email != "new@example.com" {
		t.Fatalf("config was not saved: %s", loaded.ACME.Email)
	}
	if loaded.Runtime != cfg.Runtime {
		t.Fatalf("CGI accepted client-supplied runtime paths: %+v", loaded.Runtime)
	}

	for _, action := range []string{"metadata", "status", "logs"} {
		out.Reset()
		err = serveSynologyCGI(context.Background(), path, queryEnv("action="+action, http.MethodGet), strings.NewReader(""), &out)
		if err != nil {
			t.Fatal(err)
		}
		if !parseCGIResponse(t, out.String()).Success {
			t.Fatalf("expected %s CGI success", action)
		}
	}

	out.Reset()
	err = serveSynologyCGI(context.Background(), path, queryEnv("action=missing", http.MethodGet), strings.NewReader(""), &out)
	if err != nil {
		t.Fatal(err)
	}
	if parseCGIResponse(t, out.String()).Success {
		t.Fatal("expected unknown action to fail")
	}

	out.Reset()
	err = serveSynologyCGI(context.Background(), path, queryEnv("action=config", http.MethodPost), strings.NewReader("{"), &out)
	if err != nil {
		t.Fatal(err)
	}
	if parseCGIResponse(t, out.String()).Success {
		t.Fatal("expected invalid JSON to fail")
	}

	out.Reset()
	err = serveSynologyCGI(context.Background(), path, queryEnv("action=test-run", http.MethodGet), strings.NewReader(""), &out)
	if err != nil {
		t.Fatal(err)
	}
	if parseCGIResponse(t, out.String()).Success {
		t.Fatal("expected method error")
	}

	out.Reset()
	err = serveSynologyCGI(context.Background(), path, queryEnv("", http.MethodGet, "status"), strings.NewReader(""), &out)
	if err != nil {
		t.Fatal(err)
	}
	if !parseCGIResponse(t, out.String()).Success {
		t.Fatal("expected PATH_INFO status success")
	}
}

func TestCGIReconfigurePersistsWithoutInvalidatingRenewal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := validSynologyConfig(t.TempDir())
	hash := cfg.ConfigHash()
	cfg.LastTest = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: hash}
	cfg.LastApply = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: hash}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	if _, err := cgiReconfigure(http.MethodGet, path); err == nil {
		t.Fatal("GET must not enable reconfiguration mode")
	}
	if _, err := cgiReconfigure(http.MethodPost, path); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Reconfiguring {
		t.Fatal("reconfiguration mode was not persisted")
	}
	if !loaded.CanRenew() {
		t.Fatal("opening the wizard must not invalidate active renewal")
	}
	if !loaded.TestPassed() || !loaded.LastTest.Success {
		t.Fatal("opening the wizard must preserve a matching optional staging result")
	}

	// A regular form save cannot clear the server-owned mode flag.
	next := loaded.Redacted()
	next.Reconfiguring = false
	body, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cgiConfig(http.MethodPost, path, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	loaded, err = loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Reconfiguring {
		t.Fatal("normal config save cleared reconfiguration mode")
	}
}

func TestSynologyCommandExecutesTestRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	setSynologyTestServer(t, &cfg)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	oldManage := manageCertificates
	oldConfigFile := configFile
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error { return nil }
	configFile = path
	defer func() {
		manageCertificates = oldManage
		configFile = oldConfigFile
	}()

	cmd := newSynologyCommand()
	cmd.SetArgs([]string{"test-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	printJSON(map[string]string{"ok": "true"})
}

func TestSynologyCommandExecutesApplyAPICGIAndDaemonError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	server := fakeSynologyServer(t)
	u, _ := url.Parse(server.URL)
	host, port, _ := strings.Cut(u.Host, ":")
	cfg.Synology.Scheme = u.Scheme
	cfg.Synology.Host = host
	cfg.Synology.Port = atoiForTest(port)
	cfg.LastTest = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash()}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	writeStoredCert(t, cfg.Runtime.StorageDir, cfg.ACME.Domains[0])

	oldManage := manageCertificates
	oldConfigFile := configFile
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error { return nil }
	configFile = path
	defer func() {
		manageCertificates = oldManage
		configFile = oldConfigFile
	}()

	cmd := newSynologyCommand()
	cmd.SetArgs([]string{"apply"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	cmd = newSynologyCommand()
	cmd.SetArgs([]string{"api-cgi"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	invalidPath := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte("acme: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	oldRetry := synologyDaemonRetryInterval
	synologyDaemonRetryInterval = time.Millisecond
	defer func() { synologyDaemonRetryInterval = oldRetry }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd = newSynologyCommand()
	cmd.SetContext(ctx)
	configFile = invalidPath
	cmd.SetArgs([]string{"daemon"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("daemon should exit cleanly on context cancellation: %v", err)
	}
}

func TestSynologyRemovedOptionsAreNotExposed(t *testing.T) {
	for _, child := range newSynologyCommand().Commands() {
		if strings.Contains(child.Name(), "notification") {
			t.Fatalf("removed notification command is still exposed: %s", child.Name())
		}
	}
	data, err := json.Marshal(defaultSynologyConfig())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "notification") {
		t.Fatalf("removed notification state is still persisted: %s", data)
	}
	if strings.Contains(string(data), "renewalWindowRatio") {
		t.Fatalf("removed renewal-window override is still persisted: %s", data)
	}
}

func TestRunSynologyTestAndApply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	server := fakeSynologyServer(t)
	u, _ := url.Parse(server.URL)
	host, port, _ := strings.Cut(u.Host, ":")
	cfg.Synology.Scheme = u.Scheme
	cfg.Synology.Host = host
	cfg.Synology.Port = atoiForTest(port)
	cfg.Reconfiguring = true
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	oldManage := manageCertificates
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error {
		return nil
	}
	defer func() { manageCertificates = oldManage }()

	result, err := runSynologyTest(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	assertTaskResultRedacted(t, result)
	if !result.Config.LastTest.Success {
		t.Fatalf("unexpected test result: %+v", result)
	}
	loaded, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.TestPassed() {
		t.Fatalf("persisted config should allow apply after test-run: %+v", loaded.LastTest)
	}
	if loaded.CanRenew() {
		t.Fatal("test-run must not allow background production renewal")
	}

	writeStoredCert(t, cfg.Runtime.StorageDir, cfg.ACME.Domains[0])
	result, err = runSynologyApply(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	assertTaskResultRedacted(t, result)
	if result.State != "ok" {
		t.Fatalf("unexpected apply state: %s", result.State)
	}
	loaded, err = loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.CanRenew() {
		t.Fatalf("persisted config should allow renew after apply: %+v", loaded.LastApply)
	}
	if loaded.Reconfiguring {
		t.Fatal("successful apply must leave reconfiguration mode")
	}
}

func TestRunSynologyTestUsesFreshStagingStorage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	server := fakeSynologyServer(t)
	u, _ := url.Parse(server.URL)
	host, port, _ := strings.Cut(u.Host, ":")
	cfg.Synology.Scheme = u.Scheme
	cfg.Synology.Host = host
	cfg.Synology.Port = atoiForTest(port)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	var storagePaths []string
	oldManage := manageCertificates
	manageCertificates = func(ctx context.Context, magic *certmagic.Config, domains []string) error {
		storage, ok := magic.Storage.(*certmagic.FileStorage)
		if !ok {
			t.Fatalf("unexpected staging storage type: %T", magic.Storage)
		}
		storagePaths = append(storagePaths, storage.Path)
		return nil
	}
	defer func() { manageCertificates = oldManage }()

	for range 2 {
		if _, err := runSynologyTest(context.Background(), path); err != nil {
			t.Fatal(err)
		}
	}
	if len(storagePaths) != 2 {
		t.Fatalf("staging management calls = %d, want 2", len(storagePaths))
	}
	if storagePaths[0] == storagePaths[1] {
		t.Fatalf("test runs reused staging storage: %s", storagePaths[0])
	}
	for _, storagePath := range storagePaths {
		if filepath.Dir(storagePath) != cfg.Runtime.StagingDir {
			t.Fatalf("staging storage %s is outside %s", storagePath, cfg.Runtime.StagingDir)
		}
		if _, err := os.Stat(storagePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary staging storage was not removed: %s", storagePath)
		}
	}
}

func TestCGITestRunAndApplyActions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	server := fakeSynologyServer(t)
	u, _ := url.Parse(server.URL)
	host, port, _ := strings.Cut(u.Host, ":")
	cfg.Synology.Scheme = u.Scheme
	cfg.Synology.Host = host
	cfg.Synology.Port = atoiForTest(port)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	oldManage := manageCertificates
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error {
		return nil
	}
	defer func() { manageCertificates = oldManage }()

	var out bytes.Buffer
	err := serveSynologyCGI(context.Background(), path, queryEnv("action=test-run", http.MethodPost), strings.NewReader("{}"), &out)
	if err != nil {
		t.Fatal(err)
	}
	resp := parseCGIResponse(t, out.String())
	if !resp.Success {
		t.Fatalf("test-run failed: %s", out.String())
	}
	var result synologyTaskResult
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}
	assertTaskResultRedacted(t, result)

	writeStoredCert(t, cfg.Runtime.StorageDir, cfg.ACME.Domains[0])
	out.Reset()
	err = serveSynologyCGI(context.Background(), path, queryEnv("action=apply", http.MethodPost), strings.NewReader("{}"), &out)
	if err != nil {
		t.Fatal(err)
	}
	resp = parseCGIResponse(t, out.String())
	if !resp.Success {
		t.Fatalf("apply failed: %s", out.String())
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}
	assertTaskResultRedacted(t, result)
}

func TestRunSynologyApplyWithoutTest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	setSynologyTestServer(t, &cfg)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	writeStoredCert(t, cfg.Runtime.StorageDir, cfg.ACME.Domains[0])
	oldManage := manageCertificates
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error { return nil }
	defer func() { manageCertificates = oldManage }()

	result, err := runSynologyApply(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "ok" {
		t.Fatalf("unexpected direct apply state: %s", result.State)
	}
	loaded, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TestPassed() {
		t.Fatal("direct apply must not synthesize a staging result")
	}
	if !loaded.CanRenew() {
		t.Fatal("successful direct apply must enable background renewal")
	}
}

func TestFindStoredCertificateWildcard(t *testing.T) {
	dir := t.TempDir()
	writeStoredCert(t, dir, "*.oss.link")

	keyPath, certPath, err := findStoredCertificate(context.Background(), dir, "*.oss.link")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(keyPath, "wildcard_.oss.link.key") {
		t.Fatalf("unexpected wildcard key path: %s", keyPath)
	}
	if !strings.HasSuffix(certPath, "wildcard_.oss.link.crt") {
		t.Fatalf("unexpected wildcard cert path: %s", certPath)
	}
}

func TestRunSynologyTaskFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	setSynologyTestServer(t, &cfg)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	oldManage := manageCertificates
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error {
		return errors.New("acme failed")
	}
	defer func() { manageCertificates = oldManage }()

	if _, err := runSynologyTest(context.Background(), path); err == nil || !strings.Contains(err.Error(), "acme failed") {
		t.Fatalf("expected ACME failure, got %v", err)
	}

	loaded, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LastTest.Success || !strings.Contains(loaded.LastTest.Message, "acme failed") {
		t.Fatalf("failure state was not saved: %+v", loaded.LastTest)
	}

	loaded.LastTest = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: loaded.ConfigHash()}
	if err := saveSynologyConfig(path, loaded); err != nil {
		t.Fatal(err)
	}
	if _, err := runSynologyApply(context.Background(), path); err == nil || !strings.Contains(err.Error(), "acme failed") {
		t.Fatalf("expected production ACME failure, got %v", err)
	}
}

func TestRunSynologyDaemonWaitsForConfigAndRunsValidConfig(t *testing.T) {
	dir := t.TempDir()
	oldRetry := synologyDaemonRetryInterval
	synologyDaemonRetryInterval = time.Millisecond
	defer func() { synologyDaemonRetryInterval = oldRetry }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel()
	if err := runSynologyDaemon(ctx, filepath.Join(dir, "missing.yaml")); err != nil {
		t.Fatalf("daemon should wait for missing config until context cancellation: %v", err)
	}

	cfg := validSynologyConfig(dir)
	path := filepath.Join(dir, "config.yaml")
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	oldManage := manageCertificates
	oldReload := waitForSynologyConfigChange
	manageCalls := 0
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error { return nil }
	waitForSynologyConfigChange = func(ctx context.Context, configPath, activeHash string) bool { return false }
	defer func() {
		manageCertificates = oldManage
		waitForSynologyConfigChange = oldReload
	}()

	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel()
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error {
		manageCalls++
		return nil
	}
	if err := runSynologyDaemon(ctx, path); err != nil {
		t.Fatalf("daemon should wait for passing staging test: %v", err)
	}
	if manageCalls != 0 {
		t.Fatalf("daemon called production ACME before staging test passed: %d", manageCalls)
	}

	cfg.LastTest = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash()}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel()
	if err := runSynologyDaemon(ctx, path); err != nil {
		t.Fatalf("daemon should still wait before apply succeeds: %v", err)
	}
	if manageCalls != 0 {
		t.Fatalf("daemon called production ACME after staging test but before apply: %d", manageCalls)
	}

	cfg.LastApply = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash()}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	if err := runSynologyDaemon(context.Background(), path); err != nil {
		t.Fatalf("daemon should run after apply succeeds: %v", err)
	}
	if manageCalls != 1 {
		t.Fatalf("daemon should call production ACME after apply passed, got %d", manageCalls)
	}
}

func TestRunSynologyDaemonReloadsChangedConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	cfg.LastTest = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash()}
	cfg.LastApply = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash()}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	oldManage := manageCertificates
	oldReload := waitForSynologyConfigChange
	defer func() {
		manageCertificates = oldManage
		waitForSynologyConfigChange = oldReload
	}()

	var managedDomains []string
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error {
		managedDomains = append(managedDomains, domains...)
		return nil
	}
	reloads := 0
	waitForSynologyConfigChange = func(ctx context.Context, configPath, activeHash string) bool {
		reloads++
		if reloads > 1 {
			return false
		}
		next, err := loadSynologyConfig(configPath)
		if err != nil {
			t.Fatal(err)
		}
		next.ACME.Domains = []string{"new.example.com"}
		next.LastTest = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: next.ConfigHash()}
		next.LastApply = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: next.ConfigHash()}
		if err := saveSynologyConfig(configPath, next); err != nil {
			t.Fatal(err)
		}
		return true
	}

	if err := runSynologyDaemon(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(managedDomains, ","); got != "example.com,new.example.com" {
		t.Fatalf("daemon did not reload changed domains: %s", got)
	}
}

func TestMonitorSynologyConfigChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	cfg.LastApply = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash()}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	activeHash := cfg.ConfigHash()

	oldRetry := synologyDaemonRetryInterval
	synologyDaemonRetryInterval = time.Millisecond
	defer func() { synologyDaemonRetryInterval = oldRetry }()

	cfg.ACME.Email = "changed@example.com"
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if !monitorSynologyConfigChange(ctx, path, activeHash) {
		t.Fatal("expected changed config to trigger daemon reload")
	}

	unchanged, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	unchanged.LastApply = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: unchanged.ConfigHash()}
	if err := saveSynologyConfig(path, unchanged); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel()
	if monitorSynologyConfigChange(ctx, path, unchanged.ConfigHash()) {
		t.Fatal("unchanged renewable config should wait until context cancellation")
	}
}

func TestRunSynologyDaemonDeploysRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	imports := 0
	server := fakeSynologyServerWithCerts(t, map[string]string{"DNSACME": "cert-id-1"}, func(fields map[string]string) {
		imports++
		if fields["id"] != "cert-id-1" {
			t.Fatalf("renewal import should update existing certificate id, fields=%+v", fields)
		}
	})
	u, _ := url.Parse(server.URL)
	host, port, _ := strings.Cut(u.Host, ":")

	cfg := validSynologyConfig(dir)
	cfg.Synology.Scheme = u.Scheme
	cfg.Synology.Host = host
	cfg.Synology.Port = atoiForTest(port)
	cfg.LastTest = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash()}
	cfg.LastApply = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash()}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	writeStoredCert(t, cfg.Runtime.StorageDir, cfg.ACME.Domains[0])

	oldManage := manageCertificates
	oldReload := waitForSynologyConfigChange
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error {
		if cfg.OnEvent == nil {
			t.Fatal("expected renewal event hook")
		}
		return cfg.OnEvent(ctx, "cert_obtained", map[string]any{"identifier": domains[0], "renewal": true})
	}
	waitForSynologyConfigChange = func(ctx context.Context, configPath, activeHash string) bool { return false }
	defer func() {
		manageCertificates = oldManage
		waitForSynologyConfigChange = oldReload
	}()

	if err := runSynologyDaemon(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if imports != 1 {
		t.Fatalf("expected one DSM import after renewal event, got %d", imports)
	}
}

func TestSynologyConfigIOFailures(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadSynologyConfig(dir); err == nil {
		t.Fatal("expected directory read error")
	}
	if err := saveSynologyConfig(dir, defaultSynologyConfig()); err == nil {
		t.Fatal("expected directory write error")
	}
}

func TestSynologyApplyValidationAndCertificateLookupFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	cfg.Synology.Password = ""
	cfg.LastTest = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash()}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := runSynologyApply(context.Background(), path); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("expected password validation error, got %v", err)
	}

	cfg = validSynologyConfig(dir)
	setSynologyTestServer(t, &cfg)
	cfg.LastTest = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash()}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	oldManage := manageCertificates
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error { return nil }
	defer func() { manageCertificates = oldManage }()
	if _, err := runSynologyApply(context.Background(), path); err == nil || !strings.Contains(err.Error(), "cert files") {
		t.Fatalf("expected certificate lookup error, got %v", err)
	}

	cfg = validSynologyConfig(dir)
	cfg.Synology.Account = ""
	if err := validateConfigForSynology(cfg, true); err == nil || !strings.Contains(err.Error(), "account") {
		t.Fatalf("expected account validation error, got %v", err)
	}
	cfg.Synology.Account = "admin"
	cfg.Synology.Create = false
	cfg.Synology.CertificateDesc = ""
	if err := validateConfigForSynology(cfg, true); err == nil || !strings.Contains(err.Error(), "description") {
		t.Fatalf("expected description validation error, got %v", err)
	}
	if got := stringsTrim("\n\t value \r"); got != "value" {
		t.Fatalf("unexpected trim result: %q", got)
	}

	cfg = validSynologyConfig(dir)
	cfg.ACME.Domains = []string{"example.com", "*.example.com"}
	if err := validateConfigForSynology(cfg, true); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected multi-domain Synology validation error, got %v", err)
	}
}

func TestSynologyDeployClientAndCertificateSplit(t *testing.T) {
	leaf, chain, err := splitCertificateChain([]byte(testFullChainPEM))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(leaf), "CERTIFICATE") || !strings.Contains(string(chain), "CERTIFICATE") {
		t.Fatalf("unexpected split: leaf=%q chain=%q", leaf, chain)
	}
	if _, _, err := splitCertificateChain([]byte("no pem")); err == nil {
		t.Fatal("expected invalid PEM error")
	}

	server := fakeSynologyServer(t)
	u, _ := url.Parse(server.URL)
	host, port, _ := strings.Cut(u.Host, ":")
	client := newSynologyAPIClient(SynologyDeployConfig{
		Scheme:   u.Scheme,
		Host:     host,
		Port:     atoiForTest(port),
		Account:  "admin",
		Password: "password",
	})
	if err := client.login(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.sid != "sid-1" {
		t.Fatalf("unexpected sid: %s", client.sid)
	}
	if err := client.importCertificate(context.Background(), "DNSACME", true, true, []byte("key"), leaf, chain); err != nil {
		t.Fatal(err)
	}
	if err := client.importCertificate(context.Background(), "missing", false, true, []byte("key"), leaf, chain); err == nil || !strings.Contains(err.Error(), "was not found") {
		t.Fatalf("expected missing existing certificate error, got %v", err)
	}
	if err := client.logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := (synologyAPIError{Code: 100, Text: "bad"}).String(); got != "bad (code 100)" {
		t.Fatalf("unexpected error string: %s", got)
	}
}

func TestDeploySynologyCertificateFromFiles(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "fullchain.pem")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte(testFullChainPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	server := fakeSynologyServer(t)
	u, _ := url.Parse(server.URL)
	host, port, _ := strings.Cut(u.Host, ":")
	err := deploySynologyCertificate(context.Background(), SynologyDeployConfig{
		Scheme:          u.Scheme,
		Host:            host,
		Port:            atoiForTest(port),
		Account:         "admin",
		Password:        "password",
		CertificateDesc: "DNSACME",
		Create:          true,
		AsDefault:       true,
	}, keyPath, certPath)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSynologyDeployClientFailures(t *testing.T) {
	authFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":400,"text":"bad auth"}}`))
	}))
	defer authFail.Close()
	u, _ := url.Parse(authFail.URL)
	host, port, _ := strings.Cut(u.Host, ":")
	client := newSynologyAPIClient(SynologyDeployConfig{Scheme: u.Scheme, Host: host, Port: atoiForTest(port)})
	if err := client.login(context.Background()); err == nil || !strings.Contains(err.Error(), "bad auth") {
		t.Fatalf("expected auth failure, got %v", err)
	}

	importFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webapi/auth.cgi":
			_, _ = w.Write([]byte(`{"success":true,"data":{"sid":"sid-1","synotoken":"token-1"}}`))
		case "/webapi/entry.cgi":
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
				_, _ = w.Write([]byte(`{"success":true,"data":{"certificates":[{"id":"cert-id-1","desc":"DNSACME"}]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":false,"error":{"code":123,"text":"bad import"}}`))
		}
	}))
	defer importFail.Close()
	u, _ = url.Parse(importFail.URL)
	host, port, _ = strings.Cut(u.Host, ":")
	client = newSynologyAPIClient(SynologyDeployConfig{Scheme: u.Scheme, Host: host, Port: atoiForTest(port)})
	if err := client.login(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.importCertificate(context.Background(), "DNSACME", true, false, []byte("key"), []byte("cert"), nil); err == nil || !strings.Contains(err.Error(), "bad import") {
		t.Fatalf("expected import failure, got %v", err)
	}

	if got := (synologyAPIError{}).String(); got != "unknown error" {
		t.Fatalf("unexpected empty error string: %s", got)
	}
	if got := (synologyAPIError{Code: 9}).String(); got != "code 9" {
		t.Fatalf("unexpected code-only error string: %s", got)
	}

	statusFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer statusFail.Close()
	u, _ = url.Parse(statusFail.URL)
	host, port, _ = strings.Cut(u.Host, ":")
	client = newSynologyAPIClient(SynologyDeployConfig{Scheme: u.Scheme, Host: host, Port: atoiForTest(port)})
	var out map[string]any
	if err := client.postForm(context.Background(), "/x", url.Values{}, &out); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("expected HTTP status failure, got %v", err)
	}

	httpsLocal := newSynologyAPIClient(SynologyDeployConfig{Scheme: "https", Host: "127.0.0.1"})
	if httpsLocal.baseURL != "https://127.0.0.1:5001" {
		t.Fatalf("unexpected default HTTPS base URL: %s", httpsLocal.baseURL)
	}
}

func validSynologyConfig(dir string) SynologyConfig {
	cfg := defaultSynologyConfig()
	cfg.ACME.Domains = []string{"example.com"}
	cfg.ACME.Email = "admin@example.com"
	cfg.DNS.Config[provider.CloudflareAPIToken] = "cf-token"
	cfg.Synology.Account = "admin"
	cfg.Synology.Password = "password"
	cfg.Synology.CertificateDesc = "DNSACME"
	cfg.Runtime.StorageDir = filepath.Join(dir, "certmagic")
	cfg.Runtime.StagingDir = filepath.Join(dir, "staging")
	cfg.Runtime.LogPath = filepath.Join(dir, "dnsacme.log")
	return cfg
}

func queryEnv(query, method string, pathInfo ...string) cgiEnv {
	return func(key string) string {
		switch key {
		case "QUERY_STRING":
			return query
		case "REQUEST_METHOD":
			return method
		case "PATH_INFO":
			if len(pathInfo) > 0 {
				return "/" + pathInfo[0]
			}
			return ""
		default:
			return ""
		}
	}
}

type cgiResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   string          `json:"error"`
}

func parseCGIResponse(t *testing.T, raw string) cgiResponse {
	t.Helper()
	_, body, ok := strings.Cut(raw, "\r\n\r\n")
	if !ok {
		t.Fatalf("missing CGI body: %q", raw)
	}
	var resp cgiResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func fakeSynologyServer(t *testing.T) *httptest.Server {
	return fakeSynologyServerWithCerts(t, map[string]string{"DNSACME": "cert-id-1"}, nil)
}

func fakeSynologyServerWithCerts(t *testing.T, certs map[string]string, onImport func(map[string]string)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webapi/auth.cgi":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			switch r.Form.Get("method") {
			case "login":
				if r.Form.Get("enable_syno_token") != "yes" {
					t.Fatalf("login must request SynoToken: %+v", r.Form)
				}
				_, _ = w.Write([]byte(`{"success":true,"data":{"sid":"sid-1","synotoken":"token-1"}}`))
			case "logout":
				_, _ = w.Write([]byte(`{"success":true}`))
			default:
				t.Fatalf("unexpected auth method: %s", r.Form.Get("method"))
			}
		case "/webapi/entry.cgi":
			if r.Header.Get("X-SYNO-TOKEN") != "token-1" {
				t.Fatalf("missing SynoToken header: %q", r.Header.Get("X-SYNO-TOKEN"))
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.Form.Get("api") != "SYNO.Core.Certificate.CRT" || r.Form.Get("method") != "list" {
					t.Fatalf("unexpected form request: %+v", r.Form)
				}
				type certificate struct {
					ID   string `json:"id"`
					Desc string `json:"desc"`
				}
				var certificates []certificate
				for desc, id := range certs {
					certificates = append(certificates, certificate{ID: id, Desc: desc})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"data":    map[string]any{"certificates": certificates},
				})
				return
			}
			q := r.URL.Query()
			if q.Get("api") != "SYNO.Core.Certificate" ||
				q.Get("method") != "import" ||
				q.Get("version") != "1" ||
				q.Get("SynoToken") != "token-1" ||
				q.Get("_sid") != "sid-1" {
				t.Fatalf("unexpected import query: %s", r.URL.RawQuery)
			}
			reader, err := r.MultipartReader()
			if err != nil {
				t.Fatal(err)
			}
			fields := map[string]string{}
			files := map[string]bool{}
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				data, _ := io.ReadAll(part)
				if part.FileName() == "" {
					fields[part.FormName()] = string(data)
				} else {
					files[part.FormName()] = true
				}
			}
			if fields["api"] != "" || fields["method"] != "" || fields["version"] != "" || fields["_sid"] != "" {
				t.Fatalf("import request must keep API fields in query, not multipart body: %+v", fields)
			}
			if fields["create"] != "" {
				t.Fatalf("import request must not send unsupported create field: %+v", fields)
			}
			if fields["desc"] == "" {
				t.Fatalf("missing certificate description: %+v", fields)
			}
			if id, ok := certs[fields["desc"]]; ok && fields["id"] != id {
				t.Fatalf("expected import to reuse certificate id %q for %q, fields=%+v", id, fields["desc"], fields)
			}
			if _, ok := certs[fields["desc"]]; !ok && fields["id"] != "" {
				t.Fatalf("new certificate import should not send id, fields=%+v", fields)
			}
			for _, name := range []string{"key", "cert", "inter_cert"} {
				if !files[name] {
					t.Fatalf("missing multipart file %s: %+v", name, files)
				}
			}
			if onImport != nil {
				onImport(fields)
			}
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func setSynologyTestServer(t *testing.T, cfg *SynologyConfig) {
	t.Helper()
	server := fakeSynologyServer(t)
	u, _ := url.Parse(server.URL)
	host, port, _ := strings.Cut(u.Host, ":")
	cfg.Synology.Scheme = u.Scheme
	cfg.Synology.Host = host
	cfg.Synology.Port = atoiForTest(port)
}

func assertTaskResultRedacted(t *testing.T, result synologyTaskResult) {
	t.Helper()
	if got := result.Config.DNS.Config[provider.CloudflareAPIToken]; got != "********" {
		t.Fatalf("task result leaked DNS token: %q", got)
	}
	if got := result.Config.Synology.Password; got != "********" {
		t.Fatalf("task result leaked DSM password: %q", got)
	}
	if result.Config.LastTest.ConfigHash != "" {
		t.Fatalf("task result leaked LastTest.ConfigHash: %q", result.Config.LastTest.ConfigHash)
	}
	if result.Config.LastApply.ConfigHash != "" {
		t.Fatalf("task result leaked LastApply.ConfigHash: %q", result.Config.LastApply.ConfigHash)
	}
}

func writeStoredCert(t *testing.T, storageDir, domain string) {
	t.Helper()
	storageName := certStorageName(domain)
	dir := filepath.Join(storageDir, "certificates", "example-ca", storageName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, storageName+".key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, storageName+".crt"), []byte(testFullChainPEM), 0o600); err != nil {
		t.Fatal(err)
	}
}

func atoiForTest(s string) int {
	var n int
	for _, ch := range s {
		n = n*10 + int(ch-'0')
	}
	return n
}

const testFullChainPEM = `-----BEGIN CERTIFICATE-----
AQID
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
BAUG
-----END CERTIFICATE-----
`
