package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"gopkg.in/yaml.v3"
)

// chownFile is a seam so tests can observe the ownership-preserving chown without
// requiring root to actually change a file's owner.
var chownFile = os.Chown

// preserveFileOwnership chowns dst to match ref's owner, so an atomic-rename write
// keeps the target's original uid/gid and a root-run writer does not strip the
// non-root package user's access to a file it later reads. When ref does not exist
// yet (a first write), it falls back to the owner of ref's containing directory:
// the one-time publish-notifications command runs as root and can create config for
// the first time, and a root-owned config would lock the unprivileged package
// daemon out; inheriting the package-owned etc directory keeps it readable. Best
// effort: a same-owner chown is a no-op, and any failure leaves the write intact.
func preserveFileOwnership(dst, ref string) {
	info, err := os.Stat(ref)
	if errors.Is(err, os.ErrNotExist) {
		info, err = os.Stat(filepath.Dir(ref))
	}
	if err != nil {
		return
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	_ = chownFile(dst, int(st.Uid), int(st.Gid))
}

const (
	defaultSynologyConfigPath = "/var/packages/dnsacme/etc/config.yaml"
	defaultSynologyLogPath    = "/var/packages/dnsacme/var/dnsacme.log"
)

// SynologyConfig is the persisted package configuration and operation state.
// It contains secrets and must only be exposed through Redacted.
type SynologyConfig struct {
	ACME     SynologyACMEConfig    `json:"acme" yaml:"acme"`
	DNS      SynologyDNSConfig     `json:"dns" yaml:"dns"`
	Synology SynologyDeployConfig  `json:"synology" yaml:"synology"`
	Runtime  SynologyRuntimeConfig `json:"runtime" yaml:"runtime"`
	// RenewalWindowRatio tunes how early background renewal fires (remaining:total
	// lifetime, 0 = CertMagic default 1/3). It is deliberately a top-level field so
	// it stays outside ConfigHash: changing only the window must not invalidate the
	// staged-test/apply authorization the way certificate-identity inputs do. The
	// daemon still reloads on change through renewalReloadKey.
	RenewalWindowRatio float64 `json:"renewalWindowRatio,omitempty" yaml:"renewalWindowRatio,omitempty"`
	// ForceStaging routes the production apply and renewal daemon through Let's
	// Encrypt's staging CA and its separate storage root. It exists so a renewal
	// test (usually paired with a high RenewalWindowRatio) can loop on staging's
	// vastly higher rate limits instead of the 5-per-week production duplicate
	// limit; the resulting certificate is untrusted, so DSM shows it as invalid
	// until a production certificate is reapplied. Unlike RenewalWindowRatio, this
	// changes which CA and storage are deployed, so it is part of ConfigHash: a
	// toggle must revoke the previous test/apply authorization before the daemon
	// can import a certificate from the newly selected CA.
	ForceStaging bool `json:"forceStaging,omitempty" yaml:"forceStaging,omitempty"`
	// NotificationsEnabled turns DSM system notifications for certificate deploy and
	// renewal events on. Publishing the localized text catalog into the root-owned
	// /var/cache/texts needs root, but only once: the user runs a one-time
	// `synology publish-notifications` command over SSH (the daemon and CGI always
	// run as the package user), which publishes the catalog and sets this flag. Once
	// published the catalog is persistent, so later toggles are plain non-root config
	// flips. It is top-level and kept out of ConfigHash (it never affects certificate
	// issuance or the test/apply authorization) but folded into renewalReloadKey so a
	// toggle reloads the daemon and its renewal deploy hook observes the change
	// instead of sending with a stale captured value. The reload is driven by a poll,
	// so a renewal landing within one poll interval of the toggle can still miss
	// (enable) or rely on the live present() check (disable); the worst case is a
	// single skipped notification, never a wrong-state send.
	NotificationsEnabled bool                   `json:"notificationsEnabled,omitempty" yaml:"notificationsEnabled,omitempty"`
	Reconfiguring        bool                   `json:"reconfiguring,omitempty" yaml:"reconfiguring,omitempty"`
	LastTest             SynologyOperationState `json:"lastTest,omitempty" yaml:"lastTest,omitempty"`
	LastApply            SynologyOperationState `json:"lastApply,omitempty" yaml:"lastApply,omitempty"`
}

// SynologyACMEConfig contains certificate request inputs owned by the wizard.
type SynologyACMEConfig struct {
	Domains []string `json:"domains" yaml:"domains"`
	Email   string   `json:"email" yaml:"email"`
	KeyType string   `json:"keyType" yaml:"keyType"`
	CA      string   `json:"ca" yaml:"ca"`
}

// SynologyDNSConfig stores one provider name and its provider-specific values.
type SynologyDNSConfig struct {
	Provider string            `json:"provider" yaml:"provider"`
	Config   map[string]string `json:"config" yaml:"config"`
}

// SynologyDeployConfig identifies a DSM API endpoint and import behavior. HTTP
// transports the DSM password in cleartext and should be limited to loopback.
type SynologyDeployConfig struct {
	Scheme          string `json:"scheme" yaml:"scheme"`
	Host            string `json:"host" yaml:"host"`
	Port            int    `json:"port" yaml:"port"`
	Account         string `json:"account" yaml:"account"`
	Password        string `json:"password,omitempty" yaml:"password,omitempty"`
	CertificateDesc string `json:"certificateDesc" yaml:"certificateDesc"`
	Create          bool   `json:"create" yaml:"create"`
	AsDefault       bool   `json:"asDefault" yaml:"asDefault"`
}

// SynologyRuntimeConfig keeps production, staging, and UI log data separated.
type SynologyRuntimeConfig struct {
	StorageDir string `json:"storageDir" yaml:"storageDir"`
	StagingDir string `json:"stagingDir" yaml:"stagingDir"`
	LogPath    string `json:"logPath" yaml:"logPath"`
}

// SynologyOperationState binds a test or apply result to the exact config hash
// that produced it, preventing stale success from authorizing later work.
type SynologyOperationState struct {
	Success    bool      `json:"success" yaml:"success"`
	At         time.Time `json:"at" yaml:"at"`
	ConfigHash string    `json:"configHash" yaml:"configHash"`
	Message    string    `json:"message,omitempty" yaml:"message,omitempty"`
}

// ProviderField describes one dynamic DNS credential field for the DSM UI.
type ProviderField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Secret      bool   `json:"secret"`
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder,omitempty"`
}

// ProviderMetadata is the UI and validation schema for a supported provider.
type ProviderMetadata struct {
	Name   string          `json:"name"`
	Label  string          `json:"label"`
	Fields []ProviderField `json:"fields"`
}

// defaultSynologyConfig returns safe package defaults without pre-populating any
// user-controlled certificate, account, or credential value.
func defaultSynologyConfig() SynologyConfig {
	return SynologyConfig{
		ACME: SynologyACMEConfig{
			KeyType: "rsa4096",
			CA:      "letsencrypt",
		},
		DNS: SynologyDNSConfig{
			Provider: DNS_PROVIDER_CLOUDFLARE,
			Config:   map[string]string{},
		},
		Synology: SynologyDeployConfig{
			Scheme:          "https",
			Host:            "127.0.0.1",
			Port:            5001,
			CertificateDesc: "dnsacme",
			Create:          true,
			AsDefault:       true,
		},
		Runtime: SynologyRuntimeConfig{
			StorageDir: "/var/packages/dnsacme/var/certmagic",
			StagingDir: "/var/packages/dnsacme/var/staging",
			LogPath:    defaultSynologyLogPath,
		},
	}
}

// synologyConfigPath resolves explicit CLI input before the package environment
// and finally the DSM package default.
func synologyConfigPath(path string) string {
	if path != "" {
		return path
	}
	if env := os.Getenv("DNSACME_CONFIG"); env != "" {
		return env
	}
	return defaultSynologyConfigPath
}

// loadSynologyConfig treats a missing file as first-run state but reports all
// other read and parse errors so the daemon does not silently reset config.
func loadSynologyConfig(path string) (SynologyConfig, error) {
	path = synologyConfigPath(path)
	cfg := defaultSynologyConfig()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return normalizeSynologyConfig(cfg), nil
}

// saveSynologyConfig creates new directories and YAML files with restrictive
// modes because DNS and DSM credentials are stored for the package process.
func saveSynologyConfig(path string, cfg SynologyConfig) error {
	path = synologyConfigPath(path)
	cfg = normalizeSynologyConfig(cfg)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	// Write a temp file in the same directory and atomically rename it over the
	// target. A concurrent reader then always sees either the old or the new
	// complete file, never a half-written one, and two overlapping writers cannot
	// leave a truncated config behind. The temp file is created 0600 because it
	// holds DNS and DSM credentials.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.yaml.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup; a no-op once the rename below has consumed the temp file.
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Keep the config owned by whoever owned it before this write. The notifications
	// action publishes as root and therefore saves config as root; without this a
	// root-written config becomes root:root 0600 and the non-root package daemon
	// (the default run-as, and what an upgrade resets to) can no longer read its own
	// config. Preserving the existing owner keeps a root writer from locking it out.
	preserveFileOwnership(tmpName, path)
	return os.Rename(tmpName, path)
}

// normalizeSynologyConfig applies backward-compatible defaults at every ingress
// so file, CGI, and daemon callers share the same canonical representation.
func normalizeSynologyConfig(cfg SynologyConfig) SynologyConfig {
	def := defaultSynologyConfig()
	cfg.ACME.Domains = normalizeDomains(cfg.ACME.Domains)
	if cfg.ACME.KeyType == "" {
		cfg.ACME.KeyType = def.ACME.KeyType
	}
	cfg.ACME.KeyType = normalizeSynologyKeyType(cfg.ACME.KeyType)
	if cfg.ACME.CA == "" {
		cfg.ACME.CA = def.ACME.CA
	}
	if cfg.DNS.Provider == "" {
		cfg.DNS.Provider = def.DNS.Provider
	}
	cfg.DNS.Provider = strings.ToLower(cfg.DNS.Provider)
	if cfg.DNS.Config == nil {
		cfg.DNS.Config = map[string]string{}
	}
	if cfg.Synology.Scheme == "" {
		cfg.Synology.Scheme = def.Synology.Scheme
	}
	cfg.Synology.Scheme = strings.ToLower(cfg.Synology.Scheme)
	if cfg.Synology.Host == "" {
		cfg.Synology.Host = def.Synology.Host
	}
	if cfg.Synology.Port == 0 {
		cfg.Synology.Port = def.Synology.Port
	}
	if cfg.Synology.CertificateDesc == "" {
		cfg.Synology.CertificateDesc = def.Synology.CertificateDesc
	}
	if cfg.Runtime.StorageDir == "" {
		cfg.Runtime.StorageDir = def.Runtime.StorageDir
	}
	if cfg.Runtime.StagingDir == "" {
		cfg.Runtime.StagingDir = def.Runtime.StagingDir
	}
	if cfg.Runtime.LogPath == "" {
		cfg.Runtime.LogPath = def.Runtime.LogPath
	}
	// An out-of-range ratio (hand-edited YAML or a raw CGI post) is normalized to
	// "unset" so persisted config, the UI, the reload key, and the daemon all agree
	// on the effective default instead of silently diverging. The negated range
	// form also catches NaN (every NaN comparison is false), which would otherwise
	// poison the JSON marshaling of config responses.
	if !(cfg.RenewalWindowRatio >= 0 && cfg.RenewalWindowRatio <= 1) {
		cfg.RenewalWindowRatio = 0
	}
	return cfg
}

// normalizeSynologyKeyType keeps file and API input aligned with the wizard's
// validated RSA-only contract; unsupported or legacy values fall back to 4096.
func normalizeSynologyKeyType(keyType string) string {
	switch normalizeKeyType(keyType) {
	case "rsa2048", "rsa4096":
		return normalizeKeyType(keyType)
	default:
		return defaultSynologyConfig().ACME.KeyType
	}
}

func normalizeDomains(domains []string) []string {
	result := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	return result
}

// RuntimeConfig converts package configuration into a CertMagic runtime. Staging
// always uses Let's Encrypt's test CA and a package-owned storage root; each UI
// test run selects a fresh child directory so it cannot reuse a prior certificate.
func (cfg SynologyConfig) RuntimeConfig(staging bool) Config {
	cfg = normalizeSynologyConfig(cfg)
	runtime := Config{
		Domains:            append([]string(nil), cfg.ACME.Domains...),
		Email:              cfg.ACME.Email,
		KeyType:            cfg.ACME.KeyType,
		DNSProvider:        cfg.DNS.Provider,
		DNSConfig:          cloneStringMap(cfg.DNS.Config),
		ZeroSSLCA:          strings.EqualFold(cfg.ACME.CA, "zerossl"),
		RenewalWindowRatio: cfg.RenewalWindowRatio,
	}
	// ForceStaging makes the "production" runtime behave like staging: the huge
	// staging rate limits let a renewal test loop freely. Staging always uses its
	// own storage root so its untrusted certificate can never be confused with the
	// production one by the suffix-matching certificate lookup in hookEnv.
	if staging || cfg.ForceStaging {
		runtime.StorageDir = cfg.Runtime.StagingDir
		runtime.ZeroSSLCA = false
		runtime.CA = certmagic.LetsEncryptStagingCA
	} else {
		runtime.StorageDir = cfg.Runtime.StorageDir
		switch strings.ToLower(cfg.ACME.CA) {
		case "", "letsencrypt":
			runtime.ZeroSSLCA = false
			runtime.CA = certmagic.LetsEncryptProductionCA
		case "zerossl":
			runtime.ZeroSSLCA = true
		default:
			runtime.ZeroSSLCA = false
			runtime.CA = cfg.ACME.CA
		}
	}
	return runtime
}

// ConfigHash fingerprints all normalized certificate inputs, including credentials
// and runtime paths. It is an internal authorization token and must stay redacted;
// UI reconfiguration state, operation timestamps, and messages are excluded.
func (cfg SynologyConfig) ConfigHash() string {
	cfg = normalizeSynologyConfig(cfg)
	shape := struct {
		ACME         SynologyACMEConfig    `json:"acme"`
		DNS          SynologyDNSConfig     `json:"dns"`
		Synology     SynologyDeployConfig  `json:"synology"`
		Runtime      SynologyRuntimeConfig `json:"runtime"`
		ForceStaging bool                  `json:"forceStaging"`
	}{
		ACME:         cfg.ACME,
		DNS:          cfg.DNS,
		Synology:     cfg.Synology,
		Runtime:      cfg.Runtime,
		ForceStaging: cfg.ForceStaging,
	}
	data, _ := json.Marshal(shape)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// renewalReloadKey fingerprints everything the renewal daemon must restart to
// apply. RenewalWindowRatio sits outside ConfigHash on purpose (tuning it must
// not revoke test/apply authorization), but the running CertMagic manager bakes
// the ratio in at start, so ratio changes still have to trigger a reload.
// NotificationsEnabled is likewise outside ConfigHash, but the daemon captures it
// in the renewal deploy hook's cfg, so a toggle must reload the daemon or an
// already-running hook would keep sending (or suppressing) with stale intent.
func renewalReloadKey(cfg SynologyConfig) string {
	return cfg.ConfigHash() +
		"|ratio=" + strconv.FormatFloat(cfg.RenewalWindowRatio, 'g', -1, 64) +
		"|notify=" + strconv.FormatBool(cfg.NotificationsEnabled)
}

// CanApply allows production issuance only after this exact configuration has
// passed staging validation.
func (cfg SynologyConfig) CanApply() bool {
	cfg = normalizeSynologyConfig(cfg)
	return cfg.LastTest.Success && cfg.LastTest.ConfigHash == cfg.ConfigHash()
}

// CanRenew allows background renewal only after this exact configuration was
// successfully imported into DSM.
func (cfg SynologyConfig) CanRenew() bool {
	cfg = normalizeSynologyConfig(cfg)
	return cfg.LastApply.Success && cfg.LastApply.ConfigHash == cfg.ConfigHash()
}

// Redacted returns a deep-enough copy for API responses, replacing credentials
// with a stable sentinel and removing internal authorization hashes.
func (cfg SynologyConfig) Redacted() SynologyConfig {
	cfg = normalizeSynologyConfig(cfg)
	cfg.DNS.Config = cloneStringMap(cfg.DNS.Config)
	for key := range cfg.DNS.Config {
		if isSecretProviderKey(key) && cfg.DNS.Config[key] != "" {
			cfg.DNS.Config[key] = "********"
		}
	}
	if cfg.Synology.Password != "" {
		cfg.Synology.Password = "********"
	}
	cfg.LastTest.ConfigHash = ""
	cfg.LastApply.ConfigHash = ""
	return cfg
}

// mergeSecrets reverses API redaction during a form save. Present masked or blank
// required/secret fields preserve an existing value, while optional non-secret
// blanks clear normally. Omitted keys remain omitted.
func mergeSecrets(next, current SynologyConfig) SynologyConfig {
	for key, value := range next.DNS.Config {
		if value == "********" {
			// A sentinel is never a credential. Restore an existing value or clear it
			// on first configuration so validation reports the missing secret.
			next.DNS.Config[key] = current.DNS.Config[key]
			continue
		}
		if value == "" && current.DNS.Config[key] != "" && (isSecretProviderKey(key) || isRequiredProviderKey(key)) {
			next.DNS.Config[key] = current.DNS.Config[key]
		}
	}
	if next.Synology.Password == "********" {
		next.Synology.Password = current.Synology.Password
	} else if next.Synology.Password == "" && current.Synology.Password != "" {
		next.Synology.Password = current.Synology.Password
	}
	return next
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func isSecretProviderKey(key string) bool {
	if field, ok := providerFieldByKey(key); ok {
		return field.Secret
	}
	// Unknown provider fields still receive conservative name-based redaction.
	key = strings.ToLower(key)
	return strings.Contains(key, "token") ||
		strings.Contains(key, "secret") ||
		strings.Contains(key, "key") ||
		strings.Contains(key, "passwd") ||
		strings.Contains(key, "password")
}

func isRequiredProviderKey(key string) bool {
	if field, ok := providerFieldByKey(key); ok {
		return field.Required
	}
	return false
}

func providerFieldByKey(key string) (ProviderField, bool) {
	for _, provider := range providerMetadata() {
		for _, field := range provider.Fields {
			if field.Key == key {
				return field, true
			}
		}
	}
	return ProviderField{}, false
}

// providerMetadata is the manually maintained schema shared by rendering,
// required-value handling, and redaction. Keep keys synchronized with consts.go;
// Cloudflare stays first because the UI uses the first item as its fallback.
func providerMetadata() []ProviderMetadata {
	items := []ProviderMetadata{
		{Name: DNS_PROVIDER_CLOUDFLARE, Label: "Cloudflare", Fields: []ProviderField{
			{Key: ENV_CLOUDFLARE_API_TOKEN, Label: "API Token", Secret: true, Required: true, Placeholder: "Zone DNS edit token"},
		}},
		{Name: DNS_PROVIDER_ALIDNS, Label: "AliDNS", Fields: []ProviderField{
			{Key: ENV_ALIDNS_ACCKEYID, Label: "AccessKey ID", Required: true, Placeholder: "LTAI..."},
			{Key: ENV_ALIDNS_ACCKEYSECRET, Label: "AccessKey Secret", Secret: true, Required: true},
			{Key: ENV_ALIDNS_REGIONID, Label: "Region ID", Placeholder: "cn-hangzhou"},
		}},
		{Name: DNS_PROVIDER_AZURE, Label: "Azure DNS", Fields: []ProviderField{
			{Key: ENV_AZURE_TENANTID, Label: "Tenant ID", Required: true},
			{Key: ENV_AZURE_CLIENTID, Label: "Client ID", Required: true},
			{Key: ENV_AZURE_CLIENTSECRET, Label: "Client Secret", Secret: true, Required: true},
			{Key: ENV_AZURE_SUBSCRIPTIONID, Label: "Subscription ID", Required: true},
			{Key: ENV_AZURE_RESOURCEGROUPNAME, Label: "Resource Group", Required: true},
		}},
		{Name: DNS_PROVIDER_DUCKDNS, Label: "Duck DNS", Fields: []ProviderField{
			{Key: ENV_DUCKDNS_API_TOKEN, Label: "API Token", Secret: true, Required: true, Placeholder: "duckdns token"},
			{Key: ENV_DUCKDNS_OVERRIDE_DOMAIN, Label: "Override Domain"},
		}},
		{Name: DNS_PROVIDER_GANDI, Label: "Gandi", Fields: []ProviderField{
			{Key: ENV_GANDI_API_TOKEN, Label: "API Token", Secret: true, Required: true, Placeholder: "Personal Access Token"},
		}},
		{Name: DNS_PROVIDER_GODADDY, Label: "GoDaddy", Fields: []ProviderField{
			{Key: ENV_GODADDY_API_TOKEN, Label: "API Token", Secret: true, Required: true, Placeholder: "key:secret"},
		}},
		{Name: DNS_PROVIDER_HUAWEICLOUD, Label: "Huawei Cloud DNS", Fields: []ProviderField{
			{Key: ENV_HUAWEICLOUD_ACCKEYID, Label: "AccessKey ID", Required: true, Placeholder: "access key id"},
			{Key: ENV_HUAWEICLOUD_ACCKEYSECRET, Label: "Secret AccessKey", Secret: true, Required: true},
			{Key: ENV_HUAWEICLOUD_REGIONID, Label: "Region ID", Placeholder: "cn-south-1"},
		}},
		{Name: DNS_PROVIDER_TENCENTCLOUD, Label: "Tencent Cloud DNS", Fields: []ProviderField{
			{Key: ENV_TENCENTCLOUD_ACCKEYID, Label: "Secret ID", Required: true, Placeholder: "AKID..."},
			{Key: ENV_TENCENTCLOUD_ACCKEYSECRET, Label: "Secret Key", Secret: true, Required: true},
		}},
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name == DNS_PROVIDER_CLOUDFLARE {
			return true
		}
		if items[j].Name == DNS_PROVIDER_CLOUDFLARE {
			return false
		}
		return items[i].Name < items[j].Name
	})
	return items
}
