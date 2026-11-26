//go:build synology

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mritd/dnsacme/internal/provider"
	"gopkg.in/yaml.v3"
)

// chownFile is a seam so tests can observe the ownership-preserving chown without
// requiring root to actually change a file's owner.
var chownFile = os.Chown

// saveSynologyConfigForMutation is a narrow test seam for simulating a failed
// atomic config write after an external ACME-DNS registration has succeeded.
// Production always uses saveSynologyConfig.
var saveSynologyConfigForMutation = saveSynologyConfig

// preserveFileOwnership chowns dst to match ref's owner, so an atomic-rename write
// keeps the target's original uid/gid and a root-run writer does not strip the
// non-root package user's access to a file it later reads. When ref does not exist
// yet (a first write), it falls back to the owner of ref's containing directory:
// a root-run maintenance command can create config for the first time, and a
// root-owned config would lock the unprivileged package daemon out; inheriting the
// package-owned etc directory keeps it readable. Best
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
	defaultSynologyResolver   = "1.1.1.1"
	// synologyDefaultCredentialName labels the single legacy provider account
	// when the UI or secret merge needs to address it by name.
	synologyDefaultCredentialName = "default"
)

var (
	synologyConfigLockTimeout = 5 * time.Second
	synologyConfigLockRetry   = 25 * time.Millisecond
	errSynologyConfigChanged  = errors.New("configuration changed while operation was running")
)

// SynologyConfig is the persisted package configuration and operation state.
// It contains secrets and must only be exposed through Redacted.
type SynologyConfig struct {
	ACME          SynologyACMEConfig     `json:"acme" yaml:"acme"`
	DNS           SynologyDNSConfig      `json:"dns" yaml:"dns"`
	Synology      SynologyDeployConfig   `json:"synology" yaml:"synology"`
	Runtime       SynologyRuntimeConfig  `json:"runtime" yaml:"runtime"`
	Reconfiguring bool                   `json:"reconfiguring,omitempty" yaml:"reconfiguring,omitempty"`
	LastTest      SynologyOperationState `json:"lastTest,omitempty" yaml:"lastTest,omitempty"`
	LastApply     SynologyOperationState `json:"lastApply,omitempty" yaml:"lastApply,omitempty"`
}

// SynologyACMEConfig contains certificate request inputs owned by the wizard.
type SynologyACMEConfig struct {
	Domains []string `json:"domains" yaml:"domains"`
	Email   string   `json:"email" yaml:"email"`
	KeyType string   `json:"keyType" yaml:"keyType"`
	CA      string   `json:"ca" yaml:"ca"`
}

// SynologyDNSConfig stores the primary provider account and, when several
// accounts are configured, every named account plus the account assigned to
// each certificate identifier. Provider, Config, and Resolvers always mirror
// the first credential so single-account configs keep their original shape.
type SynologyDNSConfig struct {
	Provider    string                  `json:"provider" yaml:"provider"`
	Config      map[string]string       `json:"config" yaml:"config"`
	Resolvers   []string                `json:"resolvers" yaml:"resolvers"`
	Credentials []SynologyDNSCredential `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	Assignments map[string]string       `json:"assignments,omitempty" yaml:"assignments,omitempty"`
}

// SynologyDNSCredential is one named DNS provider account. PreviousName is a
// request-only hint that lets a renamed account keep its redacted secrets.
type SynologyDNSCredential struct {
	Name         string            `json:"name" yaml:"name"`
	Provider     string            `json:"provider" yaml:"provider"`
	Config       map[string]string `json:"config" yaml:"config"`
	Resolvers    []string          `json:"resolvers" yaml:"resolvers"`
	PreviousName string            `json:"previousName,omitempty" yaml:"-"`
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

// defaultSynologyConfig returns safe package defaults without pre-populating any
// user-controlled certificate, account, or credential value.
func defaultSynologyConfig() SynologyConfig {
	return SynologyConfig{
		ACME: SynologyACMEConfig{
			KeyType: "rsa4096",
			CA:      "letsencrypt",
		},
		DNS: SynologyDNSConfig{
			Provider:  provider.Default(),
			Config:    map[string]string{},
			Resolvers: []string{defaultSynologyResolver},
		},
		Synology: SynologyDeployConfig{
			Scheme:          "https",
			Host:            "127.0.0.1",
			Port:            5001,
			CertificateDesc: "DNSACME",
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
	// Keep the config owned by whoever owned it before this write. Without this a
	// root-run maintenance write can make the file root:root 0600, leaving the
	// non-root package daemon unable to read its own config.
	preserveFileOwnership(tmpName, path)
	return os.Rename(tmpName, path)
}

// mutateSynologyConfig serializes a short read-modify-write operation across
// CGI processes. The lock deliberately covers only local config I/O: callers
// must complete any network or ACME work before calling it.
//
// Returning changed=false leaves the latest on-disk configuration untouched.
// This lets long-running tasks discard a result when their starting config has
// been replaced while they were running.
type synologyConfigSnapshot struct {
	Config    SynologyConfig
	EditToken string
	Persisted bool
}

// synologyConfigEditToken identifies a config file without exposing any of its
// contents. It must be called while the short config lock is held whenever the
// returned token is paired with a loaded config or a just-saved mutation.
func synologyConfigEditToken(path string) (string, bool, error) {
	info, err := os.Stat(synologyConfigPath(path))
	if errors.Is(err, os.ErrNotExist) {
		return "missing", false, nil
	}
	if err != nil {
		return "", false, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false, fmt.Errorf("read config file identity: unsupported stat type %T", info.Sys())
	}
	raw := strings.Join([]string{
		"present",
		strconv.FormatUint(uint64(st.Dev), 10),
		strconv.FormatUint(uint64(st.Ino), 10),
		strconv.FormatInt(info.Size(), 10),
		strconv.FormatInt(info.ModTime().UnixNano(), 10),
	}, ":")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:]), true, nil
}

// withSynologyConfigLock holds the bounded cross-process lock for local config
// I/O only. Callers must not perform network, ACME, CertMagic, or DSM work from
// its callback.
func withSynologyConfigLock(path string, fn func() error) error {
	path = synologyConfigPath(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	lockPath := path + ".lock"
	_, statErr := os.Stat(lockPath)
	newLock := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !newLock {
		return statErr
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if newLock {
		// A root-run maintenance command may create the lock first. Match the
		// actual config owner when it exists, otherwise its package-owned directory.
		preserveFileOwnership(lockPath, path)
	}
	if err := lock.Chmod(0o600); err != nil {
		return err
	}
	if err := lockSynologyConfig(lock); err != nil {
		return err
	}
	defer func() { _ = unlockSynologyConfig(lock) }()
	return fn()
}

// loadSynologyConfigSnapshot returns a config and its identity token from the
// same locked file state. It is used by CGI responses and task start snapshots.
func loadSynologyConfigSnapshot(path string) (synologyConfigSnapshot, error) {
	var snapshot synologyConfigSnapshot
	err := withSynologyConfigLock(path, func() error {
		cfg, err := loadSynologyConfig(path)
		if err != nil {
			return err
		}
		token, persisted, err := synologyConfigEditToken(path)
		if err != nil {
			return err
		}
		snapshot = synologyConfigSnapshot{Config: cfg, EditToken: token, Persisted: persisted}
		return nil
	})
	return snapshot, err
}

// mutateSynologyConfig serializes a short read-modify-write operation across
// CGI processes. The returned edit token is collected after save and before the
// same lock is released, so it always belongs to the returned config.
func mutateSynologyConfig(path string, mutate func(*SynologyConfig, string) (changed bool, err error)) (synologyConfigSnapshot, error) {
	var snapshot synologyConfigSnapshot
	err := withSynologyConfigLock(path, func() error {
		cfg, err := loadSynologyConfig(path)
		if err != nil {
			return err
		}
		startingToken, _, err := synologyConfigEditToken(path)
		if err != nil {
			return err
		}
		changed, err := mutate(&cfg, startingToken)
		if err != nil {
			return err
		}
		if changed {
			if err := saveSynologyConfigForMutation(path, cfg); err != nil {
				return err
			}
		}
		token, persisted, err := synologyConfigEditToken(path)
		if err != nil {
			return err
		}
		snapshot = synologyConfigSnapshot{Config: normalizeSynologyConfig(cfg), EditToken: token, Persisted: persisted}
		return nil
	})
	return snapshot, err
}

// lockSynologyConfig uses an advisory kernel lock associated with the open file
// descriptor. The lock file may persist after a process exits or a package is
// upgraded; its existence never means the configuration is locked.
func lockSynologyConfig(lock *os.File) error {
	deadline := time.Now().Add(synologyConfigLockTimeout)
	for {
		err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			if !time.Now().Before(deadline) {
				return fmt.Errorf("acquire config lock: %w", err)
			}
			time.Sleep(synologyConfigLockRetry)
			continue
		}
		return err
	}
}

func unlockSynologyConfig(lock *os.File) error {
	for {
		err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return err
	}
}

// updateSynologyTaskState merges a result from a long-running task only when
// the certificate configuration is still the one the task started with. This
// preserves concurrent form edits and prevents stale task success from opening
// the renewal gate for a newer configuration.
func updateSynologyTaskState(path, startingHash, startingEditToken string, update func(*SynologyConfig)) (synologyConfigSnapshot, bool, error) {
	updated := false
	snapshot, err := mutateSynologyConfig(path, func(cfg *SynologyConfig, currentEditToken string) (bool, error) {
		if cfg.ConfigHash() != startingHash || currentEditToken != startingEditToken {
			return false, nil
		}
		update(cfg)
		updated = true
		return true, nil
	})
	return snapshot, updated, err
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
	cfg.DNS.Resolvers = normalizeSynologyResolvers(cfg.DNS.Resolvers)
	cfg.DNS = normalizeSynologyDNSCredentials(cfg.DNS, cfg.ACME.Domains)
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
	return cfg
}

// normalizeSynologyDNSCredentials mirrors the first credential into the legacy
// fields and assigns every unassigned identifier to it. A lone credential is
// folded back into the legacy single-account shape, so its ConfigHash matches
// configurations written before multiple accounts existed. Unknown assignment
// names are preserved for validateSynologyDNSCredentials to report.
func normalizeSynologyDNSCredentials(dns SynologyDNSConfig, domains []string) SynologyDNSConfig {
	if len(dns.Credentials) == 0 {
		dns.Credentials = nil
		dns.Assignments = nil
		return dns
	}
	credentials := make([]SynologyDNSCredential, 0, len(dns.Credentials))
	for _, credential := range dns.Credentials {
		credential.Name = strings.TrimSpace(credential.Name)
		credential.Provider = strings.ToLower(strings.TrimSpace(credential.Provider))
		credential.Config = cloneStringMap(credential.Config)
		credential.Resolvers = normalizeSynologyResolvers(credential.Resolvers)
		credential.PreviousName = ""
		credentials = append(credentials, credential)
	}
	primary := credentials[0]
	if primary.Provider != "" {
		dns.Provider = primary.Provider
	}
	dns.Config = cloneStringMap(primary.Config)
	dns.Resolvers = append([]string(nil), primary.Resolvers...)
	if len(credentials) == 1 {
		dns.Credentials = nil
		dns.Assignments = nil
		return dns
	}
	assignments := make(map[string]string, len(domains))
	for _, domain := range domains {
		name := strings.TrimSpace(dns.Assignments[domain])
		if name == "" {
			name = primary.Name
		}
		assignments[domain] = name
	}
	dns.Credentials = credentials
	dns.Assignments = assignments
	return dns
}

// EffectiveCredentials lists the configured accounts, presenting a legacy
// single-account config as one credential named "default".
func (dns SynologyDNSConfig) EffectiveCredentials() []SynologyDNSCredential {
	if len(dns.Credentials) > 0 {
		return dns.Credentials
	}
	return []SynologyDNSCredential{{
		Name:      synologyDefaultCredentialName,
		Provider:  dns.Provider,
		Config:    dns.Config,
		Resolvers: dns.Resolvers,
	}}
}

// CredentialFor returns the account assigned to one certificate identifier.
func (dns SynologyDNSConfig) CredentialFor(identifier string) (SynologyDNSCredential, bool) {
	credentials := dns.EffectiveCredentials()
	if len(dns.Credentials) == 0 {
		return credentials[0], true
	}
	name := dns.Assignments[identifier]
	for _, credential := range credentials {
		if credential.Name == name {
			return credential, true
		}
	}
	return SynologyDNSCredential{}, false
}

// validateSynologyDNSCredentials checks the account structure that the UI can
// submit: unique non-empty names, assignments to existing accounts, and one
// account per DNS-01 challenge name, which wildcard and apex names share.
func validateSynologyDNSCredentials(dns SynologyDNSConfig, domains []string) error {
	if len(dns.Credentials) == 0 {
		return nil
	}
	names := make(map[string]struct{}, len(dns.Credentials))
	for _, credential := range dns.Credentials {
		name := strings.TrimSpace(credential.Name)
		if name == "" {
			return errors.New("DNS credential name is empty")
		}
		if !validSynologyCredentialName(name) {
			return fmt.Errorf("invalid DNS credential name: %q", name)
		}
		if _, ok := names[name]; ok {
			return fmt.Errorf("duplicate DNS credential name: %s", name)
		}
		names[name] = struct{}{}
		if strings.TrimSpace(credential.Provider) == "" {
			return fmt.Errorf("DNS credential %s has no provider", name)
		}
	}
	challengeOwners := make(map[string]string, len(domains))
	for _, domain := range domains {
		name := strings.TrimSpace(dns.Assignments[domain])
		if name == "" {
			name = strings.TrimSpace(dns.Credentials[0].Name)
		}
		if _, ok := names[name]; !ok {
			return fmt.Errorf("domain %s is assigned to unknown DNS credential %s", domain, name)
		}
		key := dnsRouteKey(domain)
		if owner, ok := challengeOwners[key]; ok && owner != name {
			return fmt.Errorf("domains sharing the _acme-challenge.%s record must use the same DNS credential", key)
		}
		challengeOwners[key] = name
	}
	return nil
}

// validSynologyCredentialName limits names to a plain charset because the UI
// shows them in controls that render their text as HTML.
func validSynologyCredentialName(name string) bool {
	if len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
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

func normalizeSynologyResolvers(resolvers []string) []string {
	result := make([]string, 0, len(resolvers))
	seen := make(map[string]struct{}, len(resolvers))
	for _, resolver := range resolvers {
		resolver = strings.TrimSpace(resolver)
		if resolver == "" {
			continue
		}
		if _, ok := seen[resolver]; ok {
			continue
		}
		seen[resolver] = struct{}{}
		result = append(result, resolver)
	}
	if len(result) == 0 {
		return []string{defaultSynologyResolver}
	}
	return result
}

func validateSynologyResolvers(resolvers []string) error {
	for _, resolver := range normalizeSynologyResolvers(resolvers) {
		if net.ParseIP(resolver) != nil {
			continue
		}
		host, port, err := net.SplitHostPort(resolver)
		if err != nil || net.ParseIP(host) == nil {
			return fmt.Errorf("invalid recursive DNS resolver: %s", resolver)
		}
		for _, char := range port {
			if char < '0' || char > '9' {
				return fmt.Errorf("invalid recursive DNS resolver port: %s", resolver)
			}
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return fmt.Errorf("invalid recursive DNS resolver port: %s", resolver)
		}
	}
	return nil
}

// RuntimeConfig converts package configuration into a CertMagic runtime. Staging
// always uses Let's Encrypt's test CA and a package-owned storage root; each UI
// test run selects a fresh child directory so it cannot reuse a prior certificate.
func (cfg SynologyConfig) RuntimeConfig(staging bool) Config {
	cfg = normalizeSynologyConfig(cfg)
	runtime := Config{
		Domains:     append([]string(nil), cfg.ACME.Domains...),
		Email:       cfg.ACME.Email,
		KeyType:     cfg.ACME.KeyType,
		DNSProvider: cfg.DNS.Provider,
		DNSConfig:   cloneStringMap(cfg.DNS.Config),
		ZeroSSLCA:   strings.EqualFold(cfg.ACME.CA, "zerossl"),
	}
	if cfg.DNS.Provider == provider.AcmeDNS {
		runtime.DNSResolvers = append([]string(nil), cfg.DNS.Resolvers...)
	}
	if len(cfg.DNS.Credentials) > 0 {
		runtime.DNSRoutes = make(map[string]DNSRoute, len(cfg.ACME.Domains))
		for _, domain := range cfg.ACME.Domains {
			credential, ok := cfg.DNS.CredentialFor(domain)
			if !ok {
				continue
			}
			route := DNSRoute{Provider: credential.Provider, Config: cloneStringMap(credential.Config)}
			if credential.Provider == provider.AcmeDNS {
				route.Resolvers = append([]string(nil), credential.Resolvers...)
			}
			runtime.DNSRoutes[domain] = route
		}
	}
	// Staging always uses its own storage root so its untrusted certificate can
	// never be confused with the production one by the suffix-matching certificate
	// lookup in hookEnv. Apply and background renewal always use the selected
	// production CA.
	if staging {
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

// ConfigHash fingerprints normalized certificate and deployment inputs, including
// credentials and runtime paths. Operational recursive resolvers are excluded so
// changing how propagation is observed does not close the successful-apply gate.
// It is an internal state identity and must stay redacted; UI reconfiguration
// state, operation timestamps, and messages are excluded.
func (cfg SynologyConfig) ConfigHash() string {
	cfg = normalizeSynologyConfig(cfg)
	shape := struct {
		ACME struct {
			Domains []string `json:"domains"`
			Email   string   `json:"email"`
			KeyType string   `json:"keyType"`
			CA      string   `json:"ca"`
		} `json:"acme"`
		DNS struct {
			Provider string            `json:"provider"`
			Config   map[string]string `json:"config"`
			// Multi-account fields are omitted for single-account configs so their
			// hash keeps the shape used before multiple accounts existed.
			Credentials []hashedCredential `json:"credentials,omitempty"`
			Assignments map[string]string  `json:"assignments,omitempty"`
		} `json:"dns"`
		Synology           SynologyDeployConfig  `json:"synology"`
		Runtime            SynologyRuntimeConfig `json:"runtime"`
		LegacyForceStaging bool                  `json:"forceStaging"`
	}{
		Synology: cfg.Synology,
		Runtime:  cfg.Runtime,
		// Preserve the old production hash shape so ordinary package upgrades do
		// not suspend renewal. This slot is permanently false: a legacy config that
		// used staging had a true hash and is intentionally forced to re-apply a
		// trusted production certificate.
		LegacyForceStaging: false,
	}
	shape.ACME.Domains = cfg.ACME.Domains
	shape.ACME.Email = cfg.ACME.Email
	shape.ACME.KeyType = cfg.ACME.KeyType
	shape.ACME.CA = cfg.ACME.CA
	shape.DNS.Provider = cfg.DNS.Provider
	shape.DNS.Config = cfg.DNS.Config
	for _, credential := range cfg.DNS.Credentials {
		shape.DNS.Credentials = append(shape.DNS.Credentials, hashedCredential{
			Name:     credential.Name,
			Provider: credential.Provider,
			Config:   credential.Config,
		})
	}
	shape.DNS.Assignments = cfg.DNS.Assignments
	data, _ := json.Marshal(shape)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// hashedCredential is the ConfigHash view of one DNS account; resolvers are
// operational and excluded, as they are for the primary account.
type hashedCredential struct {
	Name     string            `json:"name"`
	Provider string            `json:"provider"`
	Config   map[string]string `json:"config"`
}

// RenewalRuntimeKey identifies the CertMagic manager inputs that must trigger a
// live daemon reload. Resolver changes are operational and deliberately remain
// outside ConfigHash so they do not close the successful-apply renewal gate.
func (cfg SynologyConfig) RenewalRuntimeKey() string {
	cfg = normalizeSynologyConfig(cfg)
	shape := struct {
		ConfigHash          string              `json:"configHash"`
		Resolvers           []string            `json:"resolvers"`
		CredentialResolvers map[string][]string `json:"credentialResolvers,omitempty"`
	}{ConfigHash: cfg.ConfigHash()}
	if cfg.DNS.Provider == provider.AcmeDNS {
		shape.Resolvers = cfg.DNS.Resolvers
	}
	for _, credential := range cfg.DNS.Credentials {
		if credential.Provider != provider.AcmeDNS {
			continue
		}
		if shape.CredentialResolvers == nil {
			shape.CredentialResolvers = map[string][]string{}
		}
		shape.CredentialResolvers[credential.Name] = credential.Resolvers
	}
	data, _ := json.Marshal(shape)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestPassed reports whether this exact configuration passed the optional
// staging diagnostic. It is presentation state only: production Apply validates
// its inputs independently and is never gated by a staging result.
func (cfg SynologyConfig) TestPassed() bool {
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
	cfg.DNS.Config = redactProviderConfig(cfg.DNS.Config)
	credentials := make([]SynologyDNSCredential, 0, len(cfg.DNS.Credentials))
	for _, credential := range cfg.DNS.Credentials {
		credential.Config = redactProviderConfig(credential.Config)
		credential.Resolvers = append([]string(nil), credential.Resolvers...)
		credentials = append(credentials, credential)
	}
	if len(credentials) > 0 {
		cfg.DNS.Credentials = credentials
	}
	if cfg.Synology.Password != "" {
		cfg.Synology.Password = "********"
	}
	cfg.LastTest.ConfigHash = ""
	cfg.LastApply.ConfigHash = ""
	return cfg
}

func redactProviderConfig(config map[string]string) map[string]string {
	config = cloneStringMap(config)
	for key := range config {
		if isSecretProviderKey(key) && config[key] != "" {
			config[key] = "********"
		}
	}
	return config
}

// mergeSecrets reverses API redaction during a form save. Present masked or blank
// required/secret fields preserve an existing value, while optional non-secret
// blanks clear normally. Omitted keys remain omitted.
func mergeSecrets(next, current SynologyConfig) SynologyConfig {
	mergeProviderSecrets(next.DNS.Config, current.DNS.Config)
	// Named accounts match their persisted counterpart by the name the browser
	// loaded, so renaming an account keeps its redacted secrets.
	currentCredentials := current.DNS.EffectiveCredentials()
	for i := range next.DNS.Credentials {
		credential := &next.DNS.Credentials[i]
		name := credential.PreviousName
		if name == "" {
			name = credential.Name
		}
		var persisted map[string]string
		for _, candidate := range currentCredentials {
			if candidate.Name == name {
				persisted = candidate.Config
				break
			}
		}
		// A lone credential is stored in the legacy shape under the name
		// "default", so the browser may still address it by its own name. The
		// first credential always mirrors the persisted primary account.
		if persisted == nil && i == 0 {
			persisted = current.DNS.Config
		}
		if credential.Config == nil {
			credential.Config = map[string]string{}
		}
		mergeProviderSecrets(credential.Config, persisted)
	}
	if next.Synology.Password == "********" {
		next.Synology.Password = current.Synology.Password
	} else if next.Synology.Password == "" && current.Synology.Password != "" {
		next.Synology.Password = current.Synology.Password
	}
	return next
}

// mergeProviderSecrets applies the mergeSecrets rules to one provider config.
func mergeProviderSecrets(next, current map[string]string) {
	for key, value := range next {
		if value == "********" {
			// A sentinel is never a credential. Restore an existing value or clear it
			// on first configuration so validation reports the missing secret.
			next[key] = current[key]
			continue
		}
		if value == "" && current[key] != "" && (isSecretProviderKey(key) || isRequiredProviderKey(key)) {
			next[key] = current[key]
		}
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func isSecretProviderKey(key string) bool {
	if field, ok := provider.FieldByKey(key); ok {
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
	if field, ok := provider.FieldByKey(key); ok {
		return field.Required
	}
	return false
}
