//go:build synology

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/sirupsen/logrus"
)

type synologyTaskResult struct {
	Config SynologyConfig `json:"config"`
	State  string         `json:"state"`
}

func newSynologyTaskResult(cfg SynologyConfig, state string) synologyTaskResult {
	// Task results cross the CGI boundary, so never return the persisted secrets.
	return synologyTaskResult{Config: cfg.Redacted(), State: state}
}

// runSynologyTest verifies DSM authentication and obtains from staging storage.
// It records success for the current config hash but never starts production
// renewal or imports the staging certificate into DSM.
func runSynologyTest(ctx context.Context, configPath string) (synologyTaskResult, error) {
	cfg, err := loadSynologyConfig(configPath)
	if err != nil {
		return synologyTaskResult{}, err
	}
	cfg = normalizeSynologyConfig(cfg)
	configureSynologyLog(cfg)
	if err := validateConfigForSynology(cfg, true); err != nil {
		cfg.LastTest = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: err.Error()}
		_ = saveSynologyConfig(configPath, cfg)
		return newSynologyTaskResult(cfg, "failed"), err
	}

	appendSynologyLog(cfg, "checking DSM login")
	if err := verifySynologyLogin(ctx, cfg.Synology); err != nil {
		cfg.LastTest = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: "DSM login failed: " + err.Error()}
		_ = saveSynologyConfig(configPath, cfg)
		appendSynologyLog(cfg, "DSM login failed: "+err.Error())
		return newSynologyTaskResult(cfg, "failed"), err
	}
	appendSynologyLog(cfg, "DSM login succeeded")

	runtime, cleanup, err := freshSynologyStagingRuntime(cfg)
	if err != nil {
		cfg.LastTest = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: err.Error()}
		_ = saveSynologyConfig(configPath, cfg)
		appendSynologyLog(cfg, "staging ACME validation failed: "+err.Error())
		return newSynologyTaskResult(cfg, "failed"), err
	}
	defer cleanup()

	appendSynologyLog(cfg, "starting staging ACME validation")
	err = ObtainOnce(ctx, &runtime, false)
	if err != nil {
		cfg.LastTest = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: err.Error()}
		_ = saveSynologyConfig(configPath, cfg)
		appendSynologyLog(cfg, "staging ACME validation failed: "+err.Error())
		return newSynologyTaskResult(cfg, "failed"), err
	}

	cfg.LastTest = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: "staging ACME validation succeeded"}
	if err := saveSynologyConfig(configPath, cfg); err != nil {
		return synologyTaskResult{}, err
	}
	appendSynologyLog(cfg, "staging ACME validation succeeded")
	return newSynologyTaskResult(cfg, "ok"), nil
}

// freshSynologyStagingRuntime gives every validation an empty CertMagic storage
// directory. ManageSync treats a stored unexpired certificate as success, so a
// stable staging path would bypass the DNS-01 challenge on later test runs.
func freshSynologyStagingRuntime(cfg SynologyConfig) (Config, func(), error) {
	runtime := cfg.RuntimeConfig(true)
	if err := os.MkdirAll(runtime.StorageDir, 0o700); err != nil {
		return Config{}, nil, fmt.Errorf("create staging storage root: %w", err)
	}
	if err := os.Chmod(runtime.StorageDir, 0o700); err != nil {
		return Config{}, nil, fmt.Errorf("secure staging storage root: %w", err)
	}
	dir, err := os.MkdirTemp(runtime.StorageDir, "validation-")
	if err != nil {
		return Config{}, nil, fmt.Errorf("create fresh staging storage: %w", err)
	}
	runtime.StorageDir = dir
	cleanup := func() { _ = os.RemoveAll(dir) }
	return runtime, cleanup, nil
}

// runSynologyApply independently validates the current configuration, requests
// from the selected production CA, and imports the certificate into DSM. A prior
// staging test is optional and never gates this path.
func runSynologyApply(ctx context.Context, configPath string) (synologyTaskResult, error) {
	cfg, err := loadSynologyConfig(configPath)
	if err != nil {
		return synologyTaskResult{}, err
	}
	cfg = normalizeSynologyConfig(cfg)
	configureSynologyLog(cfg)
	if err := validateConfigForSynology(cfg, true); err != nil {
		return newSynologyTaskResult(cfg, "failed"), err
	}
	appendSynologyLog(cfg, "checking DSM login")
	if err := verifySynologyLogin(ctx, cfg.Synology); err != nil {
		cfg.LastApply = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: "DSM login failed: " + err.Error()}
		_ = saveSynologyConfig(configPath, cfg)
		appendSynologyLog(cfg, "DSM login failed: "+err.Error())
		return newSynologyTaskResult(cfg, "failed"), err
	}
	appendSynologyLog(cfg, "DSM login succeeded")

	appendSynologyLog(cfg, "starting production ACME issuance")
	runtime := cfg.RuntimeConfig(false)
	if err := ObtainOnce(ctx, &runtime, false); err != nil {
		cfg.LastApply = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: err.Error()}
		_ = saveSynologyConfig(configPath, cfg)
		appendSynologyLog(cfg, "production ACME issuance failed: "+err.Error())
		return newSynologyTaskResult(cfg, "failed"), err
	}

	keyPath, certPath, err := findStoredCertificate(ctx, runtime.StorageDir, cfg.ACME.Domains[0])
	if err != nil {
		cfg.LastApply = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: err.Error()}
		_ = saveSynologyConfig(configPath, cfg)
		appendSynologyLog(cfg, "certificate lookup failed: "+err.Error())
		return newSynologyTaskResult(cfg, "failed"), err
	}
	matches, err := privateKeyMatchesKeyType(keyPath, cfg.ACME.KeyType)
	if err != nil {
		cfg.LastApply = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: err.Error()}
		_ = saveSynologyConfig(configPath, cfg)
		appendSynologyLog(cfg, "certificate key inspection failed: "+err.Error())
		return newSynologyTaskResult(cfg, "failed"), err
	}
	if !matches {
		// CertMagic may reuse a valid cached certificate after the requested key
		// type changes. Remove only this identifier's cached material, then obtain
		// again so DSM receives a key with the selected size.
		appendSynologyLog(cfg, "stored certificate key type does not match current configuration; requesting replacement")
		if err := removeStoredCertificate(runtime.StorageDir, cfg.ACME.Domains[0]); err != nil {
			cfg.LastApply = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: err.Error()}
			_ = saveSynologyConfig(configPath, cfg)
			appendSynologyLog(cfg, "stored certificate cleanup failed: "+err.Error())
			return newSynologyTaskResult(cfg, "failed"), err
		}
		if err := ObtainOnce(ctx, &runtime, false); err != nil {
			cfg.LastApply = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: err.Error()}
			_ = saveSynologyConfig(configPath, cfg)
			appendSynologyLog(cfg, "replacement production ACME issuance failed: "+err.Error())
			return newSynologyTaskResult(cfg, "failed"), err
		}
		keyPath, certPath, err = findStoredCertificate(ctx, runtime.StorageDir, cfg.ACME.Domains[0])
		if err != nil {
			cfg.LastApply = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: err.Error()}
			_ = saveSynologyConfig(configPath, cfg)
			appendSynologyLog(cfg, "replacement certificate lookup failed: "+err.Error())
			return newSynologyTaskResult(cfg, "failed"), err
		}
	}
	if err := deploySynologyStoredCertificate(ctx, cfg, cfg.ACME.Domains[0], keyPath, certPath); err != nil {
		cfg.LastApply = SynologyOperationState{Success: false, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: err.Error()}
		_ = saveSynologyConfig(configPath, cfg)
		return newSynologyTaskResult(cfg, "failed"), err
	}

	cfg.Reconfiguring = false
	cfg.LastApply = SynologyOperationState{Success: true, At: time.Now(), ConfigHash: cfg.ConfigHash(), Message: "production certificate applied"}
	if err := saveSynologyConfig(configPath, cfg); err != nil {
		return synologyTaskResult{}, err
	}
	return newSynologyTaskResult(cfg, "ok"), nil
}

var (
	synologyDaemonRetryInterval        = 30 * time.Second
	synologyDaemonFailureRetryInterval = time.Hour
)

var waitForSynologyConfigChange = monitorSynologyConfigChange

// runSynologyDaemon polls local readiness until a production certificate has
// been applied for the current hash. It stops and replaces CertMagic's cache when
// that hash changes; the apply gate prevents failed test/apply configurations
// from reaching unattended production issuance.
func runSynologyDaemon(ctx context.Context, configPath string) error {
	// Point logrus at the log file once up front. The daemon's stdout is already
	// redirected to the same file by start-stop-status, but configuring it here
	// keeps the destination correct regardless of how the process is launched;
	// it must stay outside the loop so it opens a single file handle.
	daemonCfg, err := loadSynologyConfig(configPath)
	if err != nil {
		daemonCfg = defaultSynologyConfig()
	}
	configureSynologyLog(daemonCfg)
	for {
		cfg, err := loadSynologyConfig(configPath)
		if err != nil {
			cfg = defaultSynologyConfig()
			appendSynologyLog(cfg, "waiting for readable config: "+err.Error())
			if waitSynologyDaemonRetry(ctx) {
				return nil
			}
			continue
		}

		cfg = normalizeSynologyConfig(cfg)
		runtime := cfg.RuntimeConfig(false)
		if _, err := validateConfig(runtime); err != nil {
			appendSynologyLog(cfg, "waiting for valid config: "+err.Error())
			if waitSynologyDaemonRetry(ctx) {
				return nil
			}
			continue
		}
		if !cfg.CanRenew() {
			appendSynologyLog(cfg, "waiting for successful apply before production renewal")
			if waitSynologyDaemonRetry(ctx) {
				return nil
			}
			continue
		}

		appendSynologyLog(cfg, "starting renewal daemon (CA production)")
		// The hook must resolve certificates from the runtime the manager actually
		// uses, never a hardcoded storage path, or a renewed certificate might not
		// be found for DSM import.
		runtime.EventHook = synologyRenewalDeployHook(cfg, runtime.StorageDir)
		managerCtx, cancelManager := context.WithCancel(ctx)
		stop, err := startACMEManagement(managerCtx, &runtime, false)
		if err != nil {
			cancelManager()
			appendSynologyLog(cfg, "renewal daemon failed: "+err.Error())
			// A final management error may represent an ACME authorization failure.
			// Retry far less aggressively than local config readiness to avoid
			// compounding CA rate limits after CertMagic's own retry cycle ends.
			if waitSynologyDaemonFailureRetry(ctx) {
				return nil
			}
			continue
		}
		appendSynologyLog(cfg, "renewal daemon running")
		changed := waitForSynologyConfigChange(ctx, configPath, cfg.ConfigHash())
		cancelManager()
		stop()
		if !changed {
			return nil
		}
		appendSynologyLog(cfg, "configuration changed; reloading renewal daemon")
	}
}

// monitorSynologyConfigChange returns true only for a successfully read config
// whose normalized configuration hash or renewal gate differs. Transient read
// errors leave the active manager running and are retried on the next interval.
func monitorSynologyConfigChange(ctx context.Context, configPath, activeKey string) bool {
	ticker := time.NewTicker(synologyDaemonRetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			cfg, err := loadSynologyConfig(configPath)
			if err != nil {
				continue
			}
			cfg = normalizeSynologyConfig(cfg)
			if cfg.ConfigHash() != activeKey || !cfg.CanRenew() {
				return true
			}
		}
	}
}

func waitSynologyDaemonRetry(ctx context.Context) bool {
	return waitSynologyDaemonInterval(ctx, synologyDaemonRetryInterval)
}

func waitSynologyDaemonFailureRetry(ctx context.Context) bool {
	return waitSynologyDaemonInterval(ctx, synologyDaemonFailureRetryInterval)
}

func waitSynologyDaemonInterval(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-timer.C:
		return false
	}
}

func validateConfigForSynology(cfg SynologyConfig, requireDeploy bool) error {
	if _, err := validateConfig(cfg.RuntimeConfig(true)); err != nil {
		return err
	}
	if !requireDeploy {
		return nil
	}
	if stringsTrim(cfg.Synology.Account) == "" {
		return errors.New("Synology account is empty")
	}
	if stringsTrim(cfg.Synology.Password) == "" {
		return errors.New("Synology password is empty")
	}
	if stringsTrim(cfg.Synology.CertificateDesc) == "" && !cfg.Synology.Create {
		return errors.New("certificate description is required when create is disabled")
	}
	if len(cfg.ACME.Domains) > 1 {
		return errors.New("Synology DSM deployment supports exactly one certificate identifier")
	}
	if !certmagic.SubjectQualifiesForPublicCert(cfg.ACME.Domains[0]) {
		return fmt.Errorf("invalid public certificate identifier: %s", cfg.ACME.Domains[0])
	}
	return nil
}

// synologyRenewalDeployHook imports only completed certificate events. A
// cert_obtained event is also emitted when a manager starts with empty storage,
// both an initial obtain and a real renewal must be deployed.
// Import errors are logged and returned, but CertMagic treats cert_obtained as a
// post event and may already have committed certificate storage when deployment
// fails.
func synologyRenewalDeployHook(cfg SynologyConfig, storageDir string) func(context.Context, string, map[string]any) error {
	return func(ctx context.Context, event string, data map[string]any) error {
		if event != "cert_obtained" {
			return nil
		}
		identifier, _ := data["identifier"].(string)
		if identifier == "" {
			identifier = firstSynologyIdentifier(cfg)
		}
		keyPath, certPath, err := findStoredCertificate(ctx, storageDir, identifier)
		if err != nil {
			appendSynologyLog(cfg, "renewal certificate lookup failed: "+err.Error())
			return err
		}
		if err := deploySynologyStoredCertificate(ctx, cfg, identifier, keyPath, certPath); err != nil {
			return err
		}
		return nil
	}
}

func firstSynologyIdentifier(cfg SynologyConfig) string {
	if len(cfg.ACME.Domains) == 0 {
		return ""
	}
	return cfg.ACME.Domains[0]
}

func deploySynologyStoredCertificate(ctx context.Context, cfg SynologyConfig, identifier, keyPath, certPath string) error {
	appendSynologyLog(cfg, "importing certificate into Synology DSM for "+identifier)
	if err := deploySynologyCertificate(ctx, cfg.Synology, keyPath, certPath); err != nil {
		appendSynologyLog(cfg, "Synology DSM import failed: "+err.Error())
		return err
	}
	appendSynologyLog(cfg, "Synology DSM import succeeded")
	return nil
}

// findStoredCertificate reuses the command-hook path resolver so manual apply
// and renewal deploy exactly the same CertMagic storage files.
func findStoredCertificate(ctx context.Context, storageDir, identifier string) (string, string, error) {
	env, err := hookEnv(ctx, &Config{StorageDir: storageDir}, map[string]any{"identifier": identifier})
	if err != nil {
		return "", "", err
	}
	var keyPath, certPath string
	for _, item := range env {
		if value, ok := stringsCutPrefix(item, "ACME_KEY_PATH="); ok {
			keyPath = value
		}
		if value, ok := stringsCutPrefix(item, "ACME_CERT_PATH="); ok {
			certPath = value
		}
	}
	if keyPath == "" || certPath == "" {
		return "", "", fmt.Errorf("failed to locate certificate files for %s in %s", identifier, storageDir)
	}
	return keyPath, certPath, nil
}

// removeStoredCertificate deletes only the validated identifier directory below
// issuer-specific certificate roots. A second containment check protects this
// destructive path even if a future caller bypasses Synology validation.
func removeStoredCertificate(storageDir, identifier string) error {
	storageName := certStorageName(identifier)
	certificateRoot := filepath.Join(storageDir, "certificates")
	matches, err := filepath.Glob(filepath.Join(certificateRoot, "*", storageName))
	if err != nil {
		return err
	}
	for _, match := range matches {
		rel, err := filepath.Rel(certificateRoot, match)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("refusing to remove certificate path outside storage: %s", match)
		}
		if err := os.RemoveAll(match); err != nil {
			return err
		}
	}
	return nil
}

// privateKeyMatchesKeyType inspects the actual cached key rather than trusting
// file names or prior config, which may predate a key-type change.
func privateKeyMatchesKeyType(keyPath, keyType string) (bool, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false, fmt.Errorf("private key %s is not PEM encoded", keyPath)
	}
	var key any
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return false, err
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		switch normalizeKeyType(keyType) {
		case "rsa2048":
			return k.N.BitLen() == 2048, nil
		case "rsa4096":
			return k.N.BitLen() == 4096, nil
		default:
			return false, nil
		}
	case *ecdsa.PrivateKey:
		switch normalizeKeyType(keyType) {
		case "p256":
			return k.Curve.Params().BitSize == 256, nil
		case "p384":
			return k.Curve.Params().BitSize == 384, nil
		default:
			return false, nil
		}
	case ed25519.PrivateKey:
		return normalizeKeyType(keyType) == "ed25519", nil
	default:
		return false, fmt.Errorf("unsupported private key type %T", key)
	}
}

// configureSynologyLog routes the global logrus logger to the package log file
// the DSM UI tails. The CGI request handler writes its HTTP response to stdout
// and the CLI subcommands print their JSON result there, so logrus must not
// share stdout; pointing it at the log file keeps the two streams separate and
// puts the wrapper messages and forwarded certmagic output in one place with one
// format. Callers invoke this once per process (or per CGI request); it must not
// run inside a loop because each call opens a new file handle.
func configureSynologyLog(cfg SynologyConfig) {
	cfg = normalizeSynologyConfig(cfg)
	if cfg.Runtime.LogPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Runtime.LogPath), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(cfg.Runtime.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	logrus.SetOutput(f)
}

// appendSynologyLog records a wrapper progress message through the shared logrus
// logger (pointed at the package log file by configureSynologyLog). Level is
// inferred from the message: our failure logs all carry "failed" (the same
// signal the UI uses to surface the last error); everything else is info. The
// cfg parameter is retained for call-site symmetry with the many existing
// callers even though logrus now owns the destination.
func appendSynologyLog(_ SynologyConfig, message string) {
	if strings.Contains(message, "failed") {
		logrus.Error(message)
		return
	}
	logrus.Info(message)
}

func stringsCutPrefix(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
		return "", false
	}
	return s[len(prefix):], true
}

func stringsTrim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 {
		last := s[len(s)-1]
		if last != ' ' && last != '\t' && last != '\n' && last != '\r' {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}
