package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"github.com/mritd/dnsacme/internal/provider"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	httpClientDo        = http.DefaultClient.Do
	signalNotifyContext = signal.NotifyContext
	newDNSProvider      = provider.New
	manageCertificates  = func(ctx context.Context, cfg *certmagic.Config, domains []string) error {
		return cfg.ManageSync(ctx, domains)
	}
	waitForShutdown = func(ctx context.Context) {
		<-ctx.Done()
	}
)

// Obtain performs the initial certificate management pass, emits configured
// hooks, and keeps CertMagic's maintenance cache alive until shutdown.
func Obtain(conf *Config) {

	fmt.Print(LOGO)

	ctx, cancel := signalNotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	stop, err := startACMEManagement(ctx, conf, true)
	if err != nil {
		logrus.Fatalf("Failed to Obtain Cert: %s", err)
	}
	defer stop()

	logrus.Info("DNS ACME Running...")

	waitForShutdown(ctx)
	logrus.Info("DNS ACME Exit.")
}

// ObtainOnce builds an isolated CertMagic runtime and starts management for the
// configured identifiers. emitHooks controls only the legacy synthetic
// cert_obtained replay after startup; native CertMagic events always use OnEvent.
// The maintenance cache is stopped before this one-shot helper returns.
func ObtainOnce(ctx context.Context, conf *Config, emitHooks bool) error {
	stop, err := startACMEManagement(ctx, conf, emitHooks)
	if err != nil {
		return err
	}
	stop()
	return nil
}

// startACMEManagement returns an explicit stop function because CertMagic caches
// own a maintenance goroutine. Long-lived callers must stop the old cache before
// replacing a configuration snapshot.
func startACMEManagement(ctx context.Context, conf *Config, emitHooks bool) (func(), error) {
	dnsProvider, err := dnsProviderForConfig(conf)
	if err != nil {
		return nil, err
	}

	acmeLogger := newACMELogger()

	magic := newCertMagicConfig(conf, acmeLogger)
	magic, cache := newManagedConfigWithCache(magic, acmeLogger)
	magic.Issuers = []certmagic.Issuer{newACMEIssuer(conf, magic, dnsProvider, acmeLogger)}

	if err = manageCertificates(ctx, magic, conf.Domains); err != nil {
		cache.Stop()
		return nil, err
	}

	if emitHooks {
		emitCertObtainedEvents(ctx, conf)
	}

	return cache.Stop, nil
}

// dnsProviderForConfig constructs the configured provider through the testable package seam.
func dnsProviderForConfig(conf *Config) (certmagic.DNSProvider, error) {
	return newDNSProvider(conf.DNSProvider, conf.DNSConfig)
}

func newACMELogger() *zap.Logger {
	return zap.New(newLogrusZapCore())
}

// logrusZapCore forwards CertMagic's zap entries and structured fields verbatim
// into the project logger. Callers must avoid putting credentials in zap fields;
// the core unifies format, destination, and timestamp style but does not redact.
type logrusZapCore struct {
	fields []zapcore.Field
}

func newLogrusZapCore() zapcore.Core {
	return &logrusZapCore{}
}

func (c *logrusZapCore) Enabled(level zapcore.Level) bool {
	return level >= zapcore.InfoLevel
}

func (c *logrusZapCore) With(fields []zapcore.Field) zapcore.Core {
	combined := make([]zapcore.Field, 0, len(c.fields)+len(fields))
	combined = append(combined, c.fields...)
	combined = append(combined, fields...)
	return &logrusZapCore{fields: combined}
}

func (c *logrusZapCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return ce.AddCore(entry, c)
	}
	return ce
}

func (c *logrusZapCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, field := range c.fields {
		field.AddTo(enc)
	}
	for _, field := range fields {
		field.AddTo(enc)
	}
	data := make(logrus.Fields, len(enc.Fields)+1)
	for k, v := range enc.Fields {
		data[k] = v
	}
	if entry.LoggerName != "" {
		data["logger"] = entry.LoggerName
	}
	logEntry := logrus.WithFields(data)
	switch {
	case entry.Level >= zapcore.ErrorLevel:
		// Map every error-or-worse level (including DPanic/Panic/Fatal) to a
		// plain error so a forwarded certmagic log can never kill the process.
		logEntry.Error(entry.Message)
	case entry.Level == zapcore.WarnLevel:
		logEntry.Warn(entry.Message)
	default:
		logEntry.Info(entry.Message)
	}
	return nil
}

func (c *logrusZapCore) Sync() error {
	return nil
}

// renewalWindowRatioEnv overrides every runtime's renewal window at once (CLI
// obtain and the Synology daemon both build configs here). It exists mainly so
// operators can force an early renewal to exercise the renew-and-redeploy path
// without waiting out a certificate's natural 1/3 window.
const renewalWindowRatioEnv = "DNSACME_RENEWAL_WINDOW_RATIO"

// resolveRenewalWindowRatio picks the effective renewal window with environment
// beating config beating CertMagic's default. Values outside (0, 1] at any level
// fall through to the next one, so a typo can never disable renewal entirely.
func resolveRenewalWindowRatio(configValue float64) float64 {
	if raw := strings.TrimSpace(os.Getenv(renewalWindowRatioEnv)); raw != "" {
		if ratio, err := strconv.ParseFloat(raw, 64); err == nil && ratio > 0 && ratio <= 1 {
			return ratio
		}
	}
	if configValue > 0 && configValue <= 1 {
		return configValue
	}
	return certmagic.DefaultRenewalWindowRatio
}

func newCertMagicConfig(conf *Config, logger *zap.Logger) *certmagic.Config {
	return &certmagic.Config{
		RenewalWindowRatio: resolveRenewalWindowRatio(conf.RenewalWindowRatio),
		KeySource:          certmagic.StandardKeyGenerator{KeyType: certmagic.KeyType(normalizeKeyType(conf.KeyType))},
		Storage:            &certmagic.FileStorage{Path: conf.StorageDir},
		Logger:             logger,
		OnEvent:            OnEvent(conf),
	}
}

func newACMEIssuer(conf *Config, magic *certmagic.Config, dnsProvider certmagic.DNSProvider, logger *zap.Logger) *certmagic.ACMEIssuer {
	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		Email:                   conf.Email,
		DNS01Solver: &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: dnsProvider,
			},
		},
		Logger: logger,
	})

	// An explicit endpoint is used by staging and custom-CA callers. ZeroSSLCA
	// remains the legacy CLI selector when no endpoint was supplied.
	if conf.CA != "" {
		issuer.CA = conf.CA
	} else if conf.ZeroSSLCA {
		issuer.CA = certmagic.ZeroSSLProductionCA
		if len(conf.EABKeyID) > 0 && len(conf.EABHMACKey) > 0 {
			issuer.ExternalAccount = &acme.EAB{
				KeyID:  conf.EABKeyID,
				MACKey: conf.EABHMACKey,
			}
		} else {
			issuer.ExternalAccount = generateEABCredentials(conf.Email)
		}
	} else {
		issuer.CA = certmagic.LetsEncryptProductionCA
	}

	return issuer
}

func newManagedConfigWithCache(magic *certmagic.Config, logger *zap.Logger) (*certmagic.Config, *certmagic.Cache) {
	var managed *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			// Return the cache-bound config rather than the template passed to New;
			// renewal callbacks need the issuer and EventHook on this final value.
			return managed, nil
		},
		Logger: logger,
	})

	managed = certmagic.New(cache, *magic)
	return managed, cache
}

func emitCertObtainedEvents(ctx context.Context, conf *Config) {
	for _, domain := range conf.Domains {
		_ = OnEvent(conf)(ctx, "cert_obtained", map[string]any{"identifier": domain})
	}
}

func generateEABCredentials(email string) *acme.EAB {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := newEABCredentialsRequest(ctx, email)
	if err != nil {
		logrus.Fatalf("failed to creare ZeroSSL EAB Request: %v", err)
	}

	resp, err := httpClientDo(req)
	if err != nil {
		logrus.Fatalf("failed to create ZeroSSL EAB: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	eab, err := decodeEABCredentialsResponse(resp.StatusCode, resp.Body)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("generated EAB credentials: key_id: %s", eab.KeyID)

	return eab
}

func newEABCredentialsRequest(ctx context.Context, email string) (*http.Request, error) {
	endpoint := "https://api.zerossl.com/acme/eab-credentials-email"
	body := strings.NewReader(url.Values{"email": []string{email}}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", certmagic.UserAgent)
	return req, nil
}

func decodeEABCredentialsResponse(statusCode int, body io.Reader) (*acme.EAB, error) {
	var result struct {
		Success bool `json:"success"`
		Error   struct {
			Code int    `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	err := json.NewDecoder(body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed decoding ZeroSSL EAB API response: %w", err)
	}
	if result.Error.Code != 0 {
		return nil, fmt.Errorf("failed getting ZeroSSL EAB credentials: HTTP %d: %s (code %d)", statusCode, result.Error.Type, result.Error.Code)
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("failed getting EAB credentials: HTTP %d", statusCode)
	}

	return &acme.EAB{
		KeyID:  result.EABKID,
		MACKey: result.EABHMACKey,
	}, nil
}
