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
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	httpClientDo        = http.DefaultClient.Do
	signalNotifyContext = signal.NotifyContext
	manageCertificates  = func(ctx context.Context, cfg *certmagic.Config, domains []string) error {
		return cfg.ManageSync(ctx, domains)
	}
	waitForShutdown = func(ctx context.Context) {
		<-ctx.Done()
	}
)

func Obtain(conf *Config) {

	fmt.Print(LOGO)

	ctx, cancel := signalNotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dnsProvider, err := dnsProviderForConfig(conf)
	if err != nil {
		logrus.Fatal(err)
	}

	acmeLogger := newACMELogger()

	magic := newCertMagicConfig(conf, acmeLogger)
	magic.Issuers = []certmagic.Issuer{newACMEIssuer(conf, magic, dnsProvider, acmeLogger)}
	magic = newManagedConfig(magic, acmeLogger)

	if err = manageCertificates(ctx, magic, conf.Domains); err != nil {
		logrus.Fatalf("Failed to Obtain Cert: %s", err)
	}

	emitCertObtainedEvents(ctx, conf)
	logrus.Info("DNS ACME Running...")

	waitForShutdown(ctx)
	logrus.Info("DNS ACME Exit.")
}

func dnsProviderForConfig(conf *Config) (certmagic.DNSProvider, error) {
	if fn, ok := providerFn[strings.ToLower(conf.DNSProvider)]; ok {
		return fn(conf)
	}
	return nil, fmt.Errorf("unsupported DNS provider: %s", conf.DNSProvider)
}

func newACMELogger() *zap.Logger {
	return zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
		os.Stdout,
		zap.InfoLevel,
	))
}

func newCertMagicConfig(conf *Config, logger *zap.Logger) *certmagic.Config {
	return &certmagic.Config{
		RenewalWindowRatio: certmagic.DefaultRenewalWindowRatio,
		KeySource:          certmagic.StandardKeyGenerator{KeyType: certmagic.KeyType(conf.KeyType)},
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

	if conf.ZeroSSLCA {
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

func newManagedConfig(magic *certmagic.Config, logger *zap.Logger) *certmagic.Config {
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
		Logger: logger,
	})

	return certmagic.New(cache, *magic)
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
