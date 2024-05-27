package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v2/acme"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Obtain(conf *Config) {

	fmt.Print(LOGO)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Find a DNS Provider
	var err error
	var dnsProvider certmagic.DNSProvider
	if fn, ok := providerFn[strings.ToLower(conf.DNSProvider)]; ok {
		if dnsProvider, err = fn(conf); err != nil {
			logrus.Fatal(err)
		}
	} else {
		logrus.Fatalf("unsupported DNS provider: %s", conf.DNSProvider)
	}

	acmeLogger := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
		os.Stdout,
		zap.InfoLevel,
	))

	magic := &certmagic.Config{
		RenewalWindowRatio: certmagic.DefaultRenewalWindowRatio,
		KeySource:          certmagic.StandardKeyGenerator{KeyType: certmagic.KeyType(conf.KeyType)},
		Storage:            &certmagic.FileStorage{Path: conf.StorageDir},
		Logger:             acmeLogger,
		OnEvent:            OnEvent(conf),
	}

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
		Logger: acmeLogger,
	})

	if conf.ZeroSSLCA {
		issuer.CA = certmagic.ZeroSSLProductionCA
		issuer.ExternalAccount = generateEABCredentials(conf.Email)
	} else {
		issuer.CA = certmagic.LetsEncryptProductionCA
	}

	magic.Issuers = []certmagic.Issuer{issuer}

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
		Logger: acmeLogger,
	})

	magic = certmagic.New(cache, *magic)
	if err = magic.ManageSync(context.Background(), conf.Domains); err != nil {
		logrus.Fatalf("Failed to Obtain Cert: %s", err)
	}

	for _, domain := range conf.Domains {
		_ = OnEvent(conf)(ctx, "cert_obtained", map[string]any{"identifier": domain})
	}
	logrus.Info("DNS ACME Running...")

	<-ctx.Done()
	logrus.Info("DNS ACME Exit.")
}

func generateEABCredentials(email string) *acme.EAB {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint := "https://api.zerossl.com/acme/eab-credentials-email"
	body := strings.NewReader(url.Values{"email": []string{email}}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		logrus.Fatalf("failed to creare ZeroSSL EAB Request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", certmagic.UserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logrus.Fatalf("failed to create ZeroSSL EAB: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Success bool `json:"success"`
		Error   struct {
			Code int    `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		logrus.Fatalf("failed decoding ZeroSSL EAB API response: %v", err)
	}
	if result.Error.Code != 0 {
		logrus.Fatalf("failed getting ZeroSSL EAB credentials: HTTP %d: %s (code %d)", resp.StatusCode, result.Error.Type, result.Error.Code)
	}
	if resp.StatusCode != http.StatusOK {
		logrus.Fatalf("failed getting EAB credentials: HTTP %d", resp.StatusCode)
	}

	logrus.Infof("generated EAB credentials: key_id: %s", result.EABKID)

	return &acme.EAB{
		KeyID:  result.EABKID,
		MACKey: result.EABHMACKey,
	}
}
