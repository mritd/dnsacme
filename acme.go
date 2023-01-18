package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/caddyserver/certmagic"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Obtain(conf *Config) {

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Find a DNS Provider
	var err error
	var dnsProvider certmagic.ACMEDNSProvider
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
		CA:                      certmagic.LetsEncryptProductionCA,
		TestCA:                  certmagic.ZeroSSLProductionCA,
		Email:                   conf.Email,
		DNS01Solver:             &certmagic.DNS01Solver{DNSProvider: dnsProvider},
		Logger:                  acmeLogger,
	})

	if !conf.ZeroSSLCA {
		issuer.CA = certmagic.LetsEncryptProductionCA
	}

	if conf.TestMode {
		issuer.CA = certmagic.LetsEncryptStagingCA
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
